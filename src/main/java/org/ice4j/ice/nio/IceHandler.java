package org.ice4j.ice.nio;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.apache.mina.core.service.IoHandlerAdapter;
import org.apache.mina.core.session.IoSession;
import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.socket.IceSocketWrapper;
import org.ice4j.stack.RawMessage;
import org.ice4j.stack.StunStack;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handle routing of messages on the ICE socket.
 * 
 * @author Paul Gregoire
 */
public class IceHandler extends IoHandlerAdapter {

    private static final Logger logger = LoggerFactory.getLogger(IceHandler.class);

    // temporary holding area for stun stacks awaiting session creation
    private ConcurrentMap<SocketAddress, StunStack> stunStacks = new ConcurrentHashMap<>();

    // temporary holding area for ice sockets awaiting session creation
    private ConcurrentMap<SocketAddress, IceSocketWrapper> iceSockets = new ConcurrentHashMap<>();

    /**
     * Registers a StunStack and IceSocketWrapper to the internal maps to wait for their associated IoSession creation.
     * 
     * @param stunStack
     * @param iceSocket
     */
    public void registerStackAndSocket(StunStack stunStack, IceSocketWrapper iceSocket) {
        logger.debug("registerStackAndSocket - stunStack: {} iceSocket: {}", stunStack, iceSocket);
        SocketAddress addr = iceSocket.getLocalSocketAddress();
        if (stunStack != null) {
            stunStacks.putIfAbsent(addr, stunStack);
        } else {
            logger.debug("Stun stack exists for address: {}", stunStacks.get(addr));
        }
        iceSockets.putIfAbsent(addr, iceSocket);
    }

    /**
     * Returns an IceSocketWrapper for a given address if it exists and null if it doesn't.
     * 
     * @param localAddress
     * @return IceSocketWrapper
     */
    public IceSocketWrapper lookupBinding(TransportAddress localAddress) {
        return iceSockets.get(localAddress);
    }

    /**
     * Returns an StunStack for a given address if it exists and null if it doesn't.
     * 
     * @param localAddress
     * @return StunStack
     */
    public StunStack lookupStunStack(TransportAddress localAddress) {
        return stunStacks.get(localAddress);
    }

    /** {@inheritDoc} */
    @Override
    public void sessionOpened(IoSession session) throws Exception {
        logger.trace("Opened (session: {}) local: {} remote: {}", session.getId(), session.getLocalAddress(), session.getRemoteAddress());
        Transport transport = session.getTransportMetadata().isConnectionless() ? Transport.UDP : Transport.TCP;
        // set transport type, making it easier to look-up later
        session.setAttribute(IceTransport.Ice.TRANSPORT, transport);
        logger.debug("Acceptor sessions: {}", IceTransport.getInstance(transport).getAcceptor().getManagedSessions());
        // get the local address
        SocketAddress addr = session.getLocalAddress();
        IceSocketWrapper iceSocket = iceSockets.get(addr);
        if (iceSocket != null) {
            iceSocket.setSession(session);
        } else {
            logger.debug("No ice socket at create for: {}", addr);
            /*
             * iceSocket = (IceSocketWrapper) session.getAttribute(IceTransport.Ice.CONNECTION); if (iceSocket != null) { iceSocket.setSession(session);
             * logger.debug("Ice socket in session at create for: {} session in socket: {}", addr, iceSocket.getSession()); } else {
             * logger.debug("Ice socket in session at create for: {} session in socket: null", addr); }
             */
        }
        StunStack stunStack = stunStacks.get(addr);
        if (stunStack != null) {
            // XXX create socket registration check to stun stack
            //stunStack.addSocket(iceSocket, iceSocket.getRemoteTransportAddress());
            session.setAttribute(IceTransport.Ice.STUN_STACK, stunStack);
        } else {
            logger.debug("No stun stack at create for: {}", addr);
        }
    }

    /** {@inheritDoc} */
    @Override
    public void messageReceived(IoSession session, Object message) throws Exception {
        logger.trace("Message received (session: {}) local: {} remote: {}", session.getId(), session.getLocalAddress(), session.getRemoteAddress());
        //logger.trace("Received: {}", String.valueOf(message));
        IceSocketWrapper iceSocket = (IceSocketWrapper) session.getAttribute(IceTransport.Ice.CONNECTION);
        if (iceSocket != null) {
            if (message instanceof RawMessage) {
                // non-stun message
                iceSocket.getRawMessageQueue().offer((RawMessage) message);
            } else {
                logger.debug("Message type: {}", message.getClass().getName());
            }
        } else {
            logger.debug("Ice socket was not found in session");
        }
    }

    /** {@inheritDoc} */
    @Override
    public void messageSent(IoSession session, Object message) throws Exception {
        if (logger.isTraceEnabled()) {
            logger.trace("Message sent (session: {}) local: {} remote: {}\nread: {} write: {}", session.getId(), session.getLocalAddress(), session.getRemoteAddress(), session.getReadBytes(), session.getWrittenBytes());
            //logger.trace("Sent: {}", String.valueOf(message));
        }
    }

    /** {@inheritDoc} */
    @Override
    public void sessionClosed(IoSession session) throws Exception {
        logger.trace("Session closed");
        SocketAddress addr = session.getLocalAddress();
        // determine transport type
        Transport transport = (session.removeAttribute(IceTransport.Ice.TRANSPORT) == Transport.UDP) ? Transport.UDP : Transport.TCP;
        // remove binding
        IceTransport.getInstance(transport).removeBinding(addr);
        // clean-up
        IceSocketWrapper iceSocket = null;
        if (session.containsAttribute(IceTransport.Ice.CONNECTION)) {
            iceSocket = (IceSocketWrapper) session.removeAttribute(IceTransport.Ice.CONNECTION);
        }
        if (session.containsAttribute(IceTransport.Ice.STUN_STACK)) {
            StunStack stunStack = (StunStack) session.removeAttribute(IceTransport.Ice.STUN_STACK);
            if (addr instanceof InetSocketAddress) {
                InetSocketAddress inetAddr = (InetSocketAddress) addr;
                addr = new TransportAddress(inetAddr.getAddress(), inetAddr.getPort(), transport);
            }
            if (iceSocket != null) {
                stunStack.removeSocket((TransportAddress) addr, iceSocket.getRemoteTransportAddress());
            } else {
                SocketAddress remoteAddr = session.getRemoteAddress();
                if (remoteAddr instanceof InetSocketAddress) {
                    InetSocketAddress inetAddr = (InetSocketAddress) remoteAddr;
                    remoteAddr = new TransportAddress(inetAddr.getAddress(), inetAddr.getPort(), transport);
                }
                stunStack.removeSocket((TransportAddress) addr, (TransportAddress) remoteAddr);
            }
        }
        if (iceSocket != null) {
            iceSocket.setSession(null);
        }
        // remove any map entries
        stunStacks.remove(addr);
        iceSockets.remove(addr);
        super.sessionClosed(session);
    }

    /** {@inheritDoc} */
    @Override
    public void exceptionCaught(IoSession session, Throwable cause) throws Exception {
        SocketAddress addr = session.getLocalAddress();
        logger.warn("Exception on {}", addr, cause);
        // determine transport type
        Transport transport = (session.removeAttribute(IceTransport.Ice.TRANSPORT) == Transport.TCP) ? Transport.TCP : Transport.UDP;
        // remove binding
        IceTransport.getInstance(transport).removeBinding(addr);
        // remove any map entries
        stunStacks.remove(addr);
        iceSockets.remove(addr);
    }

}
