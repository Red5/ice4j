package org.ice4j.ice.nio;

import java.net.InetSocketAddress;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.apache.mina.core.service.IoHandlerAdapter;
import org.apache.mina.core.session.IdleStatus;
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
    private ConcurrentMap<TransportAddress, StunStack> stunStacks = new ConcurrentHashMap<>();

    // temporary holding area for ice sockets awaiting session creation
    private ConcurrentMap<TransportAddress, IceSocketWrapper> iceSockets = new ConcurrentHashMap<>();

    /**
     * Registers a StunStack and IceSocketWrapper to the internal maps to wait for their associated IoSession creation.
     * 
     * @param stunStack
     * @param iceSocket
     */
    public void registerStackAndSocket(StunStack stunStack, IceSocketWrapper iceSocket) {
        logger.debug("registerStackAndSocket on {} - stunStack: {} iceSocket: {}", this, stunStack, iceSocket);
        TransportAddress addr = iceSocket.getTransportAddress();
        if (stunStack != null) {
            stunStacks.putIfAbsent(addr, stunStack);
        } else {
            logger.debug("Stun stack for address: {}", stunStacks.get(addr));
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
        logger.trace("lookupBinding on {} for local address: {} existing bindings: {}", this, localAddress, iceSockets);
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
        logger.debug("Acceptor sessions (existing): {}", IceTransport.getInstance(transport).getAcceptor().getManagedSessions());
        // get the local address
        InetSocketAddress inetAddr = (InetSocketAddress) session.getLocalAddress();
        TransportAddress addr = new TransportAddress(inetAddr.getAddress(), inetAddr.getPort(), transport);
        IceSocketWrapper iceSocket = iceSockets.get(addr);
        if (iceSocket != null) {
            // set the session
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
            session.setAttribute(IceTransport.Ice.STUN_STACK, stunStack);
            // XXX create socket registration
            if (transport == Transport.TCP) {
                // get the remote address
                inetAddr = (InetSocketAddress) session.getRemoteAddress();
                TransportAddress remoteAddress = new TransportAddress(inetAddr.getAddress(), inetAddr.getPort(), transport);
                iceSocket.setRemoteTransportAddress(remoteAddress);
                stunStack.getNetAccessManager().addSocket(iceSocket, iceSocket.getRemoteTransportAddress());
            }
        } else {
            logger.debug("No stun stack at create for: {}", addr);
        }
    }

    /** {@inheritDoc} */
    @Override
    public void messageReceived(IoSession session, Object message) throws Exception {
        if (logger.isTraceEnabled()) {
            logger.trace("Message received (session: {}) local: {} remote: {}", session.getId(), session.getLocalAddress(), session.getRemoteAddress());
            logger.trace("Received: {}", String.valueOf(message));
        }
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
            logger.trace("Sent: {}", String.valueOf(message));
        }
    }

    /** {@inheritDoc} */
    @Override
    public void sessionIdle(IoSession session, IdleStatus status) throws Exception {
        if (logger.isTraceEnabled()) {
            logger.trace("Idle (session: {}) local: {} remote: {}\nread: {} write: {}", session.getId(), session.getLocalAddress(), session.getRemoteAddress(), session.getReadBytes(), session.getWrittenBytes());
        }
        IceSocketWrapper iceSocket = (IceSocketWrapper) session.getAttribute(IceTransport.Ice.CONNECTION);
        if (iceSocket != null) {
            iceSocket.close();
        } else {
            session.closeNow();
        }
    }

    /** {@inheritDoc} */
    @Override
    public void sessionClosed(IoSession session) throws Exception {
        logger.trace("Session closed: {}", session.getId());
        // determine transport type
        Transport transport = (session.removeAttribute(IceTransport.Ice.TRANSPORT) == Transport.UDP) ? Transport.UDP : Transport.TCP;
        InetSocketAddress inetAddr = (InetSocketAddress) session.getLocalAddress();
        TransportAddress addr = new TransportAddress(inetAddr.getAddress(), inetAddr.getPort(), transport);
        // remove binding
        IceTransport.getInstance(transport).removeBinding(addr);
        // clean-up
        IceSocketWrapper iceSocket = null;
        if (session.containsAttribute(IceTransport.Ice.CONNECTION)) {
            iceSocket = (IceSocketWrapper) session.removeAttribute(IceTransport.Ice.CONNECTION);
        }
        if (session.containsAttribute(IceTransport.Ice.STUN_STACK)) {
            StunStack stunStack = (StunStack) session.removeAttribute(IceTransport.Ice.STUN_STACK);
            if (iceSocket != null) {
                stunStack.removeSocket(addr, iceSocket.getRemoteTransportAddress());
            } else {
                inetAddr = (InetSocketAddress) session.getRemoteAddress();
                TransportAddress remoteAddr = new TransportAddress(inetAddr.getAddress(), inetAddr.getPort(), transport);
                stunStack.removeSocket(addr, remoteAddr);
            }
        }
        // remove any map entries
        stunStacks.remove(addr);
        // determine if our ice socket was removed by the transport address
        int count = iceSockets.size();
        iceSockets.remove(addr);
        // clear the socket props
        if (iceSocket != null) {
            iceSocket.setSession(IceSocketWrapper.NULL_SESSION);
            // this is quick and dirty for possibly skipping looping through the collection
            if (iceSockets.size() >= count) {
                // removing by key doesnt seem to work correction, probably due to missing transport on SocketAddress instances
                for (Entry<TransportAddress, IceSocketWrapper> ice : iceSockets.entrySet()) {
                    if (iceSocket.equals(ice.getValue())) {
                        logger.trace("Found matching ice socket by value");
                        iceSockets.remove(ice.getKey());
                        break;
                    }
                }
            }
        }
        super.sessionClosed(session);
    }

    /** {@inheritDoc} */
    @Override
    public void exceptionCaught(IoSession session, Throwable cause) throws Exception {
        // determine transport type
        Transport transport = (session.removeAttribute(IceTransport.Ice.TRANSPORT) == Transport.TCP) ? Transport.TCP : Transport.UDP;
        InetSocketAddress inetAddr = (InetSocketAddress) session.getLocalAddress();
        TransportAddress addr = new TransportAddress(inetAddr.getAddress(), inetAddr.getPort(), transport);
        logger.warn("Exception on {}", addr, cause);
        // remove binding
        IceTransport.getInstance(transport).removeBinding(addr);
        // remove any map entries
        stunStacks.remove(addr);
        iceSockets.remove(addr);
    }

}
