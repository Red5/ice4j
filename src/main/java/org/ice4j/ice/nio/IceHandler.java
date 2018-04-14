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

    private static final Logger log = LoggerFactory.getLogger(IceHandler.class);

    // temporary holding area for stun stacks awaiting session creation
    private ConcurrentMap<SocketAddress, StunStack> stunStacks = new ConcurrentHashMap<>();

    // temporary holding area for ice sockets awaiting session creation
    private ConcurrentMap<SocketAddress, IceSocketWrapper> iceSockets = new ConcurrentHashMap<>();

    /**
     * Adds the StunStack and IceSocketWrapper to the internal maps to wait for their associated IoSession creation.
     * 
     * @param stunStack
     * @param iceSocket
     */
    public void addStackAndSocket(StunStack stunStack, IceSocketWrapper iceSocket) {
        SocketAddress addr = iceSocket.getLocalSocketAddress();
        if (stunStack != null) {
            stunStacks.putIfAbsent(addr, stunStack);
        }
        iceSockets.putIfAbsent(addr, iceSocket);
    }

    /** {@inheritDoc} */
    @Override
    public void sessionCreated(IoSession session) throws Exception {
        log.trace("Created (session: {}) address: {}", session.getId(), session.getLocalAddress());
        SocketAddress addr = session.getLocalAddress();
        IceSocketWrapper iceSocket = iceSockets.remove(addr);
        if (iceSocket != null) {
            iceSocket.setSession(session);
            session.setAttribute(IceTransport.Ice.CONNECTION, iceSocket);
        }
        StunStack stunStack = stunStacks.remove(addr);
        if (stunStack != null) {
            stunStack.addSocket(iceSocket, iceSocket.getRemoteTransportAddress());
            session.setAttribute(IceTransport.Ice.STUN_STACK, stunStack);
        }
    }

    /** {@inheritDoc} */
    @Override
    public void sessionOpened(IoSession session) throws Exception {
        log.trace("Opened (session: {}) address: {}", session.getId(), session.getLocalAddress());
        SocketAddress addr = session.getLocalAddress();
        IceSocketWrapper iceSocket = iceSockets.remove(addr);
        if (iceSocket != null) {
            iceSocket.setSession(session);
            session.setAttribute(IceTransport.Ice.CONNECTION, iceSocket);
        } else {
            iceSocket = (IceSocketWrapper) session.getAttribute(IceTransport.Ice.CONNECTION);
        }
        StunStack stunStack = stunStacks.remove(addr);
        if (stunStack != null) {
            // XXX may want to add a check on stun stack to skip accidental re-adds of the socket
            stunStack.addSocket(iceSocket, iceSocket.getRemoteTransportAddress());
            session.setAttribute(IceTransport.Ice.STUN_STACK, stunStack);
        }
    }

    /** {@inheritDoc} */
    @Override
    public void messageReceived(IoSession session, Object message) throws Exception {
        log.trace("Message received (session: {}) address: {} {}", session.getId(), session.getLocalAddress(), message);
        IceSocketWrapper iceSocket = (IceSocketWrapper) session.getAttribute(IceTransport.Ice.CONNECTION);
        if (iceSocket != null) {
            if (message instanceof RawMessage) {
                // non-stun message
                iceSocket.getRawMessageQueue().offer((RawMessage) message);
            } else {
                log.debug("Message type: {}", message.getClass().getName());
            }
        } else {
            log.debug("Ice socket was not found in session");
        }
    }

    /** {@inheritDoc} */
    @Override
    public void messageSent(IoSession session, Object message) throws Exception {
        log.trace("Message sent (session: {}) address: {} {}\nread: {} write: {}", session.getId(), session.getLocalAddress(), String.valueOf(message), session.getReadBytes(), session.getWrittenBytes());
    }

    /** {@inheritDoc} */
    @Override
    public void sessionClosed(IoSession session) throws Exception {
        log.trace("Session closed");
        SocketAddress addr = session.getLocalAddress();
        // remove binding
        if (session.getTransportMetadata().isConnectionless()) {
            IceTransport.getInstance(Transport.UDP).removeBinding(addr);
        } else {
            IceTransport.getInstance(Transport.TCP).removeBinding(addr);
        }
        // clean-up
        IceSocketWrapper iceSocket = null;
        if (session.containsAttribute(IceTransport.Ice.CONNECTION)) {
            iceSocket = (IceSocketWrapper) session.removeAttribute(IceTransport.Ice.CONNECTION);
        }
        if (session.containsAttribute(IceTransport.Ice.STUN_STACK)) {
            StunStack stunStack = (StunStack) session.removeAttribute(IceTransport.Ice.STUN_STACK);
            if (addr instanceof InetSocketAddress) {
                InetSocketAddress inetAddr = (InetSocketAddress) addr;
                addr = new TransportAddress(inetAddr.getAddress(), inetAddr.getPort(), (session.getTransportMetadata().isConnectionless() ? Transport.UDP : Transport.TCP));
            }
            if (iceSocket != null) {
                stunStack.removeSocket((TransportAddress) addr, iceSocket.getRemoteTransportAddress());
            } else {
                SocketAddress remoteAddr = session.getRemoteAddress();
                if (remoteAddr instanceof InetSocketAddress) {
                    InetSocketAddress inetAddr = (InetSocketAddress) remoteAddr;
                    remoteAddr = new TransportAddress(inetAddr.getAddress(), inetAddr.getPort(), (session.getTransportMetadata().isConnectionless() ? Transport.UDP : Transport.TCP));
                }
                stunStack.removeSocket((TransportAddress) addr, (TransportAddress) remoteAddr);
            }
        }
        super.sessionClosed(session);
    }

    /** {@inheritDoc} */
    @Override
    public void exceptionCaught(IoSession session, Throwable cause) throws Exception {
        SocketAddress addr = session.getLocalAddress();
        log.warn("Exception on {}", addr, cause);
        // remove binding
        if (session.getTransportMetadata().isConnectionless()) {
            IceTransport.getInstance(Transport.UDP).removeBinding(addr);
        } else {
            IceTransport.getInstance(Transport.TCP).removeBinding(addr);
        }
        // remove any map entries
        if (stunStacks.containsKey(addr)) {
            stunStacks.remove(addr);
        }
        if (iceSockets.containsKey(addr)) {
            iceSockets.remove(addr);
        }
    }

}
