package org.ice4j.ice.nio;

import java.net.SocketAddress;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.apache.mina.core.service.IoHandlerAdapter;
import org.apache.mina.core.session.IoSession;
import org.ice4j.Transport;
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
        stunStacks.putIfAbsent(addr, stunStack);
        iceSockets.putIfAbsent(addr, iceSocket);
    }

    /** {@inheritDoc} */
    @Override
    public void sessionCreated(IoSession session) throws Exception {
        log.trace("Created (session: {}) address: {}", session.getId(), session.getLocalAddress());
        SocketAddress addr = session.getLocalAddress();
        if (stunStacks.containsKey(addr)) {
            session.setAttribute(IceTransport.Ice.STUN_STACK, stunStacks.remove(addr));
        }
        if (iceSockets.containsKey(addr)) {
            session.setAttribute(IceTransport.Ice.CONNECTION, iceSockets.remove(addr));
        }
    }

    /** {@inheritDoc} */
    @Override
    public void sessionOpened(IoSession session) throws Exception {
        log.trace("Opened (session: {}) address: {}", session.getId(), session.getLocalAddress());
    }

    /** {@inheritDoc} */
    @Override
    public void messageReceived(IoSession session, Object message) throws Exception {
        log.trace("Message received (session: {}) address: {} {}", session.getId(), session.getLocalAddress(), message);
        IceSocketWrapper conn = (IceSocketWrapper) session.getAttribute(IceTransport.Ice.CONNECTION);
        if (message instanceof RawMessage) {
            if (conn != null) {
                // non-stun message
                conn.getRawMessageQueue().offer((RawMessage) message);
            }
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
        // remove binding
        if (session.getTransportMetadata().isConnectionless()) {
            IceTransport.getInstance(Transport.UDP).removeBinding(session.getLocalAddress());
        } else {
            IceTransport.getInstance(Transport.TCP).removeBinding(session.getLocalAddress());
        }
        // clean-up
        session.removeAttribute(IceTransport.Ice.STUN_STACK);
        session.removeAttribute(IceTransport.Ice.CONNECTION);
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
