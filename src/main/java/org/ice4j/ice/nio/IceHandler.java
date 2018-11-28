package org.ice4j.ice.nio;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.apache.mina.core.buffer.IoBuffer;
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
    private static ConcurrentMap<TransportAddress, StunStack> stunStacks = new ConcurrentHashMap<>();

    // temporary holding area for ice sockets awaiting session creation
    private static ConcurrentMap<TransportAddress, IceSocketWrapper> iceSockets = new ConcurrentHashMap<>();

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
            //logger.debug("after stunStacks");
        } else {
            logger.debug("Stun stack for address: {}", stunStacks.get(addr));
        }
        iceSockets.putIfAbsent(addr, iceSocket);
        //logger.debug("exit registerStackAndSocket");
    }

    /**
     * Returns an IceSocketWrapper for a given address if it exists and null if it doesn't.
     * 
     * @param address
     * @return IceSocketWrapper
     */
    public IceSocketWrapper lookupBinding(TransportAddress address) {
        logger.trace("lookupBinding for address: {} existing bindings: {}", address, iceSockets);
        return iceSockets.get(address);
    }

    /**
     * Returns an IceSocketWrapper for a given remote address if it exists and null if it doesn't.
     * 
     * @param remoteAddress
     * @return IceSocketWrapper
     */
    public IceSocketWrapper lookupBindingByRemote(SocketAddress remoteAddress) {
        logger.trace("lookupBindingByRemote for address: {} existing bindings: {}", remoteAddress, iceSockets);
        IceSocketWrapper iceSocket = null;
        Optional<IceSocketWrapper> result = iceSockets.values().stream().filter(entry -> {
            IoSession session = entry.getSession();
            if (session != null) {
                InetSocketAddress sessionRemoteAddress = (InetSocketAddress) session.getRemoteAddress();
                // check the port and then also the host address
                return (sessionRemoteAddress.getPort() == ((InetSocketAddress) remoteAddress).getPort() &&
                        sessionRemoteAddress.getAddress().getHostAddress().equals(((InetSocketAddress) remoteAddress).getAddress().getHostAddress()));
            }
            return false;
        }).findFirst();
        if (result.isPresent()) {
            iceSocket = result.get();
        }
        return iceSocket;
    }

    /**
     * Returns an StunStack for a given address if it exists and null if it doesn't.
     * 
     * @param address
     * @return StunStack
     */
    public StunStack lookupStunStack(TransportAddress address) {
        return stunStacks.get(address);
    }

    /** {@inheritDoc} */
    @Override
    public void sessionCreated(IoSession session) throws Exception {
        logger.trace("Created (session: {}) local: {} remote: {}", session.getId(), session.getLocalAddress(), session.getRemoteAddress());
        Transport transport = session.getTransportMetadata().isConnectionless() ? Transport.UDP : Transport.TCP;
        // set transport type, making it easier to look-up later
        session.setAttribute(IceTransport.Ice.TRANSPORT, transport);
        // get the local address
        InetSocketAddress inetAddr = (InetSocketAddress) session.getLocalAddress();
        TransportAddress addr = new TransportAddress(inetAddr.getAddress(), inetAddr.getPort(), transport);
        IceSocketWrapper iceSocket = iceSockets.get(addr);
        if (iceSocket != null) {
            // set the session
            iceSocket.setSession(session);
            // add the socket to the session if its not there already
            if (!session.containsAttribute(IceTransport.Ice.CONNECTION)) {
                session.setAttribute(IceTransport.Ice.CONNECTION, iceSocket);
            }
        } else {
            logger.debug("No ice socket at create for: {}", addr);
        }
        StunStack stunStack = stunStacks.get(addr);
        if (stunStack != null) {
            session.setAttribute(IceTransport.Ice.STUN_STACK, stunStack);
            // XXX create socket registration
            if (transport == Transport.TCP) {
                if (iceSocket != null) {
                    // get the remote address
                    inetAddr = (InetSocketAddress) session.getRemoteAddress();
                    TransportAddress remoteAddress = new TransportAddress(inetAddr.getAddress(), inetAddr.getPort(), transport);
                    iceSocket.setRemoteTransportAddress(remoteAddress);
                    stunStack.getNetAccessManager().addSocket(iceSocket, iceSocket.getRemoteTransportAddress());
                } else {
                    // socket was in most cases recently closed or in-process of being closed / cleaned up, so return and exception
                    throw new IOException("Connection already closed for: " + session.toString());
                }
            }
        } else {
            logger.debug("No stun stack at create for: {}", addr);
        }
    }

    /** {@inheritDoc} */
    @Override
    public void sessionOpened(IoSession session) throws Exception {
        logger.debug("Opened (session: {}) local: {} remote: {}", session.getId(), session.getLocalAddress(), session.getRemoteAddress());
    }

    /** {@inheritDoc} */
    @Override
    public void messageReceived(IoSession session, Object message) throws Exception {
        if (logger.isTraceEnabled()) {
            logger.trace("Message received (session: {}) local: {} remote: {}\nReceived: {}", session.getId(), session.getLocalAddress(), session.getRemoteAddress(), String.valueOf(message));
        }
        IceSocketWrapper iceSocket = (IceSocketWrapper) session.getAttribute(IceTransport.Ice.CONNECTION);
        if (iceSocket != null) {
            if (message instanceof RawMessage) {
                // non-stun message
                iceSocket.offerMessage((RawMessage) message);
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
        if (message instanceof IoBuffer) {
            if (logger.isTraceEnabled()) {
                logger.trace("Message sent (session: {}) local: {} remote: {}\nread: {} write: {}", session.getId(), session.getLocalAddress(), session.getRemoteAddress(), session.getReadBytes(), session.getWrittenBytes());
                //logger.trace("Sent: {}", String.valueOf(message));
                byte[] output = ((IoBuffer) message).array();
                if (IceDecoder.isDtls(output)) {
                    logger.trace("Sent - DTLS sequence number: {}", readUint48(output, 5));
                }
            }
            Optional<Object> socket = Optional.ofNullable(session.getAttribute(IceTransport.Ice.CONNECTION));
            if (socket.isPresent()) {
                // update total message/byte counters
                ((IceSocketWrapper) socket.get()).updateWriteCounters(session.getWrittenBytes());
            } else {
                logger.info("No socket present in session {} for write counter update", session.getId());
            }
        }
    }

    /** {@inheritDoc} */
    @Override
    public void sessionIdle(IoSession session, IdleStatus status) throws Exception {
        if (logger.isTraceEnabled()) {
            logger.trace("Idle (session: {}) local: {} remote: {}\nread: {} write: {}", session.getId(), session.getLocalAddress(), session.getRemoteAddress(), session.getReadBytes(), session.getWrittenBytes());
        }
        session.closeNow();
    }

    /** {@inheritDoc} */
    @Override
    public void sessionClosed(IoSession session) throws Exception {
        logger.debug("Session closed: {}", session.getId());
        // if the session is not marked as the active one, don't close it
        if (session.containsAttribute(IceTransport.Ice.ACTIVE_SESSION)) {
            // get the existing reference to an ice socket
            final IceSocketWrapper iceSocket = (IceSocketWrapper) session.removeAttribute(IceTransport.Ice.CONNECTION);
            // close the idle socket only if the session is the current session in-use
            if (iceSocket != null) {
                iceSocket.close(session);
            } else {
                logger.debug("No socket in session at close: {}", session);
            }
        } else {
            logger.debug("Session not marked as active at close: {}", session);
        }
        super.sessionClosed(session);
    }

    /** {@inheritDoc} */
    @Override
    public void exceptionCaught(IoSession session, Throwable cause) throws Exception {
        logger.warn("Exception on session: {}", session.getId(), cause);
        // determine transport type
        Transport transportType = (session.removeAttribute(IceTransport.Ice.TRANSPORT) == Transport.TCP) ? Transport.TCP : Transport.UDP;
        InetSocketAddress inetAddr = (InetSocketAddress) session.getLocalAddress();
        TransportAddress addr = new TransportAddress(inetAddr.getAddress(), inetAddr.getPort(), transportType);
        logger.info("Exception on {}", addr);
        // get the transport / acceptor identifier
        String id = (String) session.getAttribute(IceTransport.Ice.UUID);
        // get transport by type
        IceTransport transport = IceTransport.getInstance(transportType, id);
        if (IceTransport.isSharedAcceptor()) {
            // shared, so don't kill it, just remove binding
            transport.removeBinding(addr);
        } else {
            // remove binding
            transport.removeBinding(addr);
            // not-shared, kill it
            transport.stop();
        }
        // remove any map entries
        stunStacks.remove(addr);
        IceSocketWrapper iceSocket = iceSockets.remove(addr);
        if (iceSocket == null && session.containsAttribute(IceTransport.Ice.CONNECTION)) {
            iceSocket = (IceSocketWrapper) session.removeAttribute(IceTransport.Ice.CONNECTION);
        }
        if (iceSocket != null) {
            iceSocket.close(session);
        }
    }

    public void remove(SocketAddress addr) {
        stunStacks.remove(addr);
        iceSockets.remove(addr);
    }

    /* From BC TlsUtils for debugging */

    public static int readUint24(byte[] buf, int offset) {
        int n = (buf[offset] & 0xff) << 16;
        n |= (buf[++offset] & 0xff) << 8;
        n |= (buf[++offset] & 0xff);
        return n;
    }

    public static long readUint48(byte[] buf, int offset) {
        int hi = readUint24(buf, offset);
        int lo = readUint24(buf, offset + 3);
        return ((long) (hi & 0xffffffffL) << 24) | (long) (lo & 0xffffffffL);
    }

}
