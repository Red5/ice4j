package org.ice4j.ice.nio;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Map.Entry;
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
        Optional<Entry<TransportAddress, IceSocketWrapper>> result = iceSockets.entrySet().stream().filter(entry -> (entry.getValue().getSession() != null && entry.getValue().getSession().getRemoteAddress().equals(remoteAddress))).findFirst();
        if (result.isPresent()) {
            iceSocket = result.get().getValue();
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
            logger.trace("Message received (session: {}) local: {} remote: {}", session.getId(), session.getLocalAddress(), session.getRemoteAddress());
            logger.trace("Received: {}", String.valueOf(message));
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
        if (logger.isTraceEnabled()) {
            logger.trace("Message sent (session: {}) local: {} remote: {}\nread: {} write: {}", session.getId(), session.getLocalAddress(), session.getRemoteAddress(), session.getReadBytes(), session.getWrittenBytes());
            //logger.trace("Sent: {}", String.valueOf(message));
            byte[] output = ((IoBuffer) message).array();
            if (IceDecoder.isDtls(output)) {
                logger.trace("Sent - DTLS sequence number: {}", readUint48(output, 5));
            }
        }
    }

    /** {@inheritDoc} */
    @Override
    public void sessionIdle(IoSession session, IdleStatus status) throws Exception {
        if (logger.isTraceEnabled()) {
            logger.trace("Idle (session: {}) local: {} remote: {}\nread: {} write: {}", session.getId(), session.getLocalAddress(), session.getRemoteAddress(), session.getReadBytes(), session.getWrittenBytes());
        }
        // allow flagging a session from being closed on idle
        boolean closeOnIdle = true;
        if (session.containsAttribute(IceTransport.Ice.CLOSE_ON_IDLE)) {
            closeOnIdle = Boolean.valueOf((boolean) session.getAttribute(IceTransport.Ice.CLOSE_ON_IDLE));
        }
        // get the existing reference to an ice socket
        final IceSocketWrapper iceSocket = (IceSocketWrapper) session.getAttribute(IceTransport.Ice.CONNECTION);
        // close the idle socket
        if (iceSocket != null && closeOnIdle) {
            iceSocket.close();
        } else {
            logger.debug("Skipping close on idle session: {}", session);
        }
    }

    /** {@inheritDoc} */
    @Override
    public void sessionClosed(IoSession session) throws Exception {
        logger.debug("Session closed: {}", session.getId());
        // shutdown and clear all the associated ice features only if the session is the "ACTIVE" one
        if (session.containsAttribute(IceTransport.Ice.ACTIVE_SESSION)) {
            // determine transport type
            Transport transportType = (session.removeAttribute(IceTransport.Ice.TRANSPORT) == Transport.TCP) ? Transport.TCP : Transport.UDP;
            // ensure transport is correct using metadata if its set to TCP
            if (transportType == Transport.TCP && session.getTransportMetadata().isConnectionless()) {
                transportType = Transport.UDP;
            }
            InetSocketAddress inetAddr = (InetSocketAddress) session.getLocalAddress();
            TransportAddress addr = new TransportAddress(inetAddr.getAddress(), inetAddr.getPort(), transportType);
            // clean-up
            IceSocketWrapper iceSocket = null;
            if (session.containsAttribute(IceTransport.Ice.CONNECTION)) {
                iceSocket = (IceSocketWrapper) session.removeAttribute(IceTransport.Ice.CONNECTION);
            }
            if (session.containsAttribute(IceTransport.Ice.STUN_STACK)) {
                // get the transport / acceptor id
                String id = (String) session.getAttribute(IceTransport.Ice.UUID);
                // get the stun stack
                StunStack stunStack = (StunStack) session.removeAttribute(IceTransport.Ice.STUN_STACK);
                if (iceSocket != null) {
                    stunStack.removeSocket(id, addr, iceSocket.getRemoteTransportAddress());
                } else {
                    inetAddr = (InetSocketAddress) session.getRemoteAddress();
                    TransportAddress remoteAddr = new TransportAddress(inetAddr.getAddress(), inetAddr.getPort(), transportType);
                    stunStack.removeSocket(id, addr, remoteAddr);
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
            // get the transport / acceptor identifier
            String id = (String) session.getAttribute(IceTransport.Ice.UUID);
            // get transport by type
            IceTransport transport = IceTransport.getInstance(transportType, id);
            if (transport != null) {
                if (IceTransport.isSharedAcceptor()) {
                    // shared, so don't kill it, just remove binding
                    transport.removeBinding(addr);
                } else {
                    // remove binding
                    transport.removeBinding(addr);
                    // not-shared, kill it
                    transport.stop();
                }
            } else {
                logger.debug("Transport for id: {} was not found", id);
            }
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
            iceSocket.close();
        }
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
