/* See LICENSE.md for license information */
package org.ice4j.socket;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.util.Optional;
import java.util.concurrent.LinkedTransferQueue;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.future.CloseFuture;
import org.apache.mina.core.future.ConnectFuture;
import org.apache.mina.core.future.IoFutureListener;
import org.apache.mina.core.future.WriteFuture;
import org.apache.mina.core.session.DummySession;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.core.session.IoSessionConfig;
import org.apache.mina.transport.socket.DatagramSessionConfig;
import org.apache.mina.transport.socket.SocketSessionConfig;
import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.ice.nio.IceTransport;
import org.ice4j.ice.nio.IceTransport.Ice;
import org.ice4j.ice.nio.IceUdpTransport;
import org.ice4j.stack.RawMessage;
import org.ice4j.stack.StunStack;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Abstract socket wrapper that define a socket that could be UDP, TCP...
 *
 * @author Paul Gregoire
 */
public abstract class IceSocketWrapper {

    public final static IoSession NULL_SESSION = new DummySession();

    public final static String DISCONNECTED = "disconnected";

    protected final Logger logger = LoggerFactory.getLogger(IceSocketWrapper.class);

    // whether or not we've been closed
    public volatile boolean closed;

    protected TransportAddress transportAddress;

    protected TransportAddress remoteTransportAddress;

    // whether or not we're a relay
    protected RelayedCandidateConnection relayedCandidateConnection;

    /**
     * IoSession for this socket / connection; will be one of type NioDatagramSession for UDP or NioSocketSession for TCP.
     */
    protected AtomicReference<IoSession> session = new AtomicReference<>(NULL_SESSION);

    /**
     * Socket timeout.
     */
    protected int soTimeout;

    /**
     * Written message counter.
     */
    protected long writtenMessages;

    /**
     * Written byte counter.
     */
    protected long writtenBytes;

    /**
     * Written STUN/TURN message counter.
     */
    protected long writtenStunMessages;

    /**
     * Written STUN/TURN byte counter.
     */
    protected long writtenStunBytes;

    /**
     * The message queue is where incoming messages are added that were not otherwise processed (ie. DTLS etc..).
     */
    protected LinkedTransferQueue<RawMessage> rawMessageQueue = new LinkedTransferQueue<>();

    /**
     * Reusable IoFutureListener for connect.
     */
    protected final IoFutureListener<ConnectFuture> connectListener = new IoFutureListener<ConnectFuture>() {

        @Override
        public void operationComplete(ConnectFuture future) {
            if (future.isConnected()) {
                logger.debug("Setting session from future");
                setSession(future.getSession());
            } else {
                if (remoteTransportAddress == null) {
                    logger.warn("Connect failed from: {}", transportAddress);
                } else {
                    logger.warn("Connect failed from: {} to: {}", transportAddress, remoteTransportAddress);
                }
            }
        }

    };

    /**
     * Reusable IoFutureListener for writes.
     */
    protected final IoFutureListener<WriteFuture> writeListener = new IoFutureListener<WriteFuture>() {

        @Override
        public void operationComplete(WriteFuture future) {
            if (!future.isWritten()) {
                if (logger.isDebugEnabled()) {
                    IoSession sess = future.getSession();
                    if (sess != null) {
                        logger.debug("Write failed from: {} to: {}", sess.getLocalAddress(), sess.getRemoteAddress());
                    } else {
                        logger.debug("Write failed from: {} to: {}", transportAddress, remoteTransportAddress);
                    }
                }
            }
        }

    };

    /**
     * Sends an IoBuffer from this socket. It is a utility method to provide a common way to send for both UDP and TCP socket.
     *
     * @param buf IoBuffer to send
     * @param destAddress destination SocketAddress to send to
     * @throws IOException if something goes wrong
     */
    public abstract void send(IoBuffer buf, SocketAddress destAddress) throws IOException;

    /**
     * Sends a DatagramPacket from this socket. It is a utility method to provide a common way to send for both UDP and TCP socket.
     *
     * @param p DatagramPacket to send
     * @throws IOException if something goes wrong
     */
    public abstract void send(DatagramPacket p) throws IOException;

    /**
     * Receives a DatagramPacket from this instance. Essentially it reads from already queued data, if the queue is empty, the datagram will be empty.
     * 
     * @param p DatagramPacket to receive
     */
    public abstract void receive(DatagramPacket p) throws IOException;

    /**
     * Reads one message from the head of the queue or null if the queue is empty.
     * 
     * @return RawMessage
     */
    public abstract RawMessage read();

    /**
     * Returns true if closed or unbound and false otherwise.
     * 
     * @return true = not open, false = not closed
     */
    public boolean isClosed() {
        if (!closed) {
            IoSession sess = session.get();
            if (!sess.equals(NULL_SESSION)) {
                closed = sess.isClosing(); // covers closing and / or closed
            }
        }
        return closed;
    }

    /**
     * Closes the connected session as well as the acceptor, if its non-shared.
     */
    public void close() {
        close(getSession());
    }

    /**
     * Closes the connected session as well as the acceptor, if its non-shared.
     * 
     * @param sess IoSession being closed
     */
    public void close(IoSession sess) {
        //logger.debug("Close: {}", this);
        // clear out raw messages lingering around at close
        try {
            if (rawMessageQueue != null) {
                rawMessageQueue.clear();
                rawMessageQueue = null;
            }
        } catch (Throwable t) {
            logger.warn("Exception clearing queue", t);
        }
        if (!closed) {
            // set closed flag
            closed = true;
            // get the session and close it
            Optional<IoSession> opt = Optional.ofNullable(sess);
            if (opt.isPresent()) {
                logger.debug("Close session: {}", sess.getId());
                // get the associated tranport id
                String id = getId();
                // clear session
                session.set(NULL_SESSION);
                try {
                    // if the session isn't already closed or disconnected
                    if (!sess.isClosing()) {
                        CloseFuture future = sess.closeNow();
                        // wait until the connection is closed
                        future.awaitUninterruptibly();
                        logger.debug("CloseFuture done: {}", sess.getId());
                        // now connection should be closed
                        if (!future.isClosed()) {
                            logger.info("CloseFuture not closed: {}", sess.getId());
                        }
                        // additional clean up steps
                        Optional<Object> stunStack = Optional.ofNullable(sess.removeAttribute(IceTransport.Ice.STUN_STACK));
                        if (stunStack.isPresent()) {
                            // part of the removal process in stunstack removes the binding on the transport
                            ((StunStack) stunStack.get()).removeSocket(id, transportAddress, remoteTransportAddress);
                        } else {
                            // if theres no stun stack, go the direct route
                            IceTransport transport = IceTransport.getInstance((isUDP() ? Transport.UDP : Transport.TCP), id);
                            if (transport != null) {
                                if (IceTransport.isSharedAcceptor()) {
                                    // shared, so don't kill it, just remove binding
                                    transport.removeBinding(transportAddress);
                                } else {
                                    // remove binding
                                    transport.removeBinding(transportAddress);
                                    try {
                                        // not-shared, kill it
                                        transport.stop();
                                    } catch (Exception e) {
                                        logger.warn("Exception stopping transport", e);
                                    }
                                }
                            } else {
                                logger.debug("Transport for id: {} was not found", id);
                            }
                        }
                    }
                } catch (Throwable t) {
                    logger.warn("Fail on close", t);
                }
            }
            // for GC
            transportAddress = null;
            remoteTransportAddress = null;
            relayedCandidateConnection = null;
            logger.trace("Exit close: {} closed: {}", this, closed);
        }
    }

    /**
     * Updates the written bytes / message counters.
     * 
     * @param bytesLength
     */
    public void updateWriteCounters(long bytesLength) {
        // incoming length is the total from the IoSession
        writtenBytes = bytesLength;
        writtenMessages++;
        //logger.trace("updateWriteCounters - writtenBytes: {} writtenMessages: {}", writtenBytes, writtenMessages);
    }

    /**
     * Updates the STUN/TURN written bytes / message counters.
     * 
     * @param bytesLength
     */
    public void updateSTUNWriteCounters(int bytesLength) {
        // incoming length is the message bytes length
        writtenStunBytes += bytesLength;
        writtenStunMessages++;
        //logger.trace("updateSTUNWriteCounters - writtenBytes: {} writtenMessages: {}", writtenStunBytes, writtenStunMessages);
    }

    /**
     * Returns the written byte count excluding STUN/TURN bytes.
     * 
     * @return byte count minus STUN/TURN bytes
     */
    public long getWrittenBytes() {
        long written = 0L;
        if (writtenBytes > 0) {
            written = writtenBytes - writtenStunBytes;
        }
        return written;
    }

    /**
     * Returns the written message count excluding STUN/TURN messages.
     * 
     * @return message count minus STUN/TURN messages
     */
    public long getWrittenMessages() {
        long written = 0L;
        if (writtenMessages > 0) {
            written = writtenMessages - writtenStunMessages;
        }
        return written;
    }

    /**
     * Returns the unique identifier for the associated acceptor.
     * 
     * @return UUID string for this instance or "disconnected" if not set on the session or not connected
     */
    public String getId() {
        String id = DISCONNECTED;
        IoSession sess = session.get();
        if (!sess.equals(NULL_SESSION) && sess.containsAttribute(IceTransport.Ice.UUID)) {
            id = (String) sess.getAttribute(IceTransport.Ice.UUID);
        }
        return id;
    }

    /**
     * Get local address.
     *
     * @return local address
     */
    public abstract InetAddress getLocalAddress();

    /**
     * Get local port.
     *
     * @return local port
     */
    public abstract int getLocalPort();

    /**
     * Get socket address.
     *
     * @return socket address
     */
    public SocketAddress getLocalSocketAddress() {
        IoSession sess = session.get();
        if (sess.equals(NULL_SESSION)) {
            return transportAddress;
        }
        return sess.getLocalAddress();
    }

    /**
     * Sets the IoSession for this socket wrapper.
     * 
     * @param newSession
     */
    public void setSession(IoSession newSession) {
        logger.trace("setSession - addr: {} session: {} previous: {}", transportAddress, newSession, session.get());
        if (newSession == null || newSession.equals(NULL_SESSION)) {
            session.set(NULL_SESSION);
        } else if (session.compareAndSet(NULL_SESSION, newSession)) {
            // set the connection attribute
            newSession.setAttribute(Ice.CONNECTION, this);
            // flag the session as selected / active!
            newSession.setAttribute(Ice.ACTIVE_SESSION, Boolean.TRUE);
            //} else if (session.get().getId() != newSession.getId()) {
            //logger.warn("Sessions don't match, current: {} incoming: {}", session.get(), newSession);
        } else {
            logger.warn("Session already set: {} incoming: {}", session.get(), newSession);
        }
    }

    /**
     * Returns an IoSession or null.
     *
     * @return IoSession if one exists or null otherwise
     */
    public IoSession getSession() {
        return !session.get().equals(NULL_SESSION) ? session.get() : null;
    }

    /**
     * Returns TransportAddress for the wrapped socket implementation.
     * 
     * @return transport address
     */
    public TransportAddress getTransportAddress() {
        if (logger.isTraceEnabled()) {
            logger.trace("getTransportAddress: {} session: {}", transportAddress, getSession());
        }
        if (transportAddress == null && !session.get().equals(NULL_SESSION)) {
            if (this instanceof IceUdpSocketWrapper) {
                transportAddress = new TransportAddress((InetSocketAddress) session.get().getLocalAddress(), Transport.UDP);
            } else {
                transportAddress = new TransportAddress((InetSocketAddress) session.get().getLocalAddress(), Transport.TCP);
            }
        }
        return transportAddress;
    }

    /**
     * Sets the TransportAddress of the remote end-point.
     * 
     * @param remoteAddress address
     */
    public void setRemoteTransportAddress(TransportAddress remoteAddress) {
        // only set remote address for TCP
        if (this instanceof IceTcpSocketWrapper) {
            remoteTransportAddress = remoteAddress;
        } else {
            // get the transport 
            IceUdpTransport transport = IceUdpTransport.getInstance(getId());
            // get session matching the remote address
            IoSession sess = transport.getSessionByRemote(remoteAddress);
            // set the selected session on the wrapper
            setSession(sess);
        }
        if (rawMessageQueue != null) {
            // clear the queue of any messages not meant for the remote address being set
            rawMessageQueue.forEach(message -> {
                TransportAddress messageRemoteAddress = message.getRemoteAddress();
                if (!messageRemoteAddress.equals(remoteAddress)) {
                    logger.warn("Ejecting message from {}", messageRemoteAddress);
                    rawMessageQueue.remove(message);
                }
            });
        } else {
            logger.warn("Queue is not available");
        }
    }

    public TransportAddress getRemoteTransportAddress() {
        return remoteTransportAddress;
    }

    /**
     * Sets the relay connection used for channel data in TURN.
     * 
     * @param relayedCandidateConnection
     */
    public void setRelayedConnection(RelayedCandidateConnection relayedCandidateConnection) {
        this.relayedCandidateConnection = relayedCandidateConnection;
    }

    public RelayedCandidateConnection getRelayedCandidateConnection() {
        return relayedCandidateConnection;
    }

    /**
     * Sets the socket timeout.
     * 
     * @param timeout
     */
    public void setSoTimeout(int timeout) throws SocketException {
        soTimeout = timeout;
    }

    /**
     * Sets the traffic class.
     * 
     * @param trafficClass
     */
    public void setTrafficClass(int trafficClass) {
        IoSession sess = session.get();
        if (!sess.equals(NULL_SESSION)) {
            IoSessionConfig config = sess.getConfig();
            if (config != null) {
                if (sess instanceof DatagramSessionConfig) {
                    DatagramSessionConfig dsConfig = (DatagramSessionConfig) config;
                    int currentTrafficClass = dsConfig.getTrafficClass();
                    if (logger.isDebugEnabled()) {
                        logger.debug("Datagram trafficClass: {} incoming: {}", currentTrafficClass, trafficClass);
                    }
                    if (currentTrafficClass != trafficClass) {
                        dsConfig.setTrafficClass(trafficClass);
                    }
                } else if (sess instanceof SocketSessionConfig) {
                    SocketSessionConfig ssConfig = (SocketSessionConfig) config;
                    int currentTrafficClass = ssConfig.getTrafficClass();
                    if (logger.isDebugEnabled()) {
                        logger.debug("Socket trafficClass: {} incoming: {}", currentTrafficClass, trafficClass);
                    }
                    if (currentTrafficClass != trafficClass) {
                        ssConfig.setTrafficClass(trafficClass);
                    }
                }
            }
        }
    }

    /**
     * Returns the raw message queue, which shouldn't contain any STUN/TURN messages.
     * 
     * @return rawMessageQueue
     */
    public LinkedTransferQueue<RawMessage> getRawMessageQueue() {
        return rawMessageQueue;
    }

    /**
     * Accepts or rejects an offered message based on our closed state.
     * 
     * @param message
     * @return true if accepted and false otherwise
     */
    public boolean offerMessage(RawMessage message) {
        if (!closed) {
            //logger.trace("offered message: {} local: {} remote: {}", message, transportAddress, remoteTransportAddress);
            if (rawMessageQueue != null) {
                return rawMessageQueue.offer(message);
            }
        }
        logger.debug("Message rejected, socket is closed or queue is not available");
        return false;
    }

    /**
     * Returns whether or not this is a TCP wrapper, based on the instance type.
     * 
     * @return true if TCP and false otherwise
     */
    public boolean isTCP() {
        return (this instanceof IceTcpSocketWrapper);
    }

    /**
     * Returns whether or not this is a UDP wrapper, based on the instance type.
     * 
     * @return true if UDP and false otherwise
     */
    public boolean isUDP() {
        return (this instanceof IceUdpSocketWrapper);
    }

    @Override
    public void finalize() {
        try {
            session.set(null);
            session = null;
        } catch (Exception e) {
            // ...
        }
    }
    
    /**
     * Builder for immutable IceSocketWrapper instance. If the IoSession is connection-less, an IceUdpSocketWrapper is returned; otherwise
     * an IceTcpSocketWrapper is returned.
     * 
     * @param session IoSession for the socket
     * @return IceSocketWrapper for the given session type
     * @throws IOException
     */
    @Deprecated
    public final static IceSocketWrapper build(IoSession session) throws IOException {
        InetSocketAddress inetAddr = (InetSocketAddress) session.getLocalAddress();
        IceSocketWrapper iceSocket = null;
        if (session.getTransportMetadata().isConnectionless()) {
            iceSocket = new IceUdpSocketWrapper(new TransportAddress(inetAddr.getAddress(), inetAddr.getPort(), Transport.UDP));
            iceSocket.setSession(session);
        } else {
            iceSocket = new IceTcpSocketWrapper(new TransportAddress(inetAddr.getAddress(), inetAddr.getPort(), Transport.TCP));
            iceSocket.setSession(session);
            // set remote address (only sticks if its TCP)
            inetAddr = (InetSocketAddress) session.getRemoteAddress();
            iceSocket.setRemoteTransportAddress(new TransportAddress(inetAddr.getAddress(), inetAddr.getPort(), Transport.TCP));
        }
        return iceSocket;
    }

    /**
     * Builder for immutable IceSocketWrapper instance. If the localAddress is udp, an IceUdpSocketWrapper is returned; otherwise
     * an IceTcpSocketWrapper is returned.
     * 
     * @param localAddress local address
     * @param remoteAddress destination address
     * @return IceSocketWrapper for the given address type
     * @throws IOException
     */
    public final static IceSocketWrapper build(TransportAddress localAddress, TransportAddress remoteAddress) throws IOException {
        IceSocketWrapper iceSocket = null;
        if (localAddress.getTransport() == Transport.UDP) {
            iceSocket = new IceUdpSocketWrapper(localAddress);
        } else {
            iceSocket = new IceTcpSocketWrapper(localAddress);
            // set remote address (only sticks if its TCP)
            iceSocket.setRemoteTransportAddress(new TransportAddress(remoteAddress.getAddress(), remoteAddress.getPort(), Transport.TCP));
        }
        return iceSocket;
    }

    /**
     * Builder for immutable IceSocketWrapper instance. If the localAddress is udp, an IceUdpSocketWrapper is returned; otherwise
     * an IceTcpSocketWrapper is returned.
     * 
     * @param relayedCandidateConnection relay connection (TURN channel)
     * @return IceSocketWrapper for the address session type
     * @throws IOException
     */
    public final static IceSocketWrapper build(RelayedCandidateConnection relayedCandidateConnection) throws IOException {
        // use the host address
        TransportAddress localAddress = (TransportAddress) relayedCandidateConnection.getTurnCandidateHarvest().hostCandidate.getTransportAddress();
        // look for an existing ice socket before creating a new one with the same local address
        IceSocketWrapper iceSocket = IceTransport.getIceHandler().lookupBinding(localAddress);
        if (iceSocket == null) {
            TransportAddress remoteAddress = relayedCandidateConnection.getTurnCandidateHarvest().harvester.stunServer;
            if (localAddress.getTransport() == Transport.UDP) {
                iceSocket = new IceUdpSocketWrapper(localAddress);
            } else {
                iceSocket = new IceTcpSocketWrapper(localAddress);
                // set remote address (only sticks if its TCP)
                iceSocket.setRemoteTransportAddress(new TransportAddress(remoteAddress.getAddress(), remoteAddress.getPort(), Transport.TCP));
            }
        }
        // attach the relay connection
        iceSocket.setRelayedConnection(relayedCandidateConnection);
        return iceSocket;
    }

}
