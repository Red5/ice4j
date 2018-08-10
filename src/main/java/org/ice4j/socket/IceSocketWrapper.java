/* See LICENSE.md for license information */
package org.ice4j.socket;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
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
import org.ice4j.stack.RawMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Abstract socket wrapper that define a socket that could be UDP, TCP...
 *
 * @author Paul Gregoire
 */
public abstract class IceSocketWrapper {

    protected final Logger logger = LoggerFactory.getLogger(IceSocketWrapper.class);

    public final static IoSession NULL_SESSION = new DummySession();

    public final static String DISCONNECTED = "disconnected";

    // whether or not we've been closed
    public boolean closed;

    /**
     * Used to control connection flow.
     */
    protected CountDownLatch connectLatch = new CountDownLatch(1);

    protected TransportAddress transportAddress;

    protected TransportAddress remoteTransportAddress;

    // whether or not we're a relay
    protected RelayedCandidateConnection relayedCandidateConnection;

    /**
     * IoSession for this socket / connection; will be one of type NioDatagramSession for UDP or NioSocketSession for TCP.
     */
    protected AtomicReference<IoSession> session = new AtomicReference<>(NULL_SESSION);

    /**
     * IoSession list of previous connections.
     */
    protected List<IoSession> staleSessions = new CopyOnWriteArrayList<>();

    /**
     * Socket timeout.
     */
    protected int soTimeout;

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
                setSession(future.getSession());
            } else {
                if (remoteTransportAddress == null) {
                    logger.warn("Connect failed from: {}", transportAddress);
                } else {
                    logger.warn("Connect failed from: {} to: {}", transportAddress, remoteTransportAddress);
                }
            }
            // count down since connect is complete
            connectLatch.countDown();
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
     * Creates a new session with the given remote destination address.
     * 
     * @param destAddress remote address
     */
    public void newSession(SocketAddress destAddress) {
        // this primarily for UDP see IceUdpSocketWrapper
    }

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
        IoSession sess = session.get();
        if (!sess.equals(NULL_SESSION)) {
            closed = sess.isClosing(); // covers closing and / or closed
        }
        return closed;
    }

    /**
     * Closes the connected session as well as the acceptor, if its non-shared.
     */
    public void close() {
        //logger.debug("Close: {}", this);
        IoSession sess = getSession();
        if (sess != null) {
            logger.debug("Close session: {}", sess.getId());
            try {
                // if the session isn't already closed or disconnected
                if (!sess.isClosing()) {
                    CloseFuture future = sess.closeNow();
                    // wait until the connection is closed
                    future.awaitUninterruptibly();
                    //logger.debug("CloseFuture done: {}", sess.getId());
                    // now connection should be closed
                    if (!future.isClosed()) {
                        logger.info("CloseFuture not closed: {}", sess.getId());
                    }
                }
                session.set(NULL_SESSION);
                closed = true;
            } catch (Throwable t) {
                logger.warn("Fail on close", t);
            } finally {
                staleSessions.forEach(session -> {
                    try {
                        // if the session isn't already closed or disconnected
                        if (!session.isClosing()) {
                            session.closeNow();
                        }
                    } catch (Throwable t) {
                        logger.warn("Fail on (stale session) close", t);
                    }
                });
            }
        } else {
            //logger.debug("Session null, closed: {}", closed);
            closed = true;
        }
        // clear out raw messages lingering around at close
        rawMessageQueue.clear();
        //logger.debug("Exit close: {} closed: {}", this, closed);
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
        logger.trace("setSession - new: {} old: {}", newSession, session.get());
        if (newSession == null || newSession.equals(NULL_SESSION)) {
            session.set(NULL_SESSION);
        } else if (session.compareAndSet(NULL_SESSION, newSession)) {
            // set the connection attribute
            newSession.setAttribute(IceTransport.Ice.CONNECTION, this);
            // set the newly added session as the active one
            newSession.setAttribute(IceTransport.Ice.ACTIVE_SESSION);
        } else if (newSession.getId() != session.get().getId()) {
            // if there was an old session and its not a dummy or incoming one, close it
            IoSession oldSession = session.getAndSet(newSession);
            logger.debug("Sessions didn't match, previous session: {}", oldSession);
            // set the connection attribute
            newSession.setAttribute(IceTransport.Ice.CONNECTION, this);
            // set the newly added session as the active one
            newSession.setAttribute(IceTransport.Ice.ACTIVE_SESSION);
            // remove active session indicator from previous session
            oldSession.removeAttribute(IceTransport.Ice.ACTIVE_SESSION);
            // if old session is UDP add to stale, if TCP, close it
            if (isUDP()) {
                // set a flag to prevent the idle checker on old session from closing the socket wrapper
                oldSession.setAttribute(IceTransport.Ice.CLOSE_ON_IDLE, Boolean.FALSE);
                // add to stale for closing later
                staleSessions.add(oldSession);
            } else {
                logger.debug("Closing previous TCP session: {}", oldSession);
                oldSession.closeNow();
            }
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
        logger.debug("getTransportAddress: {} session: {}", transportAddress, getSession());
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
            this.remoteTransportAddress = remoteAddress;
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
            return rawMessageQueue.offer(message);
        }
        logger.debug("Message rejected, socket is closed");
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
    protected void finalize() throws Throwable {
        try {
            if (rawMessageQueue != null) {
                rawMessageQueue.clear();
                rawMessageQueue = null;
            }
        } catch (Throwable t) {
            throw t;
        } finally {
            super.finalize();
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
    public final static IceSocketWrapper build(IoSession session) throws IOException {
        IceSocketWrapper iceSocket = null;
        if (session.getTransportMetadata().isConnectionless()) {
            iceSocket = new IceUdpSocketWrapper();
            iceSocket.setSession(session);
        } else {
            iceSocket = new IceTcpSocketWrapper();
            iceSocket.setSession(session);
            // set remote address (only sticks if its TCP)
            InetSocketAddress inetAddr = (InetSocketAddress) session.getRemoteAddress();
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
