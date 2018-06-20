/* See LICENSE.md for license information */
package org.ice4j.socket;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedTransferQueue;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.future.CloseFuture;
import org.apache.mina.core.future.ConnectFuture;
import org.apache.mina.core.future.IoFutureListener;
import org.apache.mina.core.future.WriteFuture;
import org.apache.mina.core.session.IoSession;
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

    public final static IoSession NULL_SESSION = null;

    public final static String DISCONNECTED = "disconnected";

    /**
     * Used to control fair write / send order.
     */
    protected Semaphore lock = new Semaphore(1, true);

    /**
     * Used to control connection flow.
     */
    protected CountDownLatch connectLatch = new CountDownLatch(1);

    protected TransportAddress transportAddress;

    protected TransportAddress remoteTransportAddress;

    // whether or not we've been closed
    public boolean closed;

    /**
     * IoSession for this socket / connection; will be one of type NioDatagramSession for UDP or NioSocketSession for TCP.
     */
    protected AtomicReference<IoSession> session = new AtomicReference<>();

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
                // count down since we have a session
                connectLatch.countDown();
            } else {
                logger.warn("Connect failed from: {} to: {}", transportAddress, remoteTransportAddress);
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

    IceSocketWrapper(IoSession session) {
        setSession(session);
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
     * Returns true if closed or unbound and false otherwise.
     * 
     * @return true = not open, false = not closed
     */
    public boolean isClosed() {
        IoSession sess = session.get();
        if (sess != null) {
            closed = sess.isClosing(); // covers closing and / or closed
        }
        return closed;
    }

    /**
     * Closes the connected session as well as the acceptor, if its non-shared.
     */
    public void close() {
        //logger.debug("Close: {}", this);
        IoSession sess = session.get();
        if (sess != null) {
            logger.debug("Close session: {}", sess.getId());
            try {
                CloseFuture future = sess.closeNow();
                // wait until the connection is closed
                future.awaitUninterruptibly();
                //logger.debug("CloseFuture done: {}", sess.getId());
                // now connection should be closed
                if (future.isClosed()) {
                    //logger.debug("CloseFuture closed: {}", sess.getId());
                    session.set(NULL_SESSION);
                    closed = true;
                } else {
                    logger.info("CloseFuture not closed: {}", sess.getId());
                }
            } catch (Throwable t) {
                logger.warn("Fail on close", t);
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
        if (sess != null && sess.containsAttribute(IceTransport.Ice.UUID)) {
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
        if (sess == null) {
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
        if (newSession != null && session.compareAndSet(NULL_SESSION, newSession)) {
            newSession.setAttribute(IceTransport.Ice.CONNECTION, this);
        } else {
            session.set(newSession);
        }
    }

    /**
     * Returns an IoSession or null.
     *
     * @return IoSession if one exists or null otherwise
     */
    public IoSession getSession() {
        return session.get();
    }

    /**
     * Returns TransportAddress for the wrapped socket implementation.
     * 
     * @return transport address
     */
    public TransportAddress getTransportAddress() {
        logger.debug("getTransportAddress: {} session: {}", transportAddress, session);
        if (transportAddress == null && session != null) {
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
     * Sets the socket timeout.
     */
    public void setSoTimeout(int timeout) throws SocketException {
        soTimeout = timeout;
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
        // TODO remove this sysout
        //System.out.println("build: " + session + " connectionless: " + session.getTransportMetadata().isConnectionless());
        IceSocketWrapper iceSocket = null;
        if (session.getTransportMetadata().isConnectionless()) {
            iceSocket = new IceUdpSocketWrapper(session);
        } else {
            iceSocket = new IceTcpSocketWrapper(session);
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
     * @param session IoSession for the socket
     * @return IceSocketWrapper for the given session type
     * @throws IOException
     */
    public final static IceSocketWrapper build(TransportAddress localAddress, TransportAddress remoteAddress) throws IOException {
        // TODO remove this sysout
        //System.out.println("build: " + localAddress + " remote: " + remoteAddress);
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

}
