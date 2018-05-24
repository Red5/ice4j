package org.ice4j.ice.nio;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.DelayQueue;
import java.util.concurrent.Delayed;
import java.util.concurrent.TimeUnit;

import org.apache.mina.core.service.IoAcceptor;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.ProtocolCodecFilter;
import org.ice4j.StackProperties;
import org.ice4j.Transport;
import org.ice4j.socket.IceSocketWrapper;
import org.ice4j.stack.StunStack;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * IceTransport, the parent transport class.
 * 
 * @author Paul Gregoire
 */
public abstract class IceTransport {

    private static final Logger logger = LoggerFactory.getLogger(IceTransport.class);

    private final static int BUFFER_SIZE_DEFAULT = 65535;

    // Expire ports in three seconds
    private final static long EXPIRE_TIME_NANOS = TimeUnit.MILLISECONDS.toNanos(3000L);

    private static DelayQueue<ExpiredPort> removedPortsQueue = new DelayQueue<>();

    private static Thread reaperThread;

    protected final static ProtocolCodecFilter iceCodecFilter = new ProtocolCodecFilter(new IceEncoder(), new IceDecoder());

    protected final static IceHandler iceHandler = new IceHandler();

    protected int receiveBufferSize = StackProperties.getInt("SO_RCVBUF", BUFFER_SIZE_DEFAULT);

    protected int sendBufferSize = StackProperties.getInt("SO_SNDBUF", BUFFER_SIZE_DEFAULT);

    // used for idle timeout checks, connection timeout is currently 3s
    protected static int timeout = StackProperties.getInt("SO_TIMEOUT", 30);

    protected int ioThreads = 16;

    protected IoAcceptor acceptor;

    // constants for the session map or anything else
    public enum Ice {
        TRANSPORT, CONNECTION, STUN_STACK, DECODER, ENCODER, DECODER_STATE_KEY, CANDIDATE, TCP_BUFFER;
    }

    static {
        // configure DNS cache ttl
        String ttl = System.getProperty("networkaddress.cache.ttl");
        if (ttl == null) {
            // persist successful lookup forever (during jvm instance existence)
            System.setProperty("networkaddress.cache.ttl", "-1");
        } else {
            logger.debug("DNS cache ttl: {}", ttl);
        }
    }

    /**
     * Creates the i/o handler and nio acceptor; ports and addresses are bound.
     */
    public IceTransport() {
    }

    /**
     * Returns a static instance of this transport.
     * 
     * @param type the transport type requested, either UDP or TCP
     * @return IceTransport
     */
    public static IceTransport getInstance(Transport type) {
        if (type == Transport.TCP) {
            return IceTcpTransport.getInstance();
        }
        return IceUdpTransport.getInstance();
    }

    /**
     * Returns the acceptor if it exists and null otherwise.
     * 
     * @return acceptor
     */
    public IoAcceptor getAcceptor() {
        return acceptor;
    }

    /**
     * Adds a socket binding to the acceptor.
     * 
     * @param addr
     * @return true if successful and false otherwise
     */
    public boolean addBinding(SocketAddress addr) {
        return false;
    }

    /**
     * Registers a StunStack and IceSocketWrapper to the internal maps to wait for their associated IoSession creation. This causes a bind on the given local address.
     * 
     * @param stunStack
     * @param iceSocket
     * @return true if successful and false otherwise
     */
    public boolean registerStackAndSocket(StunStack stunStack, IceSocketWrapper iceSocket) {
        return false;
    }

    /**
     * Removes a socket binding from the acceptor.
     * 
     * @param addr
     * @return true if successful and false otherwise
     */
    public boolean removeBinding(SocketAddress addr) {
        if (acceptor != null) {
            try {
                int port = ((InetSocketAddress) addr).getPort();
                // unbind
                acceptor.unbind(addr, InetSocketAddress.createUnresolved("0.0.0.0", port));
                // add to the delay queue
                removedPortsQueue.offer(new ExpiredPort(port));
                //if (logger.isTraceEnabled()) {
                logger.info("Binding removed: {}", addr);
                //}
                return true;
            } catch (Exception e) {
                logger.warn("Remove binding failed on {}", addr, e);
            }
        }
        return false;
    }

    /**
     * Ports and addresses are unbound (stop listening).
     */
    public void stop() throws Exception {
        if (acceptor != null) {
            logger.info("Stopped socket transport");
            acceptor.unbind();
            acceptor.dispose(true);
            logger.info("Disposed socket transport");
            acceptor = null;
        }
        if (reaperThread != null) {
            reaperThread.interrupt();
            reaperThread = null;
        }
    }

    /**
     * Returns true if the specified port was recently removed and its delay has not yet expired.
     * 
     * @param port
     * @return true if recently removed and false otherwise
     */
    public static boolean isRemoved(int port) {
        return removedPortsQueue.contains(port);
    }

    /**
     * Review all ports in-use for a conflict with the given port.
     * 
     * @param port
     * @return true if already bound and false otherwise
     */
    public static boolean isBound(int port) {
        // ensure there's a reaper for removed ports clearing the delay queue
        synchronized (removedPortsQueue) {
            if (reaperThread == null) {
                reaperThread = new Thread(new Runnable() {

                    @Override
                    public void run() {
                        do {
                            try {
                                ExpiredPort expired = removedPortsQueue.take();
                                if (expired != null) {
                                    logger.info("Port expired: {}", expired.port);
                                }
                            } catch (InterruptedException e) {
                                break;
                            }
                        } while (true);
                    }
                }, "Port Reaper");
                reaperThread.setDaemon(true);
                reaperThread.start();
            }
        }
        // check delay queue first for recently unbound ports
        if (isRemoved(port)) {
            logger.info("Port: {} was recently removed, it is not yet available", port);
            return true;
        }
        // UDP first
        IceTransport udpTransport = getInstance(Transport.UDP);
        Set<SocketAddress> addresses = udpTransport.acceptor.getLocalAddresses();
        if (!addresses.isEmpty()) {
            for (SocketAddress addr : addresses) {
                if (((InetSocketAddress) addr).getPort() == port) {
                    // its in-use, skip it!
                    logger.debug("UDP port: {} is already in-use (acceptor bound)", port);
                    return true;
                }
            }
        }
        Map<Long, IoSession> sessions = udpTransport.acceptor.getManagedSessions();
        if (!sessions.isEmpty()) {
            for (Entry<Long, IoSession> entry : sessions.entrySet()) {
                if (((InetSocketAddress) entry.getValue().getLocalAddress()).getPort() == port) {
                    // its in-use, skip it!
                    logger.debug("UDP port: {} is already in-use (session bound)", port);
                    return true;
                }
            }
        }
        // TCP second
        IceTransport tcpTransport = getInstance(Transport.TCP);
        addresses = tcpTransport.acceptor.getLocalAddresses();
        if (!addresses.isEmpty()) {
            for (SocketAddress addr : addresses) {
                if (((InetSocketAddress) addr).getPort() == port) {
                    // its in-use, skip it!
                    logger.debug("TCP port: {} is already in-use (acceptor bound)", port);
                    return true;
                }
            }
        }
        sessions = tcpTransport.acceptor.getManagedSessions();
        if (!sessions.isEmpty()) {
            for (Entry<Long, IoSession> entry : sessions.entrySet()) {
                if (((InetSocketAddress) entry.getValue().getLocalAddress()).getPort() == port) {
                    // its in-use, skip it!
                    logger.debug("TCP port: {} is already in-use (session bound)", port);
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Returns the static ProtocolCodecFilter.
     * 
     * @return iceCodecFilter
     */
    public static ProtocolCodecFilter getProtocolcodecfilter() {
        return iceCodecFilter;
    }

    /**
     * @param sendBufferSize the sendBufferSize to set
     */
    public void setSendBufferSize(int sendBufferSize) {
        this.sendBufferSize = sendBufferSize;
    }

    /**
     * @param receiveBufferSize the receiveBufferSize to set
     */
    public void setReceiveBufferSize(int receiveBufferSize) {
        this.receiveBufferSize = receiveBufferSize;
    }

    /**
     * General purpose timeout value; used for connection and idle timeouts.
     * 
     * @return timeout
     */
    public static int getTimeout() {
        return timeout;
    }

    /**
     * Set a timeout value in seconds.
     * 
     * @param timeout seconds to elapse before timing out
     */
    public static void setTimeout(int timeout) {
        IceTransport.timeout = timeout;
    }

    /**
     * @param ioThreads the ioThreads to set
     */
    public void setIoThreads(int ioThreads) {
        this.ioThreads = ioThreads;
    }

    /**
     * Returns the IoHandler for ICE connections.
     * 
     * @return iceHandler
     */
    public static IceHandler getIceHandler() {
        return iceHandler;
    }

    private class ExpiredPort implements Delayed {

        final long removed = System.currentTimeMillis();

        final int port;

        ExpiredPort(int port) {
            this.port = port;
        }

        @Override
        public int compareTo(Delayed o) {
            if (o instanceof ExpiredPort) {
                return ((ExpiredPort) o).port - port;
            }
            return 0;
        }

        @Override
        public long getDelay(TimeUnit unit) {
            // expects nanos
            return EXPIRE_TIME_NANOS - TimeUnit.MILLISECONDS.toNanos(System.currentTimeMillis() - removed);
        }

        @Override
        public int hashCode() {
            return port;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (getClass() != obj.getClass())
                return false;
            ExpiredPort other = (ExpiredPort) obj;
            if (port != other.port)
                return false;
            return true;
        }

    }

}