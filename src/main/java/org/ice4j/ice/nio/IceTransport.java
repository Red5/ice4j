package org.ice4j.ice.nio;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.apache.mina.core.service.IoAcceptor;
import org.apache.mina.filter.codec.ProtocolCodecFilter;
import org.apache.mina.util.CopyOnWriteMap;
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

    protected final static ProtocolCodecFilter iceCodecFilter = new ProtocolCodecFilter(new IceEncoder(), new IceDecoder());

    protected final static IceHandler iceHandler = new IceHandler();

    // used for idle timeout checks, the connection timeout is currently 3s; to disable this its -1
    protected static int timeout = StackProperties.getInt("SO_TIMEOUT", 120);

    // used for binding and unbinding timeout, default 2s
    protected static long acceptorTimeout = StackProperties.getInt("ACCEPTOR_TIMEOUT", 2);

    // whether or not to use a shared acceptor
    protected static boolean sharedAcceptor = StackProperties.getBoolean("NIO_SHARED_MODE", true);

    // whether or not to handle a hung acceptor aggressively
    protected static boolean aggressiveAcceptorReset = StackProperties.getBoolean("ACCEPTOR_RESET", false);

    // used to set QoS / traffic class option on the sockets
    public static int trafficClass = StackProperties.getInt("TRAFFIC_CLASS", 0);
    
    // thread-safe map containing ice transport instances
    protected static Map<String, IceTransport> transports = new CopyOnWriteMap<>(1);

    // holder of bound ports; used to prevent blocking issues querying acceptors
    protected static CopyOnWriteArraySet<Integer> boundPorts = new CopyOnWriteArraySet<>();

    /**
     * Unique identifier.
     */
    protected final String id = UUID.randomUUID().toString();

    protected int receiveBufferSize = StackProperties.getInt("SO_RCVBUF", BUFFER_SIZE_DEFAULT);

    protected int sendBufferSize = StackProperties.getInt("SO_SNDBUF", BUFFER_SIZE_DEFAULT);

    protected int ioThreads = StackProperties.getInt("NIO_WORKERS", Runtime.getRuntime().availableProcessors() * 2);

    /**
     * Local / instance socket acceptor; depending upon the transport, this will be NioDatagramAcceptor for UDP or NioSocketAcceptor for TCP.
     */
    protected IoAcceptor acceptor;

    protected ExecutorService executor = Executors.newCachedThreadPool();

    // constants for the session map or anything else
    public enum Ice {
        TRANSPORT, CONNECTION, STUN_STACK, DECODER, ENCODER, DECODER_STATE_KEY, CANDIDATE, TCP_BUFFER, UUID, CLOSE_ON_IDLE;
    }

    static {
        // configure DNS cache ttl
        String ttl = System.getProperty("networkaddress.cache.ttl");
        if (ttl == null) {
            // persist successful lookup forever -1
            // https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/java-dg-jvm-ttl.html
            System.setProperty("networkaddress.cache.ttl", "60");
        } else {
            logger.debug("DNS cache ttl: {}", ttl);
        }
        logger.info("Using shared acceptors: {}", sharedAcceptor);
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
     * @param id transport / acceptor identifier
     * @return IceTransport
     */
    public static IceTransport getInstance(Transport type, String id) {
        logger.trace("getInstance - type: {} id: {}", type, id);
        if (type == Transport.TCP) {
            return IceTcpTransport.getInstance(id);
        }
        return IceUdpTransport.getInstance(id);
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
        // remove map entry
        iceHandler.remove(addr);
        if (acceptor != null) {
            try {
                int port = ((InetSocketAddress) addr).getPort();
                if (isBound(port)) {
                    // unbind
                    Future<Boolean> unbindFuture = (Future<Boolean>) executor.submit(new Callable<Boolean>() {

                        @Override
                        public Boolean call() throws Exception {
                            logger.debug("Removing binding: {}", addr);
                            // remove the port from the list
                            boundPorts.remove(port);
                            // perform the unbinding
                            synchronized (acceptor) {
                                acceptor.unbind(addr);
                            }
                            logger.debug("Binding removed: {}", addr);
                            return Boolean.TRUE;
                        }

                    });
                    // wait a maximum of x seconds for this to complete the binding
                    return unbindFuture.get(acceptorTimeout, TimeUnit.SECONDS);
                }
            } catch (TimeoutException tex) {
                logger.warn("Binding removal timed-out on {}", addr, tex);
            } catch (Throwable t) {
                // if aggressive acceptor handling is enabled, reset the acceptor
                if (aggressiveAcceptorReset && acceptor != null) {
                    synchronized (acceptor) {
                        logger.warn("Acceptor will be reset with extreme predudice, due to remove binding failed on {}", addr, t);
                        acceptor.dispose(false);
                        acceptor = null;
                    }
                } else {
                    logger.warn("Remove binding failed on {}", addr, t);
                }
            }
        }
        return false;
    }

    /**
     * Ports and addresses are unbound (stop listening).
     */
    public void stop() throws Exception {
        if (executor != null && !executor.isShutdown()) {
            executor.shutdown();
        }
        if (acceptor != null) {
            synchronized (acceptor) {
                acceptor.unbind();
                acceptor.dispose(true);
                logger.info("Disposed acceptor: {}", id);
            }
        }
    }

    /**
     * Review all ports in-use for a conflict with the given port.
     * 
     * @param port
     * @return true if already bound and false otherwise
     */
    public static boolean isBound(int port) {
        //logger.info("isBound: {}", port);
        return boundPorts.contains(port);
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

    /**
     * Returns whether or not a shared acceptor is in-use.
     * 
     * @return true if shared and false otherwise
     */
    public static boolean isSharedAcceptor() {
        return sharedAcceptor;
    }

}
