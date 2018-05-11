package org.ice4j.ice.nio;

import java.net.SocketAddress;

import org.apache.mina.core.service.IoAcceptor;
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
        TRANSPORT, CONNECTION, STUN_STACK, DECODER, ENCODER, DECODER_STATE_KEY, CANDIDATE;
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
                acceptor.unbind(addr);
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

}
