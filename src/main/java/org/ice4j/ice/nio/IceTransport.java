package org.ice4j.ice.nio;

import java.io.IOException;
import java.net.SocketAddress;

import org.apache.mina.core.filterchain.DefaultIoFilterChainBuilder;
import org.apache.mina.core.service.IoHandlerAdapter;
import org.apache.mina.filter.codec.ProtocolCodecFilter;
import org.apache.mina.transport.socket.SocketAcceptor;
import org.apache.mina.transport.socket.SocketSessionConfig;
import org.apache.mina.transport.socket.nio.NioSocketAcceptor;
import org.ice4j.StackProperties;
import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.socket.IceSocketWrapper;
import org.ice4j.stack.StunStack;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * IceTransport
 * 
 * 
 * @author Paul Gregoire
 */
public class IceTransport {

    private static final Logger logger = LoggerFactory.getLogger(IceTransport.class);

    private final static int BUFFER_SIZE_DEFAULT = 65535;

    private static IceTransport instance;

    private int receiveBufferSize = StackProperties.getInt("SO_RCVBUF", BUFFER_SIZE_DEFAULT);

    private int sendBufferSize = StackProperties.getInt("SO_SNDBUF", BUFFER_SIZE_DEFAULT);

    private int ioThreads = 16;

    private SocketAcceptor acceptor;

    // constants for the session map
    public enum Ice {
        CONNECTION, STUN_STACK, DECODER, ENCODER;
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
    private IceTransport() {
        // create the nio acceptor
        acceptor = new NioSocketAcceptor(ioThreads);
        // configure the acceptor
        SocketSessionConfig sessionConf = acceptor.getSessionConfig();
        sessionConf.setReuseAddress(true);
        sessionConf.setTcpNoDelay(true);
        sessionConf.setSendBufferSize(sendBufferSize);
        sessionConf.setReadBufferSize(receiveBufferSize);
        // close sessions when the acceptor is stopped
        acceptor.setCloseOnDeactivation(true);
        // requested maximum length of the queue of incoming connections
        acceptor.setBacklog(64);
        acceptor.setReuseAddress(true);
        acceptor.setHandler(new IceHandler());
        // get the filter chain and add our codec factory
        DefaultIoFilterChainBuilder chain = acceptor.getFilterChain();
        chain.addLast("protocol", new ProtocolCodecFilter(new IceCodecFactory()));
        logger.info("Started socket transport");
        if (logger.isDebugEnabled()) {
            logger.debug("Acceptor sizes - send: {} recv: {}", sessionConf.getSendBufferSize(), sessionConf.getReadBufferSize());
        }
    }

    /**
     * Returns a static instance of this transport.
     * 
     * @return IceTransport
     */
    public static IceTransport getInstance() {
        if (instance == null) {
            instance = new IceTransport();
        }
        return instance;
    }

    /**
     * Adds a socket binding to the acceptor.
     * 
     * @param addr
     * @return true if successful and false otherwise
     */
    public boolean addBinding(SocketAddress addr) {
        try {
            acceptor.bind(addr);
            return true;
        } catch (IOException e) {
            logger.warn("Add binding failed on {}", addr, e);
        }
        return false;
    }

    /**
     * Adds an ice socket and stun stack to the acceptor handler to await session creation.
     * 
     * @param stunStack
     * @param iceSocket
     * @return true if successful and false otherwise
     */
    public boolean addBinding(StunStack stunStack, IceSocketWrapper iceSocket) {
        boolean result = false;
        // add the stack and wrapper to a map which will hold them until an associated session is opened
        // when opened, the stack and wrapper will be added to the session as attributes
        ((IceHandler) acceptor.getHandler()).addStackAndSocket(stunStack, iceSocket);
        // get the local address
        TransportAddress localAddress = iceSocket.getTransportAddress();
        if (localAddress.getTransport() == Transport.UDP) {
            // attempt to add a binding to the server
            result = addBinding(localAddress);
            if (logger.isTraceEnabled()) {
                logger.trace("UDP binding added: {}", localAddress);
            }
        } else {
            // attempt to add a binding to the server
            result = addBinding(localAddress);
            if (logger.isTraceEnabled()) {
                logger.trace("TCP binding added: {}", localAddress);
            }
        }
        return result;
    }

    /**
     * Removes a socket binding from the acceptor.
     * 
     * @param addr
     * @return true if successful and false otherwise
     */
    public boolean removeBinding(SocketAddress addr) {
        try {
            acceptor.unbind(addr);
            return true;
        } catch (Exception e) {
            logger.warn("Remove binding failed on {}", addr, e);
        }
        return false;
    }

    /**
     * Ports and addresses are unbound (stop listening).
     */
    public void stop() throws Exception {
        logger.info("Stopped socket transport");
        acceptor.unbind();
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
     * @param ioThreads the ioThreads to set
     */
    public void setIoThreads(int ioThreads) {
        this.ioThreads = ioThreads;
    }

    /**
     * Set a new IoHandler to replace the existing IceHandler.
     * 
     * @param ioHandler
     */
    public void setIoHandler(IoHandlerAdapter ioHandler) {
        acceptor.setHandler(ioHandler);
    }

}
