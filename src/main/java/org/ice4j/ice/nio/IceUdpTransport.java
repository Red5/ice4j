package org.ice4j.ice.nio;

import java.io.IOException;
import java.net.SocketAddress;

import org.apache.mina.core.service.IoService;
import org.apache.mina.core.service.IoServiceListener;
import org.apache.mina.core.session.IdleStatus;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.transport.socket.DatagramSessionConfig;
import org.apache.mina.transport.socket.nio.NioDatagramAcceptor;
import org.ice4j.TransportAddress;
import org.ice4j.socket.IceSocketWrapper;
import org.ice4j.stack.StunStack;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * IceTransport for UDP connections.
 * 
 * @author Paul Gregoire
 */
public class IceUdpTransport extends IceTransport {

    private static final Logger logger = LoggerFactory.getLogger(IceUdpTransport.class);

    private static final IceUdpTransport instance = new IceUdpTransport();

    /**
     * Creates the i/o handler and nio acceptor; ports and addresses are bound.
     */
    private IceUdpTransport() {
        createAcceptor();
    }

    /**
     * Returns a static instance of this transport.
     * 
     * @return IceTransport
     */
    public static IceUdpTransport getInstance() {
        //logger.trace("Instance: {}", instance);
        if (instance.getAcceptor() == null) {
            instance.createAcceptor();
        }
        return instance;
    }

    synchronized void createAcceptor() {
        // create the nio acceptor
        acceptor = new NioDatagramAcceptor();
        acceptor.addListener(new IoServiceListener() {

            @Override
            public void serviceActivated(IoService service) throws Exception {
                logger.info("serviceActivated: {}", service);
            }

            @Override
            public void serviceIdle(IoService service, IdleStatus idleStatus) throws Exception {
                logger.info("serviceIdle: {} status: {}", service, idleStatus);
            }

            @Override
            public void serviceDeactivated(IoService service) throws Exception {
                logger.info("serviceDeactivated: {}", service);
            }

            @Override
            public void sessionCreated(IoSession session) throws Exception {
                logger.info("sessionCreated: {}", session);
                //logger.debug("Acceptor sessions: {}", acceptor.getManagedSessions());
            }

            @Override
            public void sessionClosed(IoSession session) throws Exception {
                logger.info("sessionClosed: {}", session);
            }

            @Override
            public void sessionDestroyed(IoSession session) throws Exception {
                logger.info("sessionDestroyed: {}", session);
            }
        });
        // configure the acceptor
        DatagramSessionConfig sessionConf = ((NioDatagramAcceptor) acceptor).getSessionConfig();
        sessionConf.setReuseAddress(true);
        sessionConf.setSendBufferSize(sendBufferSize);
        sessionConf.setReadBufferSize(receiveBufferSize);
        sessionConf.setCloseOnPortUnreachable(true);
        // set an idle time of 30s
        sessionConf.setIdleTime(IdleStatus.BOTH_IDLE, timeout);
        // QoS
        //sessionConf.setTrafficClass(trafficClass);
        // in server apps this can cause a memory leak so its off
        sessionConf.setUseReadOperation(false);
        // close sessions when the acceptor is stopped
        acceptor.setCloseOnDeactivation(true);
        // get the filter chain and add our codec factory
        acceptor.getFilterChain().addLast("protocol", iceCodecFilter);
        // add our handler
        acceptor.setHandler(iceHandler);
        logger.info("Started socket transport");
        if (logger.isTraceEnabled()) {
            logger.trace("Acceptor sizes - send: {} recv: {}", sessionConf.getSendBufferSize(), sessionConf.getReadBufferSize());
        }
    }

    /**
     * Adds a socket binding to the acceptor.
     * 
     * @param addr
     * @return true if successful and false otherwise
     */
    @Override
    public boolean addBinding(SocketAddress addr) {
        try {
            acceptor.bind(addr);
            //if (logger.isTraceEnabled()) {
                logger.debug("UDP binding added: {}", addr);
            //}
            return true;
        } catch (IOException e) {
            logger.warn("Add binding failed on {}", addr, e);
        }
        return false;
    }

    /** {@inheritDoc} */
    public boolean registerStackAndSocket(StunStack stunStack, IceSocketWrapper iceSocket) {
        logger.debug("registerStackAndSocket - stunStack: {} iceSocket: {}", stunStack, iceSocket);
        boolean result = false;
        // add the stack and wrapper to a map which will hold them until an associated session is opened
        // when opened, the stack and wrapper will be added to the session as attributes
        iceHandler.registerStackAndSocket(stunStack, iceSocket);
        // get the local address
        TransportAddress localAddress = iceSocket.getTransportAddress();
        // attempt to add a binding to the server
        result = addBinding(localAddress);
        return result;
    }

}
