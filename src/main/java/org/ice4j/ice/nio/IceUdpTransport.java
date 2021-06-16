package org.ice4j.ice.nio;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.ConcurrentMap;

import org.apache.mina.core.service.IoService;
import org.apache.mina.core.service.IoServiceListener;
import org.apache.mina.core.session.IdleStatus;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.core.session.IoSessionRecycler;
import org.apache.mina.transport.socket.DatagramSessionConfig;
import org.apache.mina.transport.socket.nio.IceDatagramAcceptor;
import org.ice4j.TransportAddress;
import org.ice4j.socket.IceSocketWrapper;
import org.ice4j.socket.IceUdpSocketWrapper;
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
    
    private static boolean isTrace = logger.isTraceEnabled();

    private static boolean isDebug = logger.isDebugEnabled();

    /**
     * Recycler's session map.
     */
    private ConcurrentMap<String, IoSession> sessions = new ConcurrentHashMap<>();
    
    // track sequence to ensure we don't nack those that are too old
    private ConcurrentLinkedDeque<ExpirableAddressEntry> recentBindingsQueue = new ConcurrentLinkedDeque<>();

    private IoSessionRecycler recycler = new IoSessionRecycler() {

        @Override
        public void put(IoSession session) {
            logger.trace("Adding session to recycler: {}", session);
            String key = generateKey(session);
            // to allow binding/storage or not
            boolean allowUse = true;
            // check for recent binding removals
            for (ExpirableAddressEntry expEntry : recentBindingsQueue) {
                // remove entries when they've expired as we roll through
                if (expEntry.isExpired()) {
                    // these also won't count as a match
                    recentBindingsQueue.remove(expEntry);
                    // continue on...
                    continue;
                }
                if (key.equals(expEntry.getAddressKey())) {
                    // we've match a recently unbound address, don't allow re-use quite so quickly
                    allowUse = false;
                    break;
                }
            }
            if (allowUse) {
                sessions.put(key, session);
                if (isTrace) {
                    logger.trace("Added session: {} {} to recycler", session.getId(), key);
                }
            } else {
                logger.debug("Failed to add session: {} {} to recycler, too soon", session.getId(), key);
            }
        }

        @Override
        public IoSession recycle(SocketAddress remoteAddress) {
            logger.trace("Recycle remote address: {}", remoteAddress);
            // recycler is locked by NioDatagramAcceptor.newSessionWithoutLock so we'll attempt to prevent deadlocking
            // by using our concurrent map from outside the recycler itself
            return getSessionByRemote(remoteAddress);
        }

        @Override
        public void remove(IoSession session) {
            logger.trace("Removing session from recycler: {}", session);
            String key = generateKey(session);
            // remove by key
            if (sessions.remove(key) != null) {
                // make an entry for the key we're removed
                recentBindingsQueue.add(new ExpirableAddressEntry(key));
                if (isTrace) {
                    logger.trace("Removed session: {} {} from recycler", session.getId(), key);
                }
            }
        }

        private String generateKey(IoSession session) {
            return String.format("%s@%s", session.getLocalAddress(), session.getRemoteAddress().toString());
        }

    };

    /**
     * Creates the i/o handler and nio acceptor; ports and addresses are bound.
     */
    private IceUdpTransport() {
        logger.info("id: {} shared: {} accept timeout: {}s idle timeout: {}s", id, sharedAcceptor, acceptorTimeout, timeout);
    }

    /**
     * Returns a static instance of this transport.
     * 
     * @param id transport / acceptor identifier
     * @return IceTransport
     */
    public static IceUdpTransport getInstance(String id) {
        IceUdpTransport instance = (IceUdpTransport) transports.get(id);
        // an id of "disconnected" is a special case where the socket is not associated with an IoSession
        if (instance == null || IceSocketWrapper.DISCONNECTED.equals(id)) {
            if (IceTransport.isSharedAcceptor()) {
                // loop through transport and if none are found for UDP, create a new one
                for (Entry<String, IceTransport> entry : transports.entrySet()) {
                    if (entry.getValue() instanceof IceUdpTransport) {
                        instance = (IceUdpTransport) entry.getValue();
                        break;
                    }
                }
                if (instance == null) {
                    instance = new IceUdpTransport();
                }
            } else {
                instance = new IceUdpTransport();
            }
        }
        // create an acceptor if none exists for the instance
        if (instance != null && instance.getAcceptor() == null) {
            instance.createAcceptor();
        }
        //logger.trace("Instance: {}", instance);
        return instance;
    }

    void createAcceptor() {
        if (acceptor == null) {
            // create the nio acceptor
            //acceptor = new NioDatagramAcceptor(); // mina base acceptor
            acceptor = new IceDatagramAcceptor();
            acceptor.addListener(new IoServiceListener() {

                @Override
                public void serviceActivated(IoService service) throws Exception {
                    //logger.debug("serviceActivated: {}", service);
                }

                @Override
                public void serviceIdle(IoService service, IdleStatus idleStatus) throws Exception {
                    //logger.debug("serviceIdle: {} status: {}", service, idleStatus);
                }

                @Override
                public void serviceDeactivated(IoService service) throws Exception {
                    //logger.debug("serviceDeactivated: {}", service);
                }

                @Override
                public void sessionCreated(IoSession session) throws Exception {
                    logger.debug("sessionCreated: {}", session);
                    //logger.debug("sessionCreated acceptor sessions: {}", acceptor.getManagedSessions());
                    session.setAttribute(IceTransport.Ice.UUID, id);
                }

                @Override
                public void sessionClosed(IoSession session) throws Exception {
                    logger.debug("sessionClosed: {}", session);
                    /*
                    if (session.containsAttribute(Ice.CONNECTION)) {
                        IceSocketWrapper wrapper = (IceSocketWrapper) session.getAttribute(Ice.CONNECTION);
                        logger.warn("Wrapper closed: {} id: {}", wrapper.isClosed(), wrapper.getId());
                        if (IceSocketWrapper.DISCONNECTED.equals(wrapper.getId()) && !wrapper.isClosed()) {
                            wrapper.close();
                        }
                    }
                    */
                }

                @Override
                public void sessionDestroyed(IoSession session) throws Exception {
                    logger.debug("sessionDestroyed: {}", session);
                    if (session.containsAttribute(IceTransport.Ice.UUID)) {
                        session.removeAttribute(IceTransport.Ice.UUID);
                    }
                }
            });
            // set the recycler
            ((IceDatagramAcceptor) acceptor).setSessionRecycler(recycler);
            // configure the acceptor
            DatagramSessionConfig sessionConf = ((IceDatagramAcceptor) acceptor).getSessionConfig();
            sessionConf.setReuseAddress(true);
            sessionConf.setSendBufferSize(sendBufferSize);
            sessionConf.setReadBufferSize(receiveBufferSize);
            sessionConf.setCloseOnPortUnreachable(true);
            // set an idle time in seconds or disable this via -1
            if (timeout > 0) {
                sessionConf.setIdleTime(IdleStatus.BOTH_IDLE, timeout);
            }
            // QoS
            sessionConf.setTrafficClass(trafficClass);
            // in server apps this can cause a memory leak so its off
            sessionConf.setUseReadOperation(false);
            // close sessions when the acceptor is stopped
            acceptor.setCloseOnDeactivation(true);
            // get the filter chain and add our codec factory
            acceptor.getFilterChain().addLast("protocol", iceCodecFilter);
            // add our handler
            acceptor.setHandler(iceHandler);
            logger.info("Started socket transport");
            if (isTrace) {
                logger.trace("Acceptor sizes - send: {} recv: {}", sessionConf.getSendBufferSize(), sessionConf.getReadBufferSize());
            }
            // add ourself to the transports map
            transports.put(id, this);
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
            logger.debug("Adding UDP binding: {}", addr);
            acceptor.bind(addr);
            // add the port to the bound list
            boundPorts.add(((InetSocketAddress) addr).getPort());
            logger.debug("UDP binding added: {}", addr);
            // no exceptions? return true for adding the binding
            return true;
        } catch (Throwable t) {
            logger.warn("Add binding failed on {}", addr, t);
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

    /**
     * Create a new IoSession for the given IceSocketWrapper and remote address.
     * 
     * @param socketWrapper
     * @param destAddress remote address
     * @return IoSession or null if creation fails
     */
    public IoSession createSession(IceUdpSocketWrapper socketWrapper, SocketAddress destAddress) {
        logger.debug("createSession - wrapper: {} remote: {}", socketWrapper, destAddress);
        IoSession session = null;
        if (acceptor != null) {
            // get the local address
            TransportAddress transportAddress = socketWrapper.getTransportAddress();
            // newSession calls recycler.recycle(destAddress)
            session = acceptor.newSession(destAddress, transportAddress);
            if (session != null) {
                // set the session directly
                socketWrapper.setSession(session);
            }
        } else {
            logger.debug("No UDP acceptor available");
        }
        return session;
    }

    /**
     * Returns the first session matching the given local address and port.
     * 
     * @param localAddress
     * @return IoSession if match is found and null if not found
     */
    public IoSession getSessionByLocal(TransportAddress localAddress) {
        if (isDebug) {
            logger.debug("Session values: {}", sessions.values());
        }
        for (IoSession sess : sessions.values()) {
            if (sess.getLocalAddress().equals(localAddress)) {
                logger.debug("Found match for {} = {}", localAddress, sess);
                return sess;
            }
        }
        return null;
    }

    /**
     * Returns a session for the requested remote address.
     * 
     * @param remoteAddress
     * @return IoSession matching remote address or null if its not found
     */
    public IoSession getSessionByRemote(SocketAddress remoteAddress) {
        IoSession sess = null;
        // this is expected to return an existing session for the remote address
        Optional<IoSession> opt = sessions.values().stream().filter(session -> session.getRemoteAddress().equals(remoteAddress)).findFirst();
        if (opt.isPresent()) {
            sess = opt.get();
            return sess;
        } else {
            if (isTrace) {
                logger.trace("Session not found in recycler for remote address: {}\n{}", remoteAddress, sessions.keySet());
            }
        }
        return sess;
    }

}
