/* See LICENSE.md for license information */
package org.ice4j.stack;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.SocketAddress;
import java.util.concurrent.LinkedBlockingDeque;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.future.ConnectFuture;
import org.apache.mina.core.future.IoFutureListener;
import org.apache.mina.core.service.IoAcceptor;
import org.apache.mina.core.service.IoHandlerAdapter;
import org.apache.mina.core.service.IoService;
import org.apache.mina.core.service.IoServiceListener;
import org.apache.mina.core.session.IdleStatus;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.transport.socket.DatagramSessionConfig;
import org.apache.mina.transport.socket.SocketSessionConfig;
import org.apache.mina.transport.socket.nio.NioDatagramAcceptor;
import org.apache.mina.transport.socket.nio.NioDatagramConnector;
import org.apache.mina.transport.socket.nio.NioSocketAcceptor;
import org.apache.mina.transport.socket.nio.NioSocketConnector;
import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DatagramCollector {

    private static final Logger logger = LoggerFactory.getLogger(DatagramCollector.class);

    Boolean lock = Boolean.TRUE;

    IoAcceptor acceptor;

    IoServiceListener ioListener = new IoServiceListener() {

        @Override
        public void serviceActivated(IoService service) throws Exception {
            logger.debug("serviceActivated: {}", service);
        }

        @Override
        public void serviceIdle(IoService service, IdleStatus idleStatus) throws Exception {
            logger.debug("serviceIdle: {} status: {}", service, idleStatus);
        }

        @Override
        public void serviceDeactivated(IoService service) throws Exception {
            logger.debug("serviceDeactivated: {}", service);
        }

        @Override
        public void sessionCreated(IoSession session) throws Exception {
            logger.debug("sessionCreated: {}", session);
            logger.debug("Acceptor sessions: {}", acceptor.getManagedSessions());
            setSession(session);
        }

        @Override
        public void sessionClosed(IoSession session) throws Exception {
            logger.debug("sessionClosed: {}", session);
            setSession(null);
        }

        @Override
        public void sessionDestroyed(IoSession session) throws Exception {
            logger.debug("sessionDestroyed: {}", session);
        }
    };

    IoHandlerAdapter ioHandler = new IoHandlerAdapter() {

        @Override
        public void sessionOpened(IoSession session) throws Exception {
            super.sessionOpened(session);
        }

        @Override
        public void messageReceived(IoSession session, Object message) throws Exception {
            if (message instanceof DatagramPacket) {
                deque.offer((DatagramPacket) message);
            } else if (message instanceof IoBuffer) {
                IoBuffer in = (IoBuffer) message;
                // TCP has a 2b prefix containing its size per RFC4571 formatted frame, UDP is simply the incoming data size so we start with that
                int frameLength = in.remaining();
                // if we're TCP (not UDP), grab the size and advance the position
                if (transportAddr.getTransport() != Transport.UDP) {
                    frameLength = ((in.get() & 0xFF) << 8) | (in.get() & 0xFF);
                }
                byte[] buf = new byte[frameLength];
                in.get(buf);
                DatagramPacket dgram = new DatagramPacket(buf, frameLength, session.getRemoteAddress());
                deque.offer(dgram);
            }
            synchronized (lock) {
                lock.notify();
            }
            super.messageReceived(session, message);
        }

    };

    IoFutureListener<ConnectFuture> connectListener = new IoFutureListener<ConnectFuture>() {

        @Override
        public void operationComplete(ConnectFuture future) {
            if (!future.isConnected()) {
                IoSession sess = future.getSession();
                logger.warn("Connect failed from: {} to: {}", sess.getLocalAddress(), sess.getRemoteAddress());
            } else {
                setSession(future.getSession());
            }
            synchronized (lock) {
                lock.notify();
            }
        }

    };

    LinkedBlockingDeque<DatagramPacket> deque = new LinkedBlockingDeque<>();

    TransportAddress transportAddr;

    IoSession session;

    public void startListening(TransportAddress transportAddr) throws Exception {
        this.transportAddr = transportAddr;
        // allow re-use
        if (acceptor == null) {
            if (transportAddr.getTransport() == Transport.UDP) {
                createUDPAcceptor();
            } else if (transportAddr.getTransport() == Transport.TCP) {
                createTCPAcceptor();
            } else {
                throw new Exception("Transport not enabled: " + transportAddr.getTransport());
            }
        } else {
            logger.debug("Acceptor already instanced");
        }
    }

    public void stopListening() {
        if (acceptor != null) {
            acceptor.unbind();
            //acceptor.dispose();
            acceptor = null;
        }
        if (session != null) {
            session.closeNow();
        }
        deque.clear();
        deque = null;
    }

    public void waitForPacket() {
        logger.debug("waitForPacket: {}", acceptor.getLocalAddress());
        if (deque.isEmpty()) {
            try {
                synchronized (lock) {
                    lock.wait(50);
                }
            } catch (InterruptedException e) {
                logger.warn("Exception on wait", e);
            }
        }
    }

    public DatagramPacket collectPacket() throws InterruptedException {
        //recycle
        DatagramPacket returnValue = deque.take(); // blocks
        return returnValue;
    }

    public void send(byte[] data, SocketAddress destination) throws IOException {
        if (session == null && acceptor != null) {
            // avoid address in-use ex
            acceptor.unbind();
            // attempt to connect
            logger.debug("Not connected, attempting connect");
            if (transportAddr.getTransport() == Transport.UDP) {
                createUDPConnector(destination);
            } else if (transportAddr.getTransport() == Transport.TCP) {
                createTCPConnector(destination);
            }
            // wait for a connection
            try {
                synchronized (lock) {
                    lock.wait(300);
                }
            } catch (InterruptedException e) {
                logger.warn("Exception on wait for connect", e);
            }
        }
        if (session != null) {
            IoBuffer out;
            if (transportAddr.getTransport() == Transport.UDP) {
                out = IoBuffer.wrap(data);
                logger.debug("Sending UDP: {}", out);
                session.write(out, destination);
            } else {
                out = IoBuffer.allocate(data.length + 2);
                out.put((byte) ((data.length >> 8) & 0xff));
                out.put((byte) (data.length & 0xff));
                out.put(data);
                out.flip();
                logger.debug("Sending TCP: {}", out);
                session.write(out);
            }
        } else {
            logger.warn("No connected session, cannot send");
        }
    }

    protected void setSession(IoSession session) {
        logger.debug("setSession: {}", session);
        this.session = session;
    }

    private void createTCPAcceptor() throws IOException {
        acceptor = new NioSocketAcceptor(1);
        acceptor.addListener(ioListener);
        // configure the acceptor
        SocketSessionConfig sessionConf = ((NioSocketAcceptor) acceptor).getSessionConfig();
        sessionConf.setReuseAddress(true);
        sessionConf.setTcpNoDelay(true);
        // close sessions when the acceptor is stopped
        acceptor.setCloseOnDeactivation(true);
        // requested maximum length of the queue of incoming connections
        ((NioSocketAcceptor) acceptor).setBacklog(4);
        ((NioSocketAcceptor) acceptor).setReuseAddress(true);
        // get the filter chain and add our codec factory
        //acceptor.getFilterChain().addLast("protocol", protocolCodecFilter);
        // add our handler
        acceptor.setHandler(ioHandler);
        // bind
        acceptor.bind(transportAddr);
    }

    private void createUDPAcceptor() throws IOException {
        acceptor = new NioDatagramAcceptor();
        acceptor.addListener(ioListener);
        // configure the acceptor
        DatagramSessionConfig sessionConf = ((NioDatagramAcceptor) acceptor).getSessionConfig();
        sessionConf.setReuseAddress(true);
        sessionConf.setCloseOnPortUnreachable(true);
        // in server apps this can cause a memory leak so its off
        sessionConf.setUseReadOperation(false);
        // close sessions when the acceptor is stopped
        acceptor.setCloseOnDeactivation(true);
        // get the filter chain and add our codec factory
        //acceptor.getFilterChain().addLast("protocol", protocolCodecFilter);
        // add our handler
        acceptor.setHandler(ioHandler);
        // bind
        acceptor.bind(transportAddr);
    }

    private void createTCPConnector(SocketAddress destination) throws IOException {
        NioSocketConnector connector = new NioSocketConnector();
        SocketSessionConfig config = connector.getSessionConfig();
        config.setReuseAddress(true);
        config.setTcpNoDelay(true);
        // set connection timeout of x seconds
        connector.setConnectTimeoutMillis(3000L);
        // set the handler on the connector
        connector.setHandler(ioHandler);
        // connect it
        ConnectFuture future = connector.connect(destination, transportAddr);
        future.addListener(connectListener);
    }

    private void createUDPConnector(SocketAddress destination) throws IOException {
        NioDatagramConnector connector = new NioDatagramConnector();
        DatagramSessionConfig config = connector.getSessionConfig();
        config.setBroadcast(false);
        config.setReuseAddress(true);
        config.setCloseOnPortUnreachable(true);
        // set connection timeout of x seconds
        connector.setConnectTimeoutMillis(3000L);
        // set the handler on the connector
        connector.setHandler(ioHandler);
        // connect it
        ConnectFuture future = connector.connect(destination, transportAddr);
        future.addListener(connectListener);
    }
}
