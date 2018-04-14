/* See LICENSE.md for license information */
package org.ice4j.socket;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.future.ConnectFuture;
import org.apache.mina.core.future.IoFutureListener;
import org.apache.mina.core.service.IoHandler;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.ProtocolCodecFilter;
import org.apache.mina.transport.socket.nio.NioDatagramConnector;
import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.ice.nio.IceCodecFactory;
import org.ice4j.ice.nio.IceHandler;
import org.ice4j.ice.nio.IceUdpTransport;

/**
 * UDP implementation of the IceSocketWrapper.
 *
 * @author Paul Gregoire
 */
public class IceUdpSocketWrapper extends IceSocketWrapper {

    private Semaphore lock = new Semaphore(1, true);

    /**
     * Constructor.
     *
     * @param session
     */
    public IceUdpSocketWrapper(IoSession session) {
        super(session);
        if (session != null) {
            try {
                transportAddress = new TransportAddress((InetSocketAddress) session.getLocalAddress(), Transport.UDP);
            } catch (Exception e) {
                logger.warn("Exception configuring transport address", e);
            }
        } else {
            logger.debug("Datagram channel is not bound");
        }
    }

    /**
     * Constructor.
     *
     * @param address TransportAddress
     * @throws IOException 
     */
    public IceUdpSocketWrapper(TransportAddress address) throws IOException {
        super((IoSession) null);
        transportAddress = address;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void send(DatagramPacket p) throws IOException {
        if (logger.isDebugEnabled()) {
            logger.debug("send: {}", p);
        }
        try {
            // enforce fairness lock
            if (lock.tryAcquire(0, TimeUnit.SECONDS)) {
                if (session != null) {
                    session.write(IoBuffer.wrap(p.getData()), p.getSocketAddress());
                } else {
                    logger.debug("No session, attempting connect: {}", transportAddress);
                    NioDatagramConnector connector = new NioDatagramConnector();
                    // re-use the io handler
                    IoHandler handler = IceUdpTransport.getInstance().getIoHandler();
                    // set the handler on the connector
                    connector.setHandler(handler);
                    // add this socket for attachment to the session upon opening
                    ((IceHandler) handler).addStackAndSocket(null, this);
                    // add the ice protocol encoder/decoder
                    connector.getFilterChain().addLast("protocol", new ProtocolCodecFilter(new IceCodecFactory()));
                    // connect it
                    ConnectFuture future = connector.connect(p.getSocketAddress(), transportAddress);
                    future.addListener(new IoFutureListener<ConnectFuture>() {

                        @Override
                        public void operationComplete(ConnectFuture future) {
                            if (!future.isConnected()) {
                                logger.warn("Connect failed");
                            }
                        }

                    });
                    future.awaitUninterruptibly(3000L);
                    logger.trace("Future await returned");
                    if (session != null) {
                        session.write(IoBuffer.wrap(p.getData()), p.getSocketAddress());
                    } else {
                        logger.warn("Send failed on session creation");
                    }
                }
                lock.release();
            }
        } catch (InterruptedException e) {
            logger.warn("Exception acquiring send lock", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public InetAddress getLocalAddress() {
        return transportAddress.getAddress();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getLocalPort() {
        return transportAddress.getPort();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public SocketAddress getLocalSocketAddress() {
        if (session == null) {
            return transportAddress;
        }
        return session.getLocalAddress();
    }

}
