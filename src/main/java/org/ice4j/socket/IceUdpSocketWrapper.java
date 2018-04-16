/* See LICENSE.md for license information */
package org.ice4j.socket;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.channels.ClosedChannelException;
import java.util.concurrent.TimeUnit;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.future.ConnectFuture;
import org.apache.mina.core.future.WriteFuture;
import org.apache.mina.core.service.IoHandler;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.ProtocolCodecFilter;
import org.apache.mina.transport.socket.DatagramSessionConfig;
import org.apache.mina.transport.socket.nio.NioDatagramAcceptor;
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

    /** {@inheritDoc} */
    @Override
    public void send(IoBuffer buf, SocketAddress destAddress) throws IOException {
        if (isClosed()) {
            logger.debug("Connection is closed");
            throw new ClosedChannelException();
        } else {
            //if (logger.isTraceEnabled()) {
            //    logger.trace("send: {}", buf);
            //}
            try {
                // enforce fairness lock
                if (lock.tryAcquire(0, TimeUnit.SECONDS)) {
                    if (session != null) {
                        WriteFuture writeFuture = session.write(buf, destAddress);
                        writeFuture.addListener(writeListener);
                    } else {
                        logger.debug("No session, attempting connect: {}", transportAddress);
                        boolean bound = false;
                        // look for an existing acceptor
                        NioDatagramAcceptor acceptor = (NioDatagramAcceptor) IceUdpTransport.getInstance().getAcceptor();
                        if (acceptor != null) {
                            try {
                                // attempt to create a server session, if it fails the local address isn't bound
                                IoSession session = acceptor.newSession(destAddress, transportAddress);
                                if (session != null) {
                                    // if no session is set back on this socket wrapper, we'll need to add it here
                                    bound = true;
                                }
                            } catch (IllegalStateException ise) {
                                logger.warn("Exception creating new session for {}", transportAddress, ise);
                            }
                        }
                        // if we're not bound, attempt to create a client session
                        if (!bound) {
                            NioDatagramConnector connector = new NioDatagramConnector();
                            DatagramSessionConfig config = connector.getSessionConfig();
                            config.setBroadcast(false);
                            config.setReuseAddress(true);
                            config.setCloseOnPortUnreachable(true);
                            // re-use the io handler
                            IoHandler handler = IceUdpTransport.getInstance().getIoHandler();
                            // set the handler on the connector
                            connector.setHandler(handler);
                            // add this socket for attachment to the session upon opening
                            ((IceHandler) handler).registerStackAndSocket(null, this);
                            // add the ice protocol encoder/decoder
                            connector.getFilterChain().addLast("protocol", new ProtocolCodecFilter(new IceCodecFactory()));
                            // connect it
                            ConnectFuture future = connector.connect(destAddress, transportAddress);
                            future.addListener(connectListener);
                            future.awaitUninterruptibly(500L);
                            //logger.trace("Future await returned");
                        }
                        if (session != null) {
                            WriteFuture writeFuture = session.write(buf, destAddress);
                            writeFuture.addListener(writeListener);
                        } else {
                            logger.warn("Send failed on session creation");
                        }
                    }
                    lock.release();
                }
            } catch (Throwable t) {
                logger.warn("Exception acquiring send lock", t);
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void send(DatagramPacket p) throws IOException {
        send(IoBuffer.wrap(p.getData()), p.getSocketAddress());
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

    @Override
    public String toString() {
        return "IceUdpSocketWrapper [transportAddress=" + transportAddress + ", session=" + session + "]";
    }

}
