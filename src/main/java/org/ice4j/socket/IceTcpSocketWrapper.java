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
import org.apache.mina.transport.socket.SocketSessionConfig;
import org.apache.mina.transport.socket.nio.NioSocketConnector;
import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.ice.nio.IceCodecFactory;
import org.ice4j.ice.nio.IceHandler;
import org.ice4j.ice.nio.IceUdpTransport;

/**
 * TCP implementation of the IceSocketWrapper.
 * 
 * @author Paul Gregoire
 */
public class IceTcpSocketWrapper extends IceSocketWrapper {

    /**
     * Constructor.
     *
     * @param delegate delegate Socket
     *
     * @throws IOException if something goes wrong during initialization
     */
    public IceTcpSocketWrapper(IoSession session) throws IOException {
        super(session);
        try {
            transportAddress = new TransportAddress((InetSocketAddress) session.getLocalAddress(), Transport.TCP);
        } catch (Exception e) {
            logger.warn("Exception configuring transport address", e);
        }
    }

    /**
     * Constructor.
     *
     * @param address TransportAddress
     * @throws IOException 
     */
    public IceTcpSocketWrapper(TransportAddress address) throws IOException {
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
            //if (logger.isDebugEnabled()) {
            //    logger.debug("send: {}", buf);
            //}
            try {
                // enforce fairness lock
                if (lock.tryAcquire(0, TimeUnit.SECONDS)) {
                    if (session != null) {
                        WriteFuture writeFuture = session.write(buf, destAddress);
                        writeFuture.addListener(writeListener);
                    } else {
                        logger.debug("No session, attempting connect: {}", transportAddress);
                        NioSocketConnector connector = new NioSocketConnector();
                        SocketSessionConfig config = connector.getSessionConfig();
                        config.setReuseAddress(true);
                        config.setTcpNoDelay(true);
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
                        logger.trace("Future await returned");
                        if (session != null) {
                            WriteFuture writeFuture = session.write(buf, destAddress);
                            writeFuture.addListener(writeListener);
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
    }

    /** {@inheritDoc} */
    @Override
    public void send(DatagramPacket p) throws IOException {
        int len = p.getLength();
        int off = p.getOffset();
        IoBuffer data = IoBuffer.allocate(len + 2);
        data.put((byte) ((len >> 8) & 0xff));
        data.put((byte) (len & 0xff));
        data.put(p.getData(), off, len);
        send(data, p.getSocketAddress());
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
        return "IceTcpSocketWrapper [transportAddress=" + transportAddress + ", session=" + session + "]";
    }

}
