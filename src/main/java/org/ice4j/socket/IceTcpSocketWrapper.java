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
import org.apache.mina.core.session.IdleStatus;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.transport.socket.SocketSessionConfig;
import org.apache.mina.transport.socket.nio.NioSocketAcceptor;
import org.apache.mina.transport.socket.nio.NioSocketConnector;
import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.ice.nio.IceHandler;
import org.ice4j.ice.nio.IceTcpTransport;
import org.ice4j.ice.nio.IceTransport;
import org.ice4j.stack.RawMessage;

/**
 * TCP implementation of the IceSocketWrapper.
 * 
 * @author Paul Gregoire
 */
public class IceTcpSocketWrapper extends IceSocketWrapper {

    /**
     * Constructor.
     *
     * @param session
     */
    public IceTcpSocketWrapper(IoSession session) {
        super(session);
        if (session != null) {
            try {
                transportAddress = new TransportAddress((InetSocketAddress) session.getLocalAddress(), Transport.TCP);
            } catch (Exception e) {
                logger.warn("Exception configuring transport address", e);
            }
        } else {
            logger.debug("Datagram session is not bound");
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
            if (logger.isTraceEnabled()) {
                logger.trace("send: {} to: {}", buf, destAddress);
            }
            WriteFuture writeFuture = null;
            try {
                IoSession sess = session.get();
                if (sess != null) {
                    writeFuture = sess.write(buf);
                    writeFuture.addListener(writeListener);
                } else {
                    logger.debug("No session, attempting connect from: {} to: {}", transportAddress, destAddress);
                    // if we're not bound, attempt to create a client session
                    try {
                        NioSocketConnector connector = new NioSocketConnector();
                        SocketSessionConfig config = connector.getSessionConfig();
                        config.setReuseAddress(true);
                        config.setTcpNoDelay(true);
                        // set an idle time of 30s (default)
                        config.setIdleTime(IdleStatus.BOTH_IDLE, IceTransport.getTimeout());
                        // QoS
                        //config.setTrafficClass(trafficClass);
                        // set connection timeout of x milliseconds
                        connector.setConnectTimeoutMillis(3000L);
                        // add the ice protocol encoder/decoder
                        connector.getFilterChain().addLast("protocol", IceTransport.getProtocolcodecfilter());
                        // re-use the io handler
                        IceHandler handler = IceTransport.getIceHandler();
                        // set the handler on the connector
                        connector.setHandler(handler);
                        // check for existing registration
                        if (handler.lookupBinding(transportAddress) == null) {
                            // add this socket for attachment to the session upon opening
                            handler.registerStackAndSocket(null, this);
                        }
                        // connect it
                        ConnectFuture future = connector.connect(destAddress, transportAddress);
                        future.addListener(connectListener);
                    } catch (Throwable t) {
                        logger.warn("Exception creating new session using connector for {}, an attempt on the acceptor will be made if it exists", transportAddress, t);
                        // look for an existing acceptor
                        NioSocketAcceptor acceptor = (NioSocketAcceptor) IceTcpTransport.getInstance(getId()).getAcceptor();
                        if (acceptor != null) {
                            try {
                                acceptor.bind(transportAddress);
                            } catch (Exception e) {
                                logger.warn("Exception binding for new session using acceptor for {}", transportAddress, e);
                            }
                        } else {
                            logger.debug("No existing TCP acceptor available");
                        }
                    }
                    // wait up-to x milliseconds for a connection to be established
                    if (connectLatch.await(500L, TimeUnit.MILLISECONDS)) {
                        // attempt to get a newly added session from connect process
                        sess = session.get();
                        if (sess != null) {
                            writeFuture = sess.write(buf);
                            writeFuture.addListener(writeListener);
                        } else {
                            logger.warn("Send failed on session creation");
                        }
                    }
                }
            } catch (Throwable t) {
                logger.warn("Exception acquiring send lock", t);
            } finally {
                if (writeFuture != null) {
                    writeFuture.removeListener(writeListener);
                }
            }
        }
    }

    /** {@inheritDoc} */
    @Override
    public void send(DatagramPacket p) throws IOException {
        //if (logger.isTraceEnabled()) {
        //    logger.trace("send: {}", p);
        //}
        int len = p.getLength();
        int off = p.getOffset();
        IoBuffer data = IoBuffer.allocate(len + 2);
        data.put((byte) ((len >> 8) & 0xff));
        data.put((byte) (len & 0xff));
        data.put(p.getData(), off, len);
        data.flip();
        send(data, p.getSocketAddress());
    }

    /** {@inheritDoc} */
    @Override
    public void receive(DatagramPacket p) throws IOException {
        RawMessage message = rawMessageQueue.poll();
        if (message != null) {
            p.setData(message.getBytes(), 0, message.getMessageLength());
            p.setSocketAddress(message.getRemoteAddress());
        }
    }

    /** {@inheritDoc} */
    @Override
    public RawMessage read() {
        return rawMessageQueue.poll();
    }

    /** {@inheritDoc} */
    @Override
    public InetAddress getLocalAddress() {
        return transportAddress.getAddress();
    }

    /** {@inheritDoc} */
    @Override
    public int getLocalPort() {
        return transportAddress.getPort();
    }

    @Override
    public String toString() {
        return "IceTcpSocketWrapper [transportAddress=" + transportAddress + ", session=" + session + "]";
    }

}
