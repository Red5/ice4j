/* See LICENSE.md for license information */
package org.ice4j.socket;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.channels.ClosedChannelException;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.future.WriteFuture;
import org.apache.mina.core.session.IoSession;
import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.ice.nio.IceDecoder;
import org.ice4j.stack.RawMessage;

/**
 * TCP implementation of the IceSocketWrapper.
 * 
 * @author Paul Gregoire
 */
public class IceTcpSocketWrapper extends IceSocketWrapper {

    /**
     * Constructor.
     */
    public IceTcpSocketWrapper() {
    }

    /**
     * Constructor.
     *
     * @param address TransportAddress
     * @throws IOException 
     */
    public IceTcpSocketWrapper(TransportAddress address) throws IOException {
        transportAddress = address;
    }

    /** {@inheritDoc} */
    /*
    @SuppressWarnings("static-access")
    @Override
    public void newSession(SocketAddress destAddress) {
        logger.debug("newSession: {}", destAddress);
        // look for an existing acceptor
        IceTcpTransport transport = IceTcpTransport.getInstance(getId());
        NioSocketAcceptor acceptor = (NioSocketAcceptor) transport.getAcceptor();
        if (acceptor != null) {
            try {
                if (!transport.isBound(transportAddress.getPort())) {
                    transport.addBinding(transportAddress);
                }
                // if we're not bound, attempt to create a client session
                NioSocketConnector connector = new NioSocketConnector();
                SocketSessionConfig config = connector.getSessionConfig();
                config.setReuseAddress(true);
                config.setTcpNoDelay(true);
                // set an idle time of 30s (default)
                config.setIdleTime(IdleStatus.BOTH_IDLE, IceTransport.getTimeout());
                // QoS
                config.setTrafficClass(IceTransport.trafficClass);
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
                logger.warn("Exception creating new session using acceptor for {}, a direct acceptor binding will be attempted", transportAddress, t);
                try {
                    acceptor.bind(transportAddress);
                } catch (Exception e) {
                    logger.warn("Exception binding for new session using acceptor for {}", transportAddress, e);
                }
            }
        } else {
            logger.debug("No existing TCP acceptor available");
        }
    }
    */

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
                // if we're not relaying, proceed with normal flow
                if (relayedCandidateConnection == null || IceDecoder.isTurnMethod(buf.array())) {
                    IoSession sess = getSession();
                    if (sess != null) {
                        // ensure that the destination matches the session remote
                        if (destAddress.equals(sess.getRemoteAddress())) {
                            writeFuture = sess.write(pad(buf));
                            writeFuture.addListener(writeListener);
                        } else {
                            // if the destination doesnt match, this isn't the right ice socket
                            logger.debug("Destination {} doesnt match remote: {}", destAddress, sess.getRemoteAddress());
                            throw new IOException(String.format("Session not available for destination: %s", destAddress.toString()));
                        }
                    } else {
                        logger.debug("No session for: {} to: {}; closing? {}", transportAddress, destAddress, closed);
                        /*
                         * logger.debug("No session, attempting bind from: {} to: {}", transportAddress, destAddress); // look for an existing acceptor IceTcpTransport transport =
                         * IceTcpTransport.getInstance(getId()); if (!transport.isBound(transportAddress.getPort())) { transport.addBinding(transportAddress); } // attempt to get a
                         * new session post binding process sess = getSession(); if (sess != null) { writeFuture = sess.write(pad(buf)); writeFuture.addListener(writeListener); }
                         * else { logger.warn("Send failed, no session"); }
                         */
                    }
                } else {
                    if (logger.isTraceEnabled()) {
                        logger.trace("Relayed send: {} to: {}", buf, destAddress);
                    }
                    try {
                        relayedCandidateConnection.send(buf, destAddress);
                    } catch (Throwable t) {
                        logger.warn("Exception attempting to relay", t);
                    }
                }
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
        send(IoBuffer.wrap(p.getData(), p.getOffset(), p.getLength()), p.getSocketAddress());
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

    /**
     * Pad the data for TCP per RFC 4571.
     * 
     * @param buf non-padded source data
     * @return padded data with length
     */
    private IoBuffer pad(IoBuffer buf) {
        // pad the buffer for tcp transmission
        int len = buf.limit();
        IoBuffer data = IoBuffer.allocate(len + 2);
        data.put((byte) ((len >> 8) & 0xff));
        data.put((byte) (len & 0xff));
        data.put(buf);
        data.flip();
        return data;
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

    /** {@inheritDoc} */
    @Override
    public void setSession(IoSession newSession) {
        super.setSession(newSession);
        // update the remote address with the one from the current session
        if ("dummy".equals(newSession.getTransportMetadata().getName())) {
            remoteTransportAddress = null;
        } else {
            remoteTransportAddress = new TransportAddress((InetSocketAddress) newSession.getRemoteAddress(), Transport.TCP);
        }
    }

    @Override
    public String toString() {
        return "IceTcpSocketWrapper [transportAddress=" + transportAddress + ", session=" + getSession() + "]";
    }

}
