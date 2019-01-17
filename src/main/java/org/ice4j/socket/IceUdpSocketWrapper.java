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
import org.ice4j.TransportAddress;
import org.ice4j.ice.nio.IceDecoder;
import org.ice4j.ice.nio.IceUdpTransport;
import org.ice4j.stack.RawMessage;

/**
 * UDP implementation of the IceSocketWrapper.
 *
 * @author Paul Gregoire
 */
public class IceUdpSocketWrapper extends IceSocketWrapper {

    /**
     * Constructor.
     */
    public IceUdpSocketWrapper() {
    }

    /**
     * Constructor.
     *
     * @param address TransportAddress
     * @throws IOException 
     */
    public IceUdpSocketWrapper(TransportAddress address) throws IOException {
        logger.debug("New wrapper for {}", address);
        transportAddress = address;
    }

    /** {@inheritDoc} */
    @SuppressWarnings("static-access")
    @Override
    public void send(IoBuffer buf, SocketAddress destAddress) throws IOException {
        if (isClosed()) {
            logger.debug("Connection is closed");
            throw new ClosedChannelException();
        } else {
            if (logger.isTraceEnabled()) {
                logger.trace("send: {} bytes to: {}", buf.remaining(), destAddress);
            }
            // write future for ensuring write/send
            WriteFuture writeFuture = null;
            try {
                // if no session is set, we're likely in the negotiation phase
                IoSession sess = getSession();
                if (sess == null) {
                    // attempt to pull the session from the transport
                    IceUdpTransport transport = IceUdpTransport.getInstance(getId());
                    // get session matching the remote address
                    sess = transport.getSessionByRemote(destAddress);
                    // if theres no registered session pointing to the destination, create one
                    if (sess == null) {
                        try {
                            // if the ports not already bound, bind it
                            boolean portBound = transport.isBound(transportAddress.getPort());
                            logger.debug("Port bound: {}", portBound);
                            if (portBound) {
                                // if the port is already bound but no session is set as of yet; look up a usable session
                                // in transport vs making a new one to prevent dupes with the same end points.
                                logger.debug("No session, searching transport for: {} to: {}", transportAddress, destAddress);
                                sess = transport.getSessionByLocal(transportAddress);
                            } else {
                                // bind it
                                transport.addBinding(transportAddress);
                            }
                            // if the session wasn't found elsewhere, create one
                            if (sess == null) {
                                // verify that the address can be reached first
                                if (InetAddress.getByName(((InetSocketAddress) destAddress).getHostString()).isReachable(500)) {
                                    logger.debug("No session, attempting connect from: {} to: {}", transportAddress, destAddress);
                                    // attempt to create a server session, if it fails the local address isn't bound
                                    sess = transport.createSession(this, destAddress);
                                } else {
                                    logger.warn("Destination address: {} not reachable from: {}", destAddress, transportAddress);
                                }
                            }
                        } catch (Exception e) {
                            logger.warn("Exception getting session for: {}", transportAddress, e);
                        }
                    }
                }
                // if we're not relaying, proceed with normal flow
                if (relayedCandidateConnection == null || IceDecoder.isTurnMethod(buf.array())) {
                    // ensure that the destination matches the session remote
                    if (sess != null) {
                        //if (logger.isTraceEnabled()) {
                        //    logger.trace("Destination match for send: {} -> {}", destAddress, sess.getRemoteAddress());
                        //}
                        if (destAddress.equals(sess.getRemoteAddress())) {
                            writeFuture = sess.write(buf, destAddress);
                            writeFuture.addListener(writeListener);
                        }
                    } else {
                        logger.warn("Session established, skipping write to: {}", destAddress);
                    }
                } else {
                    if (logger.isTraceEnabled()) {
                        logger.trace("Relayed send: {} to: {}", buf, destAddress);
                    }
                    relayedCandidateConnection.send(buf, destAddress);
                }
            } catch (Throwable t) {
                logger.warn("Exception attempting to send", t);
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
        return "IceUdpSocketWrapper [transportAddress=" + transportAddress + ", session=" + getSession() + "]";
    }

}
