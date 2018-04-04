/* See LICENSE.md for license information */
package org.ice4j.socket;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;

import javax.xml.bind.DatatypeConverter;

import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.ice.nio.NioServer;
import org.ice4j.ice.nio.NioServer.BindingEvent;
import org.ice4j.ice.nio.NioServer.Event;
import org.ice4j.socket.filter.DataFilter;
import org.ice4j.stack.RawMessage;

/**
 * UDP implementation of the IceSocketWrapper.
 *
 * @author Sebastien Vincent
 * @author Paul Gregoire
 */
public class IceUdpSocketWrapper extends IceSocketWrapper {

    /**
     * Constructor.
     *
     * @param datagramChannel
     */
    public IceUdpSocketWrapper(DatagramChannel datagramChannel) {
        super(datagramChannel);
        if (datagramChannel != null && datagramChannel.socket().isBound()) {
            try {
                transportAddress = new TransportAddress((InetSocketAddress) ((DatagramChannel) channel).getLocalAddress(), Transport.UDP);
            } catch (Exception e) {
                logger.warn("Exception configuring transport address", e);
            }
        } else {
            logger.debug("Datagram channel is not bound");
        }
        init();
    }

    /**
     * Constructor.
     *
     * @param address TransportAddress
     * @throws IOException 
     */
    public IceUdpSocketWrapper(TransportAddress address) throws IOException {
        super((DatagramChannel) null);
        transportAddress = address;
        init();
    }

    private void init() {
        // create an NioServer Adapter/Listener for events
        serverListener = new NioServer.Adapter(this) {

            @Override
            public boolean newBinding(BindingEvent evt) {
                if (logger.isDebugEnabled()) {
                    logger.debug("newBinding: {}", evt);
                }
                if (server == null) {
                    // get the server
                    server = evt.getNioServer();
                }
                if (channel == null) {
                    try {
                        // get the channel
                        DatagramChannel tmp = (DatagramChannel) evt.getSource();
                        //logger.debug("Binding: {} == {}", transportAddress, tmp.getLocalAddress());
                        if (transportAddress.equals(tmp.getLocalAddress())) {
                            //logger.debug("Setting channel since its null");
                            channel = tmp;
                            return true;
                        }
                    } catch (Exception e) {
                        logger.warn("Exception setting up channel", e);
                    }
                }
                return false;
            }

            @Override
            public boolean udpDataReceived(Event evt) {
                if (logger.isTraceEnabled()) {
                    //logger.trace("udpDataReceived: {}", evt);
                    logger.trace("udpDataReceived at {} for {} from {}", transportAddress, evt.getLocalSocketAddress(), evt.getRemoteSocketAddress());
                }
                // is the data for us?
                if (transportAddress.equals(evt.getLocalSocketAddress())) {
                    if (server == null) {
                        // get the server
                        server = evt.getNioServer();
                    }
                    if (channel == null) {
                        //logger.debug("Setting channel since its null");
                        channel = evt.getKey().channel();
                    }
                    // get the data
                    ByteBuffer recvBuf = evt.getInputBuffer();
                    if (logger.isTraceEnabled()) {
                        logger.trace("Recv bb: {} {}", recvBuf.position(), recvBuf.limit());
                    }
                    // pull the bytes out
                    byte[] buf = new byte[recvBuf.remaining()];
                    recvBuf.get(buf);
                    // clear the receive buffer
                    recvBuf.clear();
                    if (logger.isTraceEnabled()) {
                        logger.trace("Recv cleared bb: {} {} buf: {}", recvBuf.position(), recvBuf.limit(), DatatypeConverter.printHexBinary(buf));
                    }
                    // filter the data if filters exist
                    boolean reject = false;
                    for (DataFilter filter : filters) {
                        // most likely, we're only filtering on STUN messages here
                        if (filter.accept(buf)) {
                            logger.trace("Data accepted by: {}", filter.getClass().getName());
                        } else {
                            logger.trace("Data rejected by: {}", filter.getClass().getName());
                            reject = true;
                        }
                    }
                    // create raw message
                    InetSocketAddress fromAddr = (InetSocketAddress) evt.getRemoteSocketAddress();
                    RawMessage rawMessage = new RawMessage(buf, buf.length, new TransportAddress(fromAddr.getAddress(), fromAddr.getPort(), Transport.UDP), transportAddress);
                    // Non-rejects are expected to be stun and we'll process them, if its something else we'll route it to another queue
                    // for consuming by other interested parties
                    if (!reject) {
                        // add the message to the queue, which is shared with the Connector, etc...
                        messageQueue.add(rawMessage);
                    } else {
                        if (logger.isTraceEnabled()) {
                            logger.trace("RawMessage sequence number: {} length: {}", ((buf[2] & 0xFF) << 8 | (buf[3] & 0xFF)), buf.length);
                        }
                        //    logger.debug("Rejected: {}", DatatypeConverter.printHexBinary(buf));
                        rawMessageQueue.add(rawMessage);
                    }
                    return true;
                } else {
                    //logger.debug("Data is not for us");
                }
                return false;
            }

            @Override
            public boolean connectionClosed(Event evt) {
                // ensure the connection closed event is meant for us
                if (transportAddress.equals(evt.getLocalSocketAddress())) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("connectionClosed: {}", evt);
                    }
                    // remove the binding
                    evt.getNioServer().removeUdpBinding(transportAddress);
                    return true;
                }
                return false;
            }

        };
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void send(DatagramPacket p) throws IOException {
        if (logger.isDebugEnabled()) {
            logger.debug("send: {}", p);
        }
        // allow sending prior to a proper bind on the channel
        if (channel == null) {
            DatagramChannel tmp = DatagramChannel.open();
            //tmp.bind(transportAddress);
            tmp.socket().send(p);
            tmp.close();
        }
        if (channel != null) {
            ((DatagramChannel) channel).send(ByteBuffer.wrap(p.getData()), p.getSocketAddress());
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void receive(DatagramPacket p) throws IOException {
        if (logger.isDebugEnabled()) {
            logger.debug("receive: {}", p);
        }
        // add the message to the queue, which is shared with the Connector, etc...
        RawMessage rawMessage = new RawMessage(p.getData(), p.getData().length, (TransportAddress) p.getSocketAddress(), transportAddress);
        messageQueue.add(rawMessage);
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
        if (channel == null) {
            return transportAddress;
        } else {
            try {
                return ((DatagramChannel) channel).getLocalAddress();
            } catch (IOException e) {
                logger.warn("Exception getting socket address", e);
            }
        }
        return null;
    }

}
