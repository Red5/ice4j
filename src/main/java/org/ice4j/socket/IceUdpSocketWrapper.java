/* See LICENSE.md for license information */
package org.ice4j.socket;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;

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
        // create an NioServer Adapter/Listener for events
        serverListener = new NioServer.Adapter() {

            @Override
            public void newBinding(BindingEvent evt) {
                if (logger.isDebugEnabled()) {
                    logger.debug("newBinding: {}", evt);
                }
                if (channel == null) {
                    try {
                        DatagramChannel tmp = (DatagramChannel) evt.getSource();
                        //logger.debug("Binding: {} == {}", transportAddress, tmp.getLocalAddress());
                        if (transportAddress.equals(tmp.getLocalAddress())) {
                            //logger.debug("Setting channel since its null");
                            channel = tmp;
                        }
                    } catch (Exception e) {
                        logger.warn("Exception setting up channel", e);
                    }
                }
            }

            @Override
            public void udpDataReceived(Event evt) {
                if (logger.isDebugEnabled()) {
                    //logger.debug("udpDataReceived: {}", evt);
                    logger.debug("udpDataReceived at {} for {} from {}", transportAddress, evt.getLocalSocketAddress(), evt.getRemoteSocketAddress());
                }
                // is the data for us?
                if (transportAddress.equals(evt.getLocalSocketAddress())) {
                    if (channel == null) {
                        logger.debug("Setting channel since its null");
                        channel = evt.getKey().channel();
                    }
                    // get the data
                    ByteBuffer recvBuf = evt.getInputBuffer();
                    byte[] buf = new byte[recvBuf.remaining()];
                    recvBuf.get(buf);
                    // filter the data if filters exist
                    boolean reject = false;
                    for (DataFilter filter : filters) {
                        if (filter.accept(buf)) {
                            logger.debug("Data accepted by: {}", filter.getClass().getName());
                        } else {
                            logger.warn("Data rejected by: {}", filter.getClass().getName());
                            reject = true;
                        }
                    }
                    if (!reject) {
                        // add the message to the queue, which is shared with the Connector, etc...
                        InetSocketAddress fromAddr = (InetSocketAddress) evt.getRemoteSocketAddress();
                        RawMessage rawMessage = new RawMessage(buf, buf.length, new TransportAddress(fromAddr.getAddress(), fromAddr.getPort(), Transport.UDP), transportAddress);
                        messageQueue.add(rawMessage);
                    }
                } else {
                    logger.debug("Data is not for us");
                }
            }

            @Override
            public void connectionClosed(Event evt) {
                if (logger.isDebugEnabled()) {
                    logger.debug("connectionClosed: {}", evt);
                }
                // remove the binding
                evt.getNioServer().removeUdpBinding(transportAddress);
                // remove listener
                evt.getNioServer().removeNioServerListener(serverListener);
            }

        };
    }

    /**
     * Constructor.
     *
     * @param address TransportAddress
     * @throws IOException 
     */
    public IceUdpSocketWrapper(TransportAddress address) throws IOException {
        this((DatagramChannel) null);
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
        // allow sending prior to a proper bind on the channel
        if (channel == null) {
            DatagramChannel tmp = DatagramChannel.open();
            //tmp.bind(transportAddress);
            tmp.socket().send(p);
            //tmp.close();
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
