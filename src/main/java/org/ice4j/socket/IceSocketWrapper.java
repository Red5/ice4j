/* See LICENSE.md for license information */
package org.ice4j.socket;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SocketChannel;
import java.util.LinkedList;

import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.socket.filter.DatagramPacketFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Abstract socket wrapper that define a socket that could be UDP, TCP...
 *
 * @author Sebastien Vincent
 * @author Paul Gregoire
 */
public abstract class IceSocketWrapper {

    protected final Logger logger = LoggerFactory.getLogger(IceSocketWrapper.class);

    /**
     * NIO channel for this wrapper; will be one of type DatagramChannel for UDP or SocketChannel for TCP.
     */
    protected final SelectableChannel channel;

    protected TransportAddress transportAddress;

    protected TransportAddress remoteTransportAddress;

    /**
     * Packet filters.
     */
    protected LinkedList<DatagramPacketFilter> filters = new LinkedList<>();

    /**
     * Socket timeout.
     */
    protected int soTimeout;

    public IceSocketWrapper(SelectableChannel channel) {
        this.channel = channel;
    }

    /**
     * Sends a DatagramPacket from this socket. It is a utility method to provide a common way to send for both
     * UDP and TCP socket. If the underlying socket is a TCP one, it is still possible to get the OutputStream and do stuff with it.
     *
     * @param p DatagramPacket to send
     * @throws IOException if something goes wrong
     */
    public abstract void send(DatagramPacket p) throws IOException;

    /**
     * Receives a DatagramPacket from this socket. It is a utility method to provide a common way to receive for both
     * UDP and TCP socket. If the underlying socket is a TCP one, it is still possible to get the InputStream and do stuff with it.
     *
     * @param p DatagramPacket
     * @throws IOException if something goes wrong
     */
    public abstract void receive(DatagramPacket p) throws IOException;

    /**
     * Adds a filter to manipulate data on the wrapped socket.
     * 
     * @param datagramPacketFilter
     * @return true if added and false otherwise
     */
    public boolean addFilter(DatagramPacketFilter datagramPacketFilter) {
        return filters.offer(datagramPacketFilter);
    }

    /**
     * Removes a filter matching the given class if one exists.
     * 
     * @param filterClass
     * @return true if removed and false otherwise
     */
    public boolean removeFilter(Class<DatagramPacketFilter> filterClass) {
        boolean removed = false;
        for (DatagramPacketFilter filter : filters) {
            if (filterClass.isInstance(filter)) {
                removed = filters.remove(filter);
                break;
            }
        }
        return removed;
    }

    /**
     * Closes the channel.
     */
    public void close() {
        try {
            channel.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Get local address.
     *
     * @return local address
     */
    public abstract InetAddress getLocalAddress();

    /**
     * Get local port.
     *
     * @return local port
     */
    public abstract int getLocalPort();

    /**
     * Get socket address.
     *
     * @return socket address
     */
    public abstract SocketAddress getLocalSocketAddress();

    /**
     * Returns a SelectableChannel if the delegate has one, null otherwise.
     *
     * @return SelectableChannel if one exists or null otherwise
     */
    public SelectableChannel getChannel() {
        return channel;
    }

    /**
     * Returns TransportAddress for the wrapped socket implementation.
     * 
     * @return transport address
     */
    public TransportAddress getTransportAddress() {
        logger.debug("getTransportAddress: {} channel: {}", transportAddress, channel);
        if (transportAddress == null && channel != null) {
            if (channel instanceof DatagramChannel) {
                //DatagramSocket socket = ((DatagramChannel) channel).socket();
                try {
                    transportAddress = new TransportAddress((InetSocketAddress) ((DatagramChannel) channel).getLocalAddress(), Transport.UDP);
                } catch (IOException e) {
                    logger.warn("Exception configuring transport address", e);
                }
            } else {
                //Socket socket = ((SocketChannel) channel).socket();
                try {
                    transportAddress = new TransportAddress((InetSocketAddress) ((SocketChannel) channel).getLocalAddress(), Transport.TCP);
                } catch (IOException e) {
                    logger.warn("Exception configuring transport address", e);
                }
            }
        }
        return transportAddress;
    }

    /**
     * Sets the TransportAddress of the remote end-point.
     * 
     * @param remoteAddress address
     */
    public void setRemoteTransportAddress(TransportAddress remoteAddress) {
        this.remoteTransportAddress = remoteAddress;
    }

    public TransportAddress getRemoteTransportAddress() {
        return remoteTransportAddress;
    }

    /**
     * Sets the socket timeout.
     */
    public void setSoTimeout(int timeout) throws SocketException {
        soTimeout = timeout;
    }

    /**
     * Returns whether or not this is a TCP wrapper, based on the instance type.
     * 
     * @return true if TCP and false otherwise
     */
    public boolean isTCP() {
        return (this instanceof IceTcpSocketWrapper);
    }

    /**
     * Returns whether or not this is a UDP wrapper, based on the instance type.
     * 
     * @return true if UDP and false otherwise
     */
    public boolean isUDP() {
        return (this instanceof IceUdpSocketWrapper);
    }

    /**
     * Builder for immutable IceUdpSocketWrapper instance.
     * 
     * @param datagramChannel
     * @return IceUdpSocketWrapper
     * @throws IOException
     */
    public final static IceSocketWrapper build(DatagramChannel datagramChannel) throws IOException {
        return new IceUdpSocketWrapper(datagramChannel);
    }

    /**
     * Builder for immutable IceTcpSocketWrapper instance.
     * 
     * @param socketChannel
     * @return IceTcpSocketWrapper
     * @throws IOException
     */
    public final static IceSocketWrapper build(SocketChannel socketChannel) throws IOException {
        return new IceTcpSocketWrapper(socketChannel);
    }

}
