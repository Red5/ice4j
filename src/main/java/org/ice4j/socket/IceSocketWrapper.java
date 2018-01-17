/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal. Copyright @ 2015 Atlassian Pty Ltd Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or
 * agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under the License.
 */
package org.ice4j.socket;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SocketChannel;

import org.ice4j.Transport;
import org.ice4j.TransportAddress;

/**
 * Abstract socket wrapper that define a socket that could be UDP, TCP...
 *
 * @author Sebastien Vincent
 * @author Paul Gregoire
 */
public abstract class IceSocketWrapper {

    /**
     * NIO channel for this wrapper; will be one of type DatagramChannel for UDP or SocketChannel for TCP.
     */
    protected final SelectableChannel channel;

    protected TransportAddress transportAddress;

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
        if (transportAddress == null && channel != null) {
            if (channel instanceof DatagramChannel) {
                DatagramSocket socket = ((DatagramChannel) channel).socket();
                transportAddress = new TransportAddress(socket.getInetAddress(), socket.getLocalPort(), Transport.UDP);
            } else {
                Socket socket = ((SocketChannel) channel).socket();
                transportAddress = new TransportAddress(socket.getInetAddress(), socket.getLocalPort(), Transport.TCP);
            }
        }
        return transportAddress;
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
