/* See LICENSE.md for license information */
package org.ice4j.socket;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.channels.DatagramChannel;

import org.ice4j.TransportAddress;

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
    }

    /**
     * Constructor.
     *
     * @param address TransportAddress
     * @throws IOException 
     */
    public IceUdpSocketWrapper(TransportAddress address) throws IOException {
        super(DatagramChannel.open());
        ((DatagramChannel) channel).socket().bind(address);
    }

    /**
     * Constructor.
     *
     * @param address InetAddress
     * @param port
     * @throws IOException 
     */
    public IceUdpSocketWrapper(InetAddress address, int port) throws IOException {
        super(DatagramChannel.open());
        ((DatagramChannel) channel).socket().bind(new InetSocketAddress(address, port));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void send(DatagramPacket p) throws IOException {
        ((DatagramChannel) channel).socket().send(p);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void receive(DatagramPacket p) throws IOException {
        ((DatagramChannel) channel).socket().receive(p);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public InetAddress getLocalAddress() {
        return ((DatagramChannel) channel).socket().getLocalAddress();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getLocalPort() {
        return ((DatagramChannel) channel).socket().getLocalPort();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public SocketAddress getLocalSocketAddress() {
        try {
            return ((DatagramChannel) channel).getLocalAddress();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

}
