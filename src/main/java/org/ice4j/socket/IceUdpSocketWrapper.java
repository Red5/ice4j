/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal. Copyright @ 2015 Atlassian Pty Ltd Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or
 * agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under the License.
 */
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
        ((DatagramChannel) channel).socket().bind(new InetSocketAddress(address.getHostAddress(), address.getPort()));
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
