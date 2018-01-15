/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal. Copyright @ 2015 Atlassian Pty Ltd Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or
 * agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under the License.
 */
package org.ice4j.socket;

import java.io.*;
import java.net.*;
import java.nio.channels.DatagramChannel;

import org.ice4j.TransportAddress;

/**
 * UDP implementation of the <tt>IceSocketWrapper</tt>.
 *
 * @author Sebastien Vincent
 * @author Paul Gregoire
 */
public class IceUdpSocketWrapper extends IceSocketWrapper {
    /**
     * Delegate UDP <tt>DatagramChannel</tt>.
     */
    private final DatagramChannel channel;

    /**
     * Constructor.
     *
     * @param address <tt>TransportAddress</tt>
     * @throws IOException 
     */
    public IceUdpSocketWrapper(TransportAddress address) throws IOException {
        this.channel = DatagramChannel.open();
        this.channel.socket().bind(new InetSocketAddress(address.getHostAddress(), address.getPort()));
    }

    /**
     * Constructor.
     *
     * @param address <tt>InetAddress</tt>
     * @param port
     * @throws IOException 
     */
    public IceUdpSocketWrapper(InetAddress address, int port) throws IOException {
        this.channel = DatagramChannel.open();
        this.channel.socket().bind(new InetSocketAddress(address, port));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void send(DatagramPacket p) throws IOException {
        channel.socket().send(p);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void receive(DatagramPacket p) throws IOException {
        channel.socket().receive(p);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void close() {
        try {
            channel.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public InetAddress getLocalAddress() {
        return channel.socket().getLocalAddress();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getLocalPort() {
        return channel.socket().getLocalPort();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public SocketAddress getLocalSocketAddress() {
        try {
            return channel.getLocalAddress();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public DatagramChannel getUDPChannel() {
        return channel;
    }
}
