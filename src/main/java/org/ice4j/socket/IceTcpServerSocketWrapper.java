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
import java.net.ServerSocket;
import java.net.SocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.List;

import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.ice.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TCP Server Socket wrapper.
 *
 * @author Sebastien Vincent
 */
public class IceTcpServerSocketWrapper extends IceSocketWrapper {

    private static final Logger logger = LoggerFactory.getLogger(IceTcpServerSocketWrapper.class);

    /**
     * Thread that will wait new connections.
     */
    private Thread acceptThread = null;

    /**
     * If the socket is still listening.
     */
    private boolean isRun;

    /**
     * STUN stack.
     */
    private final Component component;

    /**
     * List of TCP client sockets.
     */
    private final List<SocketChannel> channels = new ArrayList<>();

    /**
     * Initializes a new IceTcpServerSocketWrapper.
     *
     * @param serverSocket TCP ServerSocket
     * @param component related Component
     */
    public IceTcpServerSocketWrapper(ServerSocket serverSocket, Component component) {
        super(serverSocket.getChannel());
        this.component = component;
        acceptThread = new ThreadAccept();
        acceptThread.start();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void send(DatagramPacket p) throws IOException {
        /* Do nothing for the moment */
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void receive(DatagramPacket p) throws IOException {
        /* Do nothing for the moment */
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void close() {
        try {
            isRun = false;
            channel.close();
            for (SocketChannel s : channels) {
                s.close();
            }
        } catch (IOException e) {
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public InetAddress getLocalAddress() {
        return ((ServerSocketChannel) channel).socket().getInetAddress();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getLocalPort() {
        return ((ServerSocketChannel) channel).socket().getLocalPort();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public SocketAddress getLocalSocketAddress() {
        return ((ServerSocketChannel) channel).socket().getLocalSocketAddress();
    }

    /** {@inheritDoc} */
    @Override
    public SocketChannel getChannel() {
        if (channels.size() > 0) {
            return channels.get(0);
        }
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public TransportAddress getTransportAddress() {
        if (transportAddress == null && channel != null) {
            ServerSocket socket = ((ServerSocketChannel) channel).socket();
            transportAddress = new TransportAddress(socket.getInetAddress(), socket.getLocalPort(), Transport.TCP);
        }
        return transportAddress;
    }

    /**
     * Thread that will wait for new TCP connections.
     */
    private class ThreadAccept extends Thread {

        @Override
        public void run() {
            isRun = true;
            while (isRun) {
                try {
                    SocketChannel tcpChannel = ((ServerSocketChannel) channel).accept();
                    if (tcpChannel != null) {
                        IceTcpSocketWrapper multiplexingSocket = new IceTcpSocketWrapper(tcpChannel);
                        component.getParentStream().getParentAgent().getStunStack().addSocket(multiplexingSocket);
                        component.getComponentSocket().setSocket(multiplexingSocket);
                        channels.add(tcpChannel);
                    }
                } catch (IOException e) {
                    logger.warn("Failed to accept TCP socket", e);
                }
            }
        }

    }

}
