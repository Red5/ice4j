/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal. Copyright @ 2015 Atlassian Pty Ltd Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or
 * agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under the License.
 */
package org.ice4j.socket;

import java.io.*;
import java.net.*;
import java.nio.channels.SelectableChannel;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.*;
import java.util.logging.*;

import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.ice.*;

/**
 * TCP Server Socket wrapper.
 *
 * @author Sebastien Vincent
 */
public class IceTcpServerSocketWrapper extends IceSocketWrapper {

    private static final Logger logger = Logger.getLogger(IceTcpServerSocketWrapper.class.getName());

    /**
     * Thread that will wait new connections.
     */
    private Thread acceptThread = null;

    /**
     * The wrapped TCP ServerSocketChannel.
     */
    private final ServerSocketChannel serverChannel;

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
    public IceTcpServerSocketWrapper(ServerSocket serverChannel, Component component) {
        this.serverChannel = serverChannel;
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
            serverChannel.close();
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
        return serverChannel.socket().getInetAddress();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getLocalPort() {
        return serverChannel.socket().getLocalPort();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public SocketAddress getLocalSocketAddress() {
        return serverChannel.socket().getLocalSocketAddress();
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
        if (transportAddress == null && serverChannel != null) {
            transportAddress = new TransportAddress(serverChannel.socket().getInetAddress(), serverChannel.socket().getLocalPort(), Transport.TCP);
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
                    SocketChannel tcpChannel = serverChannel.accept();
                    if (tcpChannel != null) {
                        MultiplexingSocket multiplexingSocket = new MultiplexingSocket(tcpChannel);
                        component.getParentStream().getParentAgent().getStunStack().addSocket(new IceTcpSocketWrapper(multiplexingSocket));
                        component.getComponentSocket().add(multiplexingSocket);
                        channels.add(multiplexingSocket);
                    }
                } catch (IOException e) {
                    logger.info("Failed to accept TCP socket " + e);
                }
            }
        }
    }
}
