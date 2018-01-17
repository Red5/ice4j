/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal. Copyright @ 2015 Atlassian Pty Ltd Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or
 * agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under the License.
 */
package org.ice4j.ice;

import java.net.Socket;
import java.net.SocketAddress;
import java.nio.channels.SocketChannel;
import java.util.LinkedList;
import java.util.List;

import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.socket.IceSocketWrapper;
import org.ice4j.stack.StunStack;

/**
 * Extends {@link org.ice4j.ice.HostCandidate} allowing the instance to have
 * a list of Sockets instead of just one socket. This is needed,
 * because with TCP, connections from different remote addresses result in
 * different Socket instances.
 *
 * @author Boris Grozev
 */
public class TcpHostCandidate extends HostCandidate {
    /**
     * List of accepted sockets for this TcpHostCandidate.
     */
    private final List<IceSocketWrapper> sockets = new LinkedList<>();

    /**
     * Initializes a new TcpHostCandidate.
     *
     * @param transportAddress the transport address of this
     * TcpHostCandidate.
     * @param parentComponent the Component that this candidate
     * belongs to.
     */
    public TcpHostCandidate(TransportAddress transportAddress, Component parentComponent) {
        super(transportAddress, parentComponent);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected IceSocketWrapper getCandidateIceSocketWrapper(SocketAddress remoteAddress) {
        for (IceSocketWrapper socket : sockets) {
            if (((SocketChannel) socket.getChannel()).socket().getRemoteSocketAddress().equals(remoteAddress)) {
                return socket;
            }
        }
        return null;
    }

    public void addSocket(IceSocketWrapper socket) {
        sockets.add(socket);
    }

    @Override
    protected void free() {
        StunStack stunStack = getStunStack();
        TransportAddress localAddr = getTransportAddress();
        for (IceSocketWrapper socket : sockets) {
            //remove our sockets from the stack.
            Socket tcpSocket = ((SocketChannel) socket.getChannel()).socket();
            stunStack.removeSocket(localAddr, new TransportAddress(tcpSocket.getInetAddress(), tcpSocket.getPort(), Transport.TCP));
            socket.close();
        }
        super.free();
    }

}
