/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Copyright @ 2015 Atlassian Pty Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ice4j.socket;

import java.io.*;
import java.net.*;
import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.ice.*;
import org.ice4j.ice.harvest.*;
import org.ice4j.message.*;

/**
 * Represents an application-purposed (as opposed to an ICE-specific)
 * DatagramSocket for a RelayedCandidate harvested by a
 * TurnCandidateHarvest (and its associated
 * TurnCandidateHarvester, of course).
 * GoogleRelayedCandidateDatagramSocket is associated with a successful
 * Allocation on a TURN server and implements sends and receives through it
 * using TURN messages to and from that TURN server.
 *
 * @author Lyubomir Marinov
 * @author Sebastien Vincent
 */
public class GoogleRelayedCandidateDatagramSocket
    extends DatagramSocket
{
    /**
     * The Logger used by the
     * GoogleRelayedCandidateDatagramSocket class and its instances for
     * logging output.
     */
    private static final Logger logger
        = Logger.getLogger(
                GoogleRelayedCandidateDatagramSocket.class.getName());

    /**
     * The indicator which determines whether this instance has started
     * executing or has executed its {@link #close()} method.
     */
    private boolean closed = false;

    /**
     * The GoogleRelayedCandidate which uses this instance as the value
     * of its socket property.
     */
    private final GoogleRelayedCandidate relayedCandidate;

    /**
     * The GoogleTurnCandidateHarvest which has harvested
     * {@link #relayedCandidate}.
     */
    private final GoogleTurnCandidateHarvest turnCandidateHarvest;

    /**
     * The GoogleTurnCandidateDelegage which will handle send/receive
     * operations.
     */
    private final GoogleRelayedCandidateDelegate socketDelegate;

    /**
     * Initializes a new GoogleRelayedCandidateDatagramSocket instance
     * which is to be the socket of a specific
     * RelayedCandidate harvested by a specific
     * TurnCandidateHarvest.
     *
     * @param relayedCandidate the RelayedCandidate which is to use the
     * new instance as the value of its socket property
     * @param turnCandidateHarvest the TurnCandidateHarvest which has
     * harvested relayedCandidate
     * @param username username
     * @throws SocketException if anything goes wrong while initializing the new
     * GoogleRelayedCandidateDatagramSocket instance
     */
    public GoogleRelayedCandidateDatagramSocket(
            GoogleRelayedCandidate relayedCandidate,
            GoogleTurnCandidateHarvest turnCandidateHarvest,
            String username)
        throws SocketException
    {
        super(/* bindaddr */ (SocketAddress) null);

        socketDelegate = new GoogleRelayedCandidateDelegate(
            turnCandidateHarvest, username);
        this.relayedCandidate = relayedCandidate;
        this.turnCandidateHarvest = turnCandidateHarvest;

        logger.finest("Create new GoogleRelayedCandidateDatagramSocket");
    }

    /**
     * Closes this datagram socket.
     *
     * @see DatagramSocket#close()
     */
    @Override
    public void close()
    {
        synchronized (this)
        {
            if (this.closed)
                return;
            else
                this.closed = true;
        }

        socketDelegate.close();
        turnCandidateHarvest.close(this);
    }

    /**
     * Gets the local address to which the socket is bound.
     * GoogleRelayedCandidateDatagramSocket returns the
     * address of its localSocketAddress.
     * <p>
     * If there is a security manager, its checkConnect method is first
     * called with the host address and -1 as its arguments to see if
     * the operation is allowed.
     * </p>
     *
     * @return the local address to which the socket is bound, or an
     * InetAddress representing any local address if either the socket
     * is not bound, or the security manager checkConnect method does
     * not allow the operation
     * @see #getLocalSocketAddress()
     * @see DatagramSocket#getLocalAddress()
     */
    @Override
    public InetAddress getLocalAddress()
    {
        return getLocalSocketAddress().getAddress();
    }

    /**
     * Returns the port number on the local host to which this socket is bound.
     * GoogleRelayedCandidateDatagramSocket returns the port
     * of its localSocketAddress.
     *
     * @return the port number on the local host to which this socket is bound
     * @see #getLocalSocketAddress()
     * @see DatagramSocket#getLocalPort()
     */
    @Override
    public int getLocalPort()
    {
        return getLocalSocketAddress().getPort();
    }

    /**
     * Returns the address of the endpoint this socket is bound to, or
     * null if it is not bound yet. Since
     * GoogleRelayedCandidateDatagramSocket represents an
     * application-purposed DatagramSocket relaying data to and from a
     * TURN server, the localSocketAddress is the
     * transportAddress of the respective RelayedCandidate.
     *
     * @return a SocketAddress representing the local endpoint of this
     * socket, or null if it is not bound yet
     * @see DatagramSocket#getLocalSocketAddress()
     */
    @Override
    public InetSocketAddress getLocalSocketAddress()
    {
        return getRelayedCandidate().getTransportAddress();
    }

    /**
     * Gets the RelayedCandidate which uses this instance as the value
     * of its socket property.
     *
     * @return the RelayedCandidate which uses this instance as the
     * value of its socket property
     */
    public final GoogleRelayedCandidate getRelayedCandidate()
    {
        return relayedCandidate;
    }

    /**
     * Notifies this GoogleRelayedCandidateDatagramSocket that a
     * specific Request it has sent has received a STUN success
     * Response.
     *
     * @param response the Response which responds to request
     * @param request the Request sent by this instance to which
     * response responds
     */
    public void processSuccess(Response response, Request request)
    {
        socketDelegate.processSuccess(response, request);
    }

    /**
     * Dispatch the specified response.
     *
     * @param response the response to dispatch.
     */
    public void processResponse(StunResponseEvent response)
    {
        socketDelegate.processResponse(response);
    }

    /**
     * Receives a datagram packet from this socket. When this method returns,
     * the DatagramPacket's buffer is filled with the data received.
     * The datagram packet also contains the sender's IP address, and the port
     * number on the sender's machine.
     *
     * @param p the DatagramPacket into which to place the incoming
     * data
     * @throws IOException if an I/O error occurs
     * @see DatagramSocket#receive(DatagramPacket)
     */
    @Override
    public void receive(DatagramPacket p)
        throws IOException
    {
        socketDelegate.receive(p);
    }

    /**
     * Sends a datagram packet from this socket. The DatagramPacket
     * includes information indicating the data to be sent, its length, the IP
     * address of the remote host, and the port number on the remote host.
     *
     * @param p the DatagramPacket to be sent
     * @throws IOException if an I/O error occurs
     * @see DatagramSocket#send(DatagramPacket)
     */
    @Override
    public void send(DatagramPacket p)
        throws IOException
    {
        socketDelegate.send(p);
    }
}
