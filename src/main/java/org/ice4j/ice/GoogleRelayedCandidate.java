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
package org.ice4j.ice;

import java.lang.reflect.*;
import java.net.*;

import org.ice4j.*;
import org.ice4j.ice.harvest.*;
import org.ice4j.socket.*;

/**
 * Represents a Candidate obtained by sending a Google TURN Allocate
 * request from a HostCandidate to a TURN server.  The Google relayed
 * candidate is resident on the TURN server, and the TURN server relays packets
 * back towards the agent.
 *
 * @author Lubomir Marinov
 * @author Sebastien Vincent
 */
public class GoogleRelayedCandidate
    extends LocalCandidate
{
    /**
     * The RelayedCandidateDatagramSocket of this
     * GoogleRelayedCandidate.
     */
    private GoogleRelayedCandidateDatagramSocket relayedCandidateDatagramSocket;

    /**
     * The RelayedCandidateSocket of this
     * GoogleRelayedCandidate.
     */
    private GoogleRelayedCandidateSocket relayedCandidateSocket = null;

    /**
     * The application-purposed DatagramSocket associated with this
     * Candidate.
     */
    private IceSocketWrapper socket;

    /**
     * The GoogleTurnCandidateHarvest which has harvested this
     * GoogleRelayedCandidate.
     */
    private final GoogleTurnCandidateHarvest turnCandidateHarvest;

    /**
     * Username.
     */
    private final String username;

    /**
     * Password.
     */
    private final String password;

    /**
     * Initializes a new RelayedCandidate which is to represent a
     * specific TransportAddress harvested through a specific
     * HostCandidate and a TURN server with a specific
     * TransportAddress.
     *
     * @param transportAddress the TransportAddress to be represented
     * by the new instance
     * @param turnCandidateHarvest the TurnCandidateHarvest which has
     * harvested the new instance
     * @param mappedAddress the mapped TransportAddress reported by the
     * TURN server with the delivery of the replayed transportAddress
     * to be represented by the new instance
     * @param username username (Send request to the Google relay server need
     * it)
     * @param password password (used with XMPP gingle candidates).
     * it)
     */
    public GoogleRelayedCandidate(
            TransportAddress transportAddress,
            GoogleTurnCandidateHarvest turnCandidateHarvest,
            TransportAddress mappedAddress,
            String username,
            String password)
    {
        super(
            transportAddress,
            turnCandidateHarvest.hostCandidate.getParentComponent(),
            CandidateType.RELAYED_CANDIDATE,
            CandidateExtendedType.GOOGLE_TURN_RELAYED_CANDIDATE,
            turnCandidateHarvest.hostCandidate.getParentComponent()
                .findLocalCandidate(mappedAddress));

        if(transportAddress.getTransport() == Transport.TCP)
        {
            super.setExtendedType(
                    CandidateExtendedType.GOOGLE_TCP_TURN_RELAYED_CANDIDATE);
        }

        this.turnCandidateHarvest = turnCandidateHarvest;
        this.username = username;
        this.password = password;

        // RFC 5245: The base of a relayed candidate is that candidate itself.
        setBase(this);
        setRelayServerAddress(turnCandidateHarvest.harvester.stunServer);
        setMappedAddress(mappedAddress);
    }

    /**
     * Gets the RelayedCandidateDatagramSocket of this
     * RelayedCandidate.
     * <p>
     * <b>Note</b>: The method is part of the internal API of
     * RelayedCandidate and TurnCandidateHarvest and is not
     * intended for public use.
     * </p>
     *
     * @return the RelayedCandidateDatagramSocket of this
     * RelayedCandidate
     */
    private synchronized GoogleRelayedCandidateDatagramSocket
        getRelayedCandidateDatagramSocket()
    {
        if (relayedCandidateDatagramSocket == null)
        {
            try
            {
                relayedCandidateDatagramSocket
                    = new GoogleRelayedCandidateDatagramSocket(
                            this,
                            turnCandidateHarvest,
                            username);
            }
            catch (SocketException sex)
            {
                throw new UndeclaredThrowableException(sex);
            }
        }
        return relayedCandidateDatagramSocket;
    }

    /**
     * Gets the RelayedCandidateDatagramSocket of this
     * RelayedCandidate.
     * <p>
     * <b>Note</b>: The method is part of the internal API of
     * RelayedCandidate and TurnCandidateHarvest and is not
     * intended for public use.
     * </p>
     *
     * @return the RelayedCandidateDatagramSocket of this
     * RelayedCandidate
     */
    private synchronized GoogleRelayedCandidateSocket
        getRelayedCandidateSocket()
    {
        if (relayedCandidateSocket == null)
        {
            try
            {
                relayedCandidateSocket
                    = new GoogleRelayedCandidateSocket(
                        this,
                        turnCandidateHarvest,
                        username);
            }
            catch (SocketException sex)
            {
                throw new UndeclaredThrowableException(sex);
            }
        }
        return relayedCandidateSocket;
    }

    /**
     * Gets the application-purposed DatagramSocket associated with
     * this Candidate.
     *
     * @return the DatagramSocket associated with this
     * Candidate
     * @see LocalCandidate#getCandidateIceSocketWrapper()
     */
    @Override
    public synchronized IceSocketWrapper getCandidateIceSocketWrapper()
    {
        if (socket == null)
        {
            try
            {
                if(getTransport() == Transport.UDP)
                {
                    socket
                       = new IceUdpSocketWrapper(new MultiplexingDatagramSocket(
                            getRelayedCandidateDatagramSocket()));
                }
                else if(getTransport() == Transport.TCP)
                {
                    final Socket s = getRelayedCandidateSocket();
                    socket = new IceTcpSocketWrapper(new MultiplexingSocket(s));
                }
            }
            catch (Exception sex)
            {
                throw new UndeclaredThrowableException(sex);
            }
        }
        return socket;
    }

    /**
     * Returns the password for this candidate.
     * @return the password for this candidate.
     */
    public String getPassword()
    {
        return this.password;
    }
}
