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
 * Represents a Candidate obtained by sending a TURN Allocate request
 * from a HostCandidate to a TURN server.  The relayed candidate is
 * resident on the TURN server, and the TURN server relays packets back towards
 * the agent.
 *
 * @author Lubomir Marinov
 */
public class RelayedCandidate
    extends LocalCandidate
{

    /**
     * The RelayedCandidateDatagramSocket of this
     * RelayedCandidate.
     */
    private RelayedCandidateDatagramSocket relayedCandidateDatagramSocket;

    /**
     * The application-purposed DatagramSocket associated with this
     * Candidate.
     */
    private IceSocketWrapper socket;

    /**
     * The TurnCandidateHarvest which has harvested this
     * RelayedCandidate.
     */
    private final TurnCandidateHarvest turnCandidateHarvest;

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
     */
    public RelayedCandidate(
            TransportAddress transportAddress,
            TurnCandidateHarvest turnCandidateHarvest,
            TransportAddress mappedAddress)
    {
        super(
            transportAddress,
            turnCandidateHarvest.hostCandidate.getParentComponent(),
            CandidateType.RELAYED_CANDIDATE,
            CandidateExtendedType.TURN_RELAYED_CANDIDATE,
            turnCandidateHarvest.hostCandidate.getParentComponent()
                .findLocalCandidate(mappedAddress));

        this.turnCandidateHarvest = turnCandidateHarvest;

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
    private synchronized RelayedCandidateDatagramSocket
        getRelayedCandidateDatagramSocket()
    {
        if (relayedCandidateDatagramSocket == null)
        {
            try
            {
                relayedCandidateDatagramSocket
                    = new RelayedCandidateDatagramSocket(
                            this,
                            turnCandidateHarvest);
            }
            catch (SocketException sex)
            {
                throw new UndeclaredThrowableException(sex);
            }
        }
        return relayedCandidateDatagramSocket;
    }

    /**
     * Gets the application-purposed DatagramSocket associated with
     * this Candidate.
     *
     * @return the DatagramSocket associated with this
     * Candidate
     */
    @Override
    public synchronized IceSocketWrapper getCandidateIceSocketWrapper()
    {
        if (socket == null)
        {
            try
            {
                socket
                    = new IceUdpSocketWrapper(new MultiplexingDatagramSocket(
                            getRelayedCandidateDatagramSocket()));
            }
            catch (SocketException sex)
            {
                throw new UndeclaredThrowableException(sex);
            }
        }
        return socket;
    }
}
