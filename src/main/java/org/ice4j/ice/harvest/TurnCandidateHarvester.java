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
package org.ice4j.ice.harvest;

import org.ice4j.*;
import org.ice4j.ice.*;
import org.ice4j.security.*;

/**
 * Implements a CandidateHarvester which gathers TURN
 * Candidates for a specified {@link Component}.
 *
 * @author Emil Ivov
 * @author Lubomir Marinov
 */
public class TurnCandidateHarvester
    extends StunCandidateHarvester
{

    /**
     * The LongTermCredential to be used with the TURN server with
     * which this instance works.
     */
    private final LongTermCredential longTermCredential;

    /**
     * Initializes a new TurnCandidateHarvester instance which is to
     * work with a specific TURN server.
     *
     * @param turnServer the TransportAddress of the TURN server the
     * new instance is to work with
     */
    public TurnCandidateHarvester(TransportAddress turnServer)
    {
        this(turnServer, (LongTermCredential) null);
    }

    /**
     * Initializes a new TurnCandidateHarvester instance which is to
     * work with a specific TURN server using a specific
     * LongTermCredential.
     *
     * @param turnServer the TransportAddress of the TURN server the
     * new instance is to work with
     * @param longTermCredential the LongTermCredential to use with the
     * specified turnServer or null if the use of the
     * long-term credential mechanism is not determined at the time of the
     * initialization of the new TurnCandidateHarvester instance
     */
    public TurnCandidateHarvester(
            TransportAddress turnServer,
            LongTermCredential longTermCredential)
    {
        super(turnServer);

        this.longTermCredential = longTermCredential;
    }

    /**
     * Initializes a new TurnCandidateHarvester instance which is to
     * work with a specific TURN server using a specific username for the
     * purposes of the STUN short-term credential mechanism.
     *
     * @param turnServer the TransportAddress of the TURN server the
     * new instance is to work with
     * @param shortTermCredentialUsername the username to be used by the new
     * instance for the purposes of the STUN short-term credential mechanism or
     * null if the use of the STUN short-term credential mechanism is
     * not determined at the time of the construction of the new instance
     */
    public TurnCandidateHarvester(
            TransportAddress turnServer,
            String shortTermCredentialUsername)
    {
        super(turnServer, shortTermCredentialUsername);

        this.longTermCredential = null;
    }

    /**
     * Creates a new TurnCandidateHarvest instance which is to perform
     * TURN harvesting of a specific HostCandidate.
     *
     * @param hostCandidate the HostCandidate for which harvesting is
     * to be performed by the new TurnCandidateHarvest instance
     * @return a new TurnCandidateHarvest instance which is to perform
     * TURN harvesting of the specified hostCandidate
     * @see StunCandidateHarvester#createHarvest(HostCandidate)
     */
    @Override
    protected TurnCandidateHarvest createHarvest(HostCandidate hostCandidate)
    {
        return new TurnCandidateHarvest(this, hostCandidate);
    }

    /**
     * Creates a LongTermCredential to be used by a specific
     * StunCandidateHarvest for the purposes of the long-term
     * credential mechanism in a specific realm of the TURN server
     * associated with this TurnCandidateHarvester. The default
     * implementation returns null and allows extenders to override in
     * order to support the long-term credential mechanism.
     *
     * @param harvest the StunCandidateHarvest which asks for the
     * LongTermCredential
     * @param realm the realm of the TURN server associated with this
     * TurnCandidateHarvester in which harvest will use the
     * returned LongTermCredential
     * @return a LongTermCredential to be used by harvest for
     * the purposes of the long-term credential mechanism in the specified
     * realm of the TURN server associated with this
     * TurnsCandidateHarvester
     * @see StunCandidateHarvester#createLongTermCredential(
     * StunCandidateHarvest,byte[])
     */
    @Override
    protected LongTermCredential createLongTermCredential(
            StunCandidateHarvest harvest,
            byte[] realm)
    {
        return longTermCredential;
    }
 }
