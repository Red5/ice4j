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

import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.attribute.*;
import org.ice4j.ice.*;
import org.ice4j.message.*;
import org.ice4j.socket.*;
import org.ice4j.stack.*;

/**
 * Represents the harvesting of Google TURN Candidates for a specific
 * HostCandidate performed by a specific
 * GoogleTurnCandidateHarvester.
 *
 * @author Lyubomir Marinov
 * @author Sebastien Vincent
 */
public class GoogleTurnCandidateHarvest
    extends StunCandidateHarvest
{
    /**
     * The Logger used by the TurnCandidateHarvest class and
     * its instances for logging output.
     */
    private static final Logger logger
        = Logger.getLogger(GoogleTurnCandidateHarvest.class.getName());

    /**
     * The Request created by the last call to
     * {@link #createRequestToStartResolvingCandidate()}.
     */
    private Request requestToStartResolvingCandidate;

    /**
     * The gingle candidates password necessary to use the TURN server.
     */
    private String password;

    /**
     * Initializes a new TurnCandidateHarvest which is to represent the
     * harvesting of TURN Candidates for a specific
     * HostCandidate performed by a specific
     * TurnCandidateHarvester.
     *
     * @param harvester the TurnCandidateHarvester which is performing
     * the TURN harvesting
     * @param hostCandidate the HostCandidate for which TURN
     * Candidates are to be harvested
     * @param password The gingle candidates password necessary to use this TURN
     * server.
     */
    public GoogleTurnCandidateHarvest(
            GoogleTurnCandidateHarvester harvester,
            HostCandidate hostCandidate,
            String password)
    {
        super(harvester, hostCandidate);
        this.password = password;
    }

    /**
     * Creates new Candidates determined by a specific STUN
     * Response.
     *
     * @param response the received STUN Response
     * @see StunCandidateHarvest#createCandidates(Response)
     */
    @Override
    protected void createCandidates(Response response)
    {
        createRelayedCandidate(response);
    }

    /**
     * Creates a RelayedCandidate using the
     * XOR-RELAYED-ADDRESS attribute in a specific STUN
     * Response for the actual TransportAddress of the new
     * candidate. If the message is malformed and/or does not contain the
     * corresponding attribute, this method simply has no effect.
     *
     * @param response the STUN Response which is supposed to contain
     * the address we should use for the new candidate
     */
    private void createRelayedCandidate(Response response)
    {
        Attribute attribute
            = response.getAttribute(Attribute.Type.MAPPED_ADDRESS);

        if(attribute != null)
        {
            TransportAddress relayedAddress
                = ((MappedAddressAttribute) attribute).getAddress();

            if (harvester.stunServer.getTransport() == Transport.TCP)
            {
                relayedAddress = new TransportAddress(
                    relayedAddress.getAddress(),
                    harvester.stunServer.getPort(),
                    //relayedAddress.getPort() - 1,
                    Transport.TCP);
            }
            GoogleRelayedCandidate relayedCandidate
                = createRelayedCandidate(
                        relayedAddress,
                        getMappedAddress(response));

            if (relayedCandidate != null)
            {
                /*
                 * The ICE connectivity checks will utilize STUN on the
                 * (application-purposed) socket of the RelayedCandidate and
                 * will not add it to the StunStack so we have to do it.
                 */
                harvester.getStunStack().addSocket(
                        relayedCandidate.getStunSocket(null));

                // Make the relayed candidate's socket available for reading
                // by the component.
                IceSocketWrapper candidateSocket
                    = relayedCandidate.getCandidateIceSocketWrapper();

                Component component = relayedCandidate.getParentComponent();
                component.getComponentSocket().add(candidateSocket);

                addCandidate(relayedCandidate);
            }
        }
    }

    /**
     * Creates a new RelayedCandidate instance which is to represent a
     * specific TransportAddress harvested through
     * {@link #hostCandidate} and the TURN server associated with
     * {@link #harvester}.
     *
     * @param transportAddress the TransportAddress to be represented
     * by the new RelayedCandidate instance
     * @param mappedAddress the mapped TransportAddress reported by the
     * TURN server with the delivery of the relayed transportAddress to
     * be represented by the new RelayedCandidate instance
     * @return a new RelayedCandidate instance which represents the
     * specified TransportAddress harvested through
     * {@link #hostCandidate} and the TURN server associated with
     * {@link #harvester}
     */
    protected GoogleRelayedCandidate createRelayedCandidate(
            TransportAddress transportAddress,
            TransportAddress mappedAddress)
    {
        GoogleRelayedCandidate candidate =
            new GoogleRelayedCandidate(
                    transportAddress,
                    this,
                    mappedAddress,
                    harvester.getShortTermCredentialUsername(),
                    this.password);

        candidate.setUfrag(harvester.getShortTermCredentialUsername());
        return candidate;
    }

    /**
     * Creates a new Request which is to be sent to
     * {@link TurnCandidateHarvester#stunServer} in order to start resolving
     * {@link #hostCandidate}.
     *
     * @return a new Request which is to be sent to
     * {@link TurnCandidateHarvester#stunServer} in order to start resolving
     * {@link #hostCandidate}
     * @see StunCandidateHarvest#createRequestToStartResolvingCandidate()
     */
    @Override
    protected Request createRequestToStartResolvingCandidate()
    {
        if (requestToStartResolvingCandidate == null)
        {
            requestToStartResolvingCandidate
                = MessageFactory.createGoogleAllocateRequest(
                        harvester.getShortTermCredentialUsername());

            return requestToStartResolvingCandidate;
        }
        else
            return null;
    }

    /**
     * Adds the Attributes to a specific Request which support
     * the STUN short-term credential mechanism if the mechanism in question is
     * utilized by this StunCandidateHarvest (i.e. by the associated
     * StunCandidateHarvester).
     *
     * @param request the Request to which to add the
     * Attributes supporting the STUN short-term credential mechanism
     * if the mechanism in question is utilized by this
     * StunCandidateHarvest
     * @return true if the STUN short-term credential mechanism is
     * actually utilized by this StunCandidateHarvest for the specified
     * request; otherwise, false
     */
    @Override
    protected boolean addShortTermCredentialAttributes(Request request)
    {
        return false;
    }

    /**
     * Completes the harvesting of Candidates for
     * {@link #hostCandidate}. Notifies {@link #harvester} about the completion
     * of the harvesting of Candidate for hostCandidate
     * performed by this StunCandidateHarvest.
     *
     * @param request the Request sent by this
     * StunCandidateHarvest with which the harvesting of
     * Candidates for hostCandidate has completed
     * @param response the Response received by this
     * StunCandidateHarvest, if any, with which the harvesting of
     * Candidates for hostCandidate has completed
     * @return true if the harvesting of Candidates for
     * hostCandidate performed by this StunCandidateHarvest
     * has completed; otherwise, false
     * @see StunCandidateHarvest#completedResolvingCandidate(Request, Response)
     */
    @Override
    protected boolean completedResolvingCandidate(
            Request request,
            Response response)
    {
        if ((response == null)
                || (!response.isSuccessResponse()
                        && (request.getMessageType()
                                == Message.ALLOCATE_REQUEST)))
        {
            try
            {
                if (startResolvingCandidate())
                    return false;
            }
            catch (Exception ex)
            {
                /*
                 * Complete the harvesting of Candidates for hostCandidate
                 * because the new attempt has just failed.
                 */
            }
        }
        return super.completedResolvingCandidate(request, response);
    }

    /**
     * Notifies this TurnCandidateHarvest that a specific
     * RelayedCandidateDatagramSocket is closing and that this instance
     * is to delete the associated TURN Allocation.
     * <p>
     * <b>Note</b>: The method is part of the internal API of
     * RelayedCandidateDatagramSocket and TurnCandidateHarvest
     * and is not intended for public use.
     * </p>
     *
     * @param relayedCandidateSocket the RelayedCandidateDatagramSocket
     * which notifies this instance and which requests that the associated TURN
     * Allocation be deleted
     */
    public void close(
            GoogleRelayedCandidateDatagramSocket relayedCandidateSocket)
    {
        /*
         * FIXME As far as logic goes, it seems that it is possible to send a
         * TURN Refresh, cancel the STUN keep-alive functionality here and only
         * then receive the response to the TURN Refresh which will enable the
         * STUN keep-alive functionality again.
         */
        setSendKeepAliveMessageInterval(
                SEND_KEEP_ALIVE_MESSAGE_INTERVAL_NOT_SPECIFIED);
    }

    /**
     * Notifies this StunCandidateHarvest that a specific
     * Request has either received an error Response or has
     * failed to receive any Response.
     *
     * @param response the error Response which has been received for
     * request
     * @param request the Request to which Response responds
     * @param transactionID the TransactionID of response and
     * request because response and request only have
     * it as a byte array and TransactionID is required for
     * the applicationData property value
     * @return true if the error or failure condition has been
     * processed and this instance can continue its execution (e.g. the
     * resolution of the candidate) as if it was expected; otherwise,
     * false
     * @see StunCandidateHarvest#processErrorOrFailure(Response, Request,
     * TransactionID)
     */
    @Override
    protected boolean processErrorOrFailure(
            Response response,
            Request request,
            TransactionID transactionID)
    {
        logger.info("Google TURN processErrorOrFailure");
        /*
         * TurnCandidateHarvest uses the applicationData of TransactionID to
         * deliver the results of Requests sent by
         * RelayedCandidateDatagramSocket back to it.
         */
        Object applicationData = transactionID.getApplicationData();

        if ((applicationData instanceof GoogleRelayedCandidateDatagramSocket)
                && ((RelayedCandidateDatagramSocket) applicationData)
                        .processErrorOrFailure(response, request))
            return true;
        else if ((applicationData instanceof
            GoogleRelayedCandidateDatagramSocket)
            && ((RelayedCandidateDatagramSocket) applicationData)
                    .processErrorOrFailure(response, request))
        return true;

        return super.processErrorOrFailure(response, request, transactionID);
    }

    /**
     * Handles a specific STUN success Response to a specific STUN
     * Request.
     *
     * @param response the received STUN success Response which is to
     * be handled
     * @param request the STUN Request to which response
     * responds
     * @param transactionID the TransactionID of response and
     * request because response and request only have
     * it as a byte array and TransactionID is required for
     * the applicationData property value
     * @see StunCandidateHarvest#processSuccess(Response, Request,
     * TransactionID)
     */
    @Override
    protected void processSuccess(
            Response response,
            Request request,
            TransactionID transactionID)
    {
        super.processSuccess(response, request, transactionID);

        LifetimeAttribute lifetimeAttribute;
        int lifetime /* minutes */ = -1;

        switch (response.getMessageType())
        {
        case Message.ALLOCATE_RESPONSE:
            // The default lifetime of an allocation is 10 minutes.
            lifetimeAttribute
                = (LifetimeAttribute) response.getAttribute(Attribute.Type.LIFETIME);
            lifetime
                = (lifetimeAttribute == null)
                    ? (10 * 60)
                    : lifetimeAttribute.getLifetime();
            logger.info("Successful Google TURN allocate");
            break;
        default:
            break;
        }

        if (lifetime >= 0)
        {
            setSendKeepAliveMessageInterval(
                    /* milliseconds */ 1000L * lifetime);
        }

        /*
         * TurnCandidateHarvest uses the applicationData of TransactionID to
         * deliver the results of Requests sent by
         * RelayedCandidateDatagramSocket back to it.
         */
        Object applicationData = transactionID.getApplicationData();

        if (applicationData instanceof GoogleRelayedCandidateDatagramSocket)
        {
            ((GoogleRelayedCandidateDatagramSocket) applicationData)
                .processSuccess(response, request);
        }
        else if (applicationData instanceof GoogleRelayedCandidateSocket)
        {
            ((GoogleRelayedCandidateSocket) applicationData)
                .processSuccess(response, request);
        }
    }
}
