/* See LICENSE.md for license information */
package org.ice4j.ice.harvest;

import java.lang.reflect.*;
import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.attribute.*;
import org.ice4j.ice.*;
import org.ice4j.message.*;
import org.ice4j.socket.*;
import org.ice4j.stack.*;

/**
 * Represents the harvesting of TURN Candidates for a specific
 * HostCandidate performed by a specific
 * TurnCandidateHarvester.
 *
 * @author Lyubomir Marinov
 */
public class TurnCandidateHarvest extends StunCandidateHarvest {

    /**
     * The Logger used by the TurnCandidateHarvest class and
     * its instances for logging output.
     */
    private static final Logger logger = Logger.getLogger(TurnCandidateHarvest.class.getName());

    /**
     * The Request created by the last call to
     * {@link #createRequestToStartResolvingCandidate()}.
     */
    private Request requestToStartResolvingCandidate;

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
     */
    public TurnCandidateHarvest(TurnCandidateHarvester harvester, HostCandidate hostCandidate) {
        super(harvester, hostCandidate);
    }

    /**
     * Notifies this TurnCandidateHarvest that a specific
     * RelayedCandidateDatagramSocket is closing and that this instance
     * is to delete the associated TURN Allocation.
     * <p>
     * <b>Note</b>: The method is part of the internal API of
     * RelayedCandidateDatagramSocket and TurnCandidateHarvest
     * and is not intended for public use.
     * <br>
     *
     * @param relayedCandidateSocket the RelayedCandidateDatagramSocket
     * which notifies this instance and which requests that the associated TURN
     * Allocation be deleted
     */
    public void close(RelayedCandidateDatagramSocket relayedCandidateSocket) {
        /*
         * FIXME As far as logic goes, it seems that it is possible to send a TURN Refresh, cancel the STUN keep-alive functionality here and only then receive the response to the
         * TURN Refresh which will enable the STUN keep-alive functionality again.
         */
        setSendKeepAliveMessageInterval(SEND_KEEP_ALIVE_MESSAGE_INTERVAL_NOT_SPECIFIED);

        /*
         * TURN Refresh with a LIFETIME value equal to zero deletes the TURN Allocation.
         */
        try {
            sendRequest(MessageFactory.createRefreshRequest(0), false, null);
        } catch (StunException sex) {
            logger.log(Level.INFO, "Failed to send TURN Refresh request to delete Allocation", sex);
        }
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
    protected boolean completedResolvingCandidate(Request request, Response response) {
        /*
         * TODO If the Allocate request is rejected because the server lacks resources to fulfill it, the agent SHOULD instead send a Binding request to obtain a server reflexive
         * candidate.
         */
        if ((response == null) || (!response.isSuccessResponse() && (request.getMessageType() == Message.ALLOCATE_REQUEST))) {
            try {
                if (startResolvingCandidate())
                    return false;
            } catch (Exception ex) {
                /*
                 * Complete the harvesting of Candidates for hostCandidate because the new attempt has just failed.
                 */
            }
        }
        return super.completedResolvingCandidate(request, response);
    }

    /**
     * Creates new Candidates determined by a specific STUN
     * Response.
     *
     * @param response the received STUN Response
     * @see StunCandidateHarvest#createCandidates(Response)
     */
    @Override
    protected void createCandidates(Response response) {
        createRelayedCandidate(response);

        // Let the super create the ServerReflexiveCandidate.
        super.createCandidates(response);
    }

    /**
     * Creates a new STUN Message to be sent to the STUN server
     * associated with the StunCandidateHarvester of this instance in
     * order to keep a specific LocalCandidate (harvested by this
     * instance) alive.
     *
     * @param candidate the LocalCandidate (harvested by this instance)
     * to create a new keep-alive STUN message for
     * @return a new keep-alive STUN Message for the specified
     * candidate or null if no keep-alive sending is to occur
     * @throws StunException if anything goes wrong while creating the new
     * keep-alive STUN Message for the specified candidate
     * or the candidate is of an unsupported CandidateType
     * @see StunCandidateHarvest#createKeepAliveMessage(LocalCandidate)
     */
    @Override
    protected Message createKeepAliveMessage(LocalCandidate candidate) throws StunException {
        switch (candidate.getType()) {
            case RELAYED_CANDIDATE:
                return MessageFactory.createRefreshRequest();
            case SERVER_REFLEXIVE_CANDIDATE:
                /*
                 * RFC 5245: The Refresh requests will also refresh the server reflexive candidate.
                 */
                boolean existsRelayedCandidate = false;

                for (Candidate<?> aCandidate : getCandidates()) {
                    if (CandidateType.RELAYED_CANDIDATE.equals(aCandidate.getType())) {
                        existsRelayedCandidate = true;
                        break;
                    }
                }
                return existsRelayedCandidate ? null : super.createKeepAliveMessage(candidate);
            default:
                return super.createKeepAliveMessage(candidate);
        }
    }

    /**
     * Creates a RelayedCandidate using the XOR-RELAYED-ADDRESS attribute in a specific STUN
     * Response for the actual TransportAddress of the new candidate. If the message is malformed and/or does not contain the
     * corresponding attribute, this method simply has no effect.
     *
     * @param response the STUN Response which is supposed to contain the address we should use for the new candidate
     */
    private void createRelayedCandidate(Response response) {
        Attribute attribute = response.getAttribute(Attribute.Type.XOR_RELAYED_ADDRESS);
        if (attribute instanceof XorRelayedAddressAttribute) {
            TransportAddress relayedAddress = ((XorRelayedAddressAttribute) attribute).getAddress(response.getTransactionID());
            RelayedCandidate relayedCandidate = createRelayedCandidate(relayedAddress, getMappedAddress(response));
            if (relayedCandidate != null) {
                // The ICE connectivity checks will utilize STUN on the (application-purposed) socket of the RelayedCandidate and will not add it to the
                // StunStack so we have to do it.
                harvester.getStunStack().addSocket(relayedCandidate.getStunSocket(null));
                relayedCandidate.getParentComponent().getComponentSocket().setSocket(relayedCandidate.getCandidateIceSocketWrapper());
                addCandidate(relayedCandidate);
            }
        }
    }

    /**
     * Creates a new RelayedCandidate instance which is to represent a specific TransportAddress harvested through
     * {@link #hostCandidate} and the TURN server associated with {@link #harvester}.
     *
     * @param transportAddress the TransportAddress to be represented by the new RelayedCandidate instance
     * @param mappedAddress the mapped TransportAddress reported by the TURN server with the delivery of the relayed transportAddress to
     * be represented by the new RelayedCandidate instance
     * @return a new RelayedCandidate instance which represents the specified TransportAddress harvested through
     * {@link #hostCandidate} and the TURN server associated with {@link #harvester}
     */
    protected RelayedCandidate createRelayedCandidate(TransportAddress transportAddress, TransportAddress mappedAddress) {
        return new RelayedCandidate(transportAddress, this, mappedAddress);
    }

    /**
     * Creates a new Request instance which is to be sent by this
     * StunCandidateHarvest in order to retry a specific
     * Request. For example, the long-term credential mechanism
     * dictates that a Request is first sent by the client without any
     * credential-related attributes, then it gets challenged by the server and
     * the client retries the original Request with the appropriate
     * credential-related attributes in response.
     *
     * @param request the Request which is to be retried by this
     * StunCandidateHarvest
     * @return the new Request instance which is to be sent by this
     * StunCandidateHarvest in order to retry the specified
     * request
     * @see StunCandidateHarvest#createRequestToRetry(Request)
     */
    @Override
    protected Request createRequestToRetry(Request request) {
        switch (request.getMessageType()) {
            case Message.ALLOCATE_REQUEST: {
                RequestedTransportAttribute requestedTransportAttribute = (RequestedTransportAttribute) request.getAttribute(Attribute.Type.REQUESTED_TRANSPORT);
                int requestedTransport = (requestedTransportAttribute == null) ? 17 /* User Datagram Protocol */
                : requestedTransportAttribute.getRequestedTransport();
                EvenPortAttribute evenPortAttribute = (EvenPortAttribute) request.getAttribute(Attribute.Type.EVEN_PORT);
                boolean rFlag = (evenPortAttribute != null) && evenPortAttribute.isRFlag();

                return MessageFactory.createAllocateRequest((byte) requestedTransport, rFlag);
            }

            case Message.CHANNELBIND_REQUEST: {
                ChannelNumberAttribute channelNumberAttribute = (ChannelNumberAttribute) request.getAttribute(Attribute.Type.CHANNEL_NUMBER);
                char channelNumber = channelNumberAttribute.getChannelNumber();
                XorPeerAddressAttribute peerAddressAttribute = (XorPeerAddressAttribute) request.getAttribute(Attribute.Type.XOR_PEER_ADDRESS);
                TransportAddress peerAddress = peerAddressAttribute.getAddress(request.getTransactionID());
                byte[] retryTransactionID = TransactionID.createNewTransactionID().getBytes();
                Request retryChannelBindRequest = MessageFactory.createChannelBindRequest(channelNumber, peerAddress, retryTransactionID);

                try {
                    retryChannelBindRequest.setTransactionID(retryTransactionID);
                } catch (StunException sex) {
                    throw new UndeclaredThrowableException(sex);
                }
                return retryChannelBindRequest;
            }

            case Message.CREATEPERMISSION_REQUEST: {
                XorPeerAddressAttribute peerAddressAttribute = (XorPeerAddressAttribute) request.getAttribute(Attribute.Type.XOR_PEER_ADDRESS);
                TransportAddress peerAddress = peerAddressAttribute.getAddress(request.getTransactionID());
                byte[] retryTransactionID = TransactionID.createNewTransactionID().getBytes();
                Request retryCreatePermissionRequest = MessageFactory.createCreatePermissionRequest(peerAddress, retryTransactionID);

                try {
                    retryCreatePermissionRequest.setTransactionID(retryTransactionID);
                } catch (StunException sex) {
                    throw new UndeclaredThrowableException(sex);
                }
                return retryCreatePermissionRequest;
            }

            case Message.REFRESH_REQUEST: {
                LifetimeAttribute lifetimeAttribute = (LifetimeAttribute) request.getAttribute(Attribute.Type.LIFETIME);

                if (lifetimeAttribute == null)
                    return MessageFactory.createRefreshRequest();
                else {
                    return MessageFactory.createRefreshRequest(lifetimeAttribute.getLifetime());
                }
            }

            default:
                return super.createRequestToRetry(request);
        }
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
    protected Request createRequestToStartResolvingCandidate() {
        if (requestToStartResolvingCandidate == null) {
            requestToStartResolvingCandidate = MessageFactory.createAllocateRequest((byte) 17 /* User Datagram Protocol */, false);
            return requestToStartResolvingCandidate;
        } else if (requestToStartResolvingCandidate.getMessageType() == Message.ALLOCATE_REQUEST) {
            requestToStartResolvingCandidate = super.createRequestToStartResolvingCandidate();
            return requestToStartResolvingCandidate;
        } else
            return null;
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
    protected boolean processErrorOrFailure(Response response, Request request, TransactionID transactionID) {

        /*
         * TurnCandidateHarvest uses the applicationData of TransactionID to deliver the results of Requests sent by RelayedCandidateDatagramSocket back to it.
         */
        Object applicationData = transactionID.getApplicationData();

        if ((applicationData instanceof RelayedCandidateDatagramSocket) && ((RelayedCandidateDatagramSocket) applicationData).processErrorOrFailure(response, request))
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
    protected void processSuccess(Response response, Request request, TransactionID transactionID) {
        super.processSuccess(response, request, transactionID);

        LifetimeAttribute lifetimeAttribute;
        int lifetime /* minutes */= -1;

        switch (response.getMessageType()) {
            case Message.ALLOCATE_RESPONSE:
                // The default lifetime of an allocation is 10 minutes.
                lifetimeAttribute = (LifetimeAttribute) response.getAttribute(Attribute.Type.LIFETIME);
                lifetime = (lifetimeAttribute == null) ? (10 * 60) : lifetimeAttribute.getLifetime();
                break;
            case Message.REFRESH_RESPONSE:
                lifetimeAttribute = (LifetimeAttribute) response.getAttribute(Attribute.Type.LIFETIME);
                if (lifetimeAttribute != null)
                    lifetime = lifetimeAttribute.getLifetime();
                break;
        }
        if (lifetime >= 0) {
            setSendKeepAliveMessageInterval(
            /* milliseconds */1000L * lifetime);
        }

        /*
         * TurnCandidateHarvest uses the applicationData of TransactionID to deliver the results of Requests sent by RelayedCandidateDatagramSocket back to it.
         */
        Object applicationData = transactionID.getApplicationData();

        if (applicationData instanceof RelayedCandidateDatagramSocket) {
            ((RelayedCandidateDatagramSocket) applicationData).processSuccess(response, request);
        }
    }

    /**
     * Sends a specific Request on behalf of a specific
     * RelayedCandidateDatagramSocket to the TURN server associated
     * with this TurnCandidateHarvest.
     *
     * @param relayedCandidateDatagramSocket the
     * RelayedCandidateDatagramSocket which sends the specified
     * Request and which is to be notified of the result
     * @param request the Request to be sent to the TURN server
     * associated with this TurnCandidateHarvest
     * @return an array of bytes which represents the ID of the
     * transaction with which the specified Request has been sent to
     * the TURN server
     * @throws StunException if anything goes wrong while sending the specified
     * Request
     */
    public byte[] sendRequest(RelayedCandidateDatagramSocket relayedCandidateDatagramSocket, Request request) throws StunException {
        TransactionID transactionID = TransactionID.createNewTransactionID();

        transactionID.setApplicationData(relayedCandidateDatagramSocket);
        transactionID = sendRequest(request, false, transactionID);
        return (transactionID == null) ? null : transactionID.getBytes();
    }
}
