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

import java.io.IOException;
import java.lang.ref.WeakReference;
import java.util.EnumSet;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.ice4j.AbstractResponseCollector;
import org.ice4j.BaseStunMessageEvent;
import org.ice4j.ResponseCollector;
import org.ice4j.StunException;
import org.ice4j.StunResponseEvent;
import org.ice4j.TransportAddress;
import org.ice4j.attribute.Attribute;
import org.ice4j.attribute.AttributeFactory;
import org.ice4j.attribute.ErrorCodeAttribute;
import org.ice4j.attribute.MappedAddressAttribute;
import org.ice4j.attribute.MessageIntegrityAttribute;
import org.ice4j.attribute.NonceAttribute;
import org.ice4j.attribute.RealmAttribute;
import org.ice4j.attribute.UsernameAttribute;
import org.ice4j.attribute.XorMappedAddressAttribute;
import org.ice4j.ice.CandidateExtendedType;
import org.ice4j.ice.CandidateType;
import org.ice4j.ice.HostCandidate;
import org.ice4j.ice.LocalCandidate;
import org.ice4j.ice.ServerReflexiveCandidate;
import org.ice4j.message.Message;
import org.ice4j.message.MessageFactory;
import org.ice4j.message.Request;
import org.ice4j.message.Response;
import org.ice4j.security.LongTermCredential;
import org.ice4j.security.LongTermCredentialSession;
import org.ice4j.stack.StunStack;
import org.ice4j.stack.TransactionID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents the harvesting of STUN Candidates for a specific
 * HostCandidate performed by a specific
 * StunCandidateHarvester.
 *
 * @author Lyubomir Marinov
 */
public class StunCandidateHarvest
    extends AbstractResponseCollector
{

    /**
     * The Logger used by the StunCandidateHarvest class and
     * its instances for logging output.
     */
    private static final Logger logger = LoggerFactory.getLogger(StunCandidateHarvest.class);

    /**
     * The constant which defines an empty array with LocalCandidate
     * element type. Explicitly defined in order to reduce unnecessary
     * allocations.
     */
    private static final LocalCandidate[] NO_CANDIDATES = new LocalCandidate[0];

    /**
     * The value of the sendKeepAliveMessage property of
     * StunCandidateHarvest which specifies that no sending of STUN
     * keep-alive messages is to performed for the purposes of keeping the
     * Candidates harvested by the StunCandidateHarvester in
     * question alive.
     */
    protected static final long SEND_KEEP_ALIVE_MESSAGE_INTERVAL_NOT_SPECIFIED
        = 0;

    /**
     * The list of Candidates harvested for {@link #hostCandidate} by
     * this harvest.
     */
    private final List<LocalCandidate> candidates = new LinkedList<>();

    /**
     * The indicator which determines whether this StunCandidateHarvest
     * has completed the harvesting of Candidates for
     * {@link #hostCandidate}.
     */
    private boolean completedResolvingCandidate = false;

    /**
     * The StunCandidateHarvester performing the harvesting of STUN
     * Candidates for a Component which this harvest is part
     * of.
     */
    public final StunCandidateHarvester harvester;

    /**
     * The HostCandidate the STUN harvesting of which is represented by
     * this instance.
     */
    public final HostCandidate hostCandidate;

    /**
     * The LongTermCredential used by this instance.
     */
    private LongTermCredentialSession longTermCredentialSession;

    /**
     * The STUN Requests which have been sent by this instance, have
     * not received a STUN Response yet and have not timed out. Put in
     * place to avoid a limitation of the ResponseCollector and its use
     * of StunMessageEvent which do not make the STUN Request
     * to which a STUN Response responds available though it is known
     * in StunClientTransaction.
     */
    private final ConcurrentMap<TransactionID, Request> requests = new ConcurrentHashMap<>();

    /**
     * The interval in milliseconds at which a new STUN keep-alive message is to
     * be sent to the STUN server associated with the
     * StunCandidateHarvester of this instance in order to keep one of
     * the Candidates harvested by this instance alive.
     */
    private long sendKeepAliveMessageInterval
        = SEND_KEEP_ALIVE_MESSAGE_INTERVAL_NOT_SPECIFIED;

    /**
     * The Object used to synchronize access to the members related to
     * the sending of STUN keep-alive messages to the STUN server associated
     * with the StunCandidateHarvester of this instance.
     */
    private final Object sendKeepAliveMessageSyncRoot = new Object();

    /**
     * The Thread which sends the STUN keep-alive messages to the STUN
     * server associated with the StunCandidateHarvester of this
     * instance in order to keep the Candidates harvested by this
     * instance alive.
     */
    private Thread sendKeepAliveMessageThread;

    /**
     * The time (stamp) in milliseconds of the last call to
     * {@link #sendKeepAliveMessage()} which completed without throwing an
     * exception. <b>Note</b>: It doesn't mean that the keep-alive message was a
     * STUN Request and it received a success STUN Response.
     */
    private long sendKeepAliveMessageTime = -1;

    /**
     * Initializes a new StunCandidateHarvest which is to represent the
     * harvesting of STUN Candidates for a specific
     * HostCandidate performed by a specific
     * StunCandidateHarvester.
     *
     * @param harvester the StunCandidateHarvester which is performing
     * the STUN harvesting
     * @param hostCandidate the HostCandidate for which STUN
     * Candidates are to be harvested
     */
    public StunCandidateHarvest(
            StunCandidateHarvester harvester,
            HostCandidate hostCandidate)
    {
        this.harvester = harvester;
        this.hostCandidate = hostCandidate;
    }

    /**
     * Adds a specific LocalCandidate to the list of
     * LocalCandidates harvested for {@link #hostCandidate} by this
     * harvest.
     *
     * @param candidate the LocalCandidate to be added to the list of
     * LocalCandidates harvested for {@link #hostCandidate} by this
     * harvest
     * @return true if the list of LocalCandidates changed as
     * a result of the method invocation; otherwise, false
     */
    protected boolean addCandidate(LocalCandidate candidate)
    {
        boolean added;

        //try to add the candidate to the component and then only add it to the
        //harvest if it wasn't deemed redundant
        if (!candidates.contains(candidate)
                && hostCandidate.getParentComponent().addLocalCandidate(
                        candidate))
        {
            added = candidates.add(candidate);
        }
        else
        {
            added = false;
        }
        return added;
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
    protected boolean addShortTermCredentialAttributes(Request request)
    {
        String shortTermCredentialUsername
            = harvester.getShortTermCredentialUsername();

        if (shortTermCredentialUsername != null)
        {
            request.putAttribute(
                    AttributeFactory.createUsernameAttribute(
                            shortTermCredentialUsername));
            request.putAttribute(
                    AttributeFactory.createMessageIntegrityAttribute(
                            shortTermCredentialUsername));
            return true;
        }
        else
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
     */
    protected boolean completedResolvingCandidate(
            Request request,
            Response response)
    {
        if (!completedResolvingCandidate)
        {
            completedResolvingCandidate = true;
            try
            {
                if (((response == null) || !response.isSuccessResponse())
                        && (longTermCredentialSession != null))
                {
                    harvester
                        .getStunStack()
                            .getCredentialsManager()
                                .unregisterAuthority(longTermCredentialSession);
                    longTermCredentialSession = null;
                }
            }
            finally
            {
                harvester.completedResolvingCandidate(this);
            }
        }
        return completedResolvingCandidate;
    }

    /**
     * Determines whether a specific LocalCandidate is contained in the
     * list of LocalCandidates harvested for {@link #hostCandidate} by
     * this harvest.
     *
     * @param candidate the LocalCandidate to look for in the list of
     * LocalCandidates harvested for {@link #hostCandidate} by this
     * harvest
     * @return true if the list of LocalCandidates contains
     * the specified candidate; otherwise, false
     */
    protected boolean containsCandidate(LocalCandidate candidate)
    {
        if (candidate != null)
        {
            LocalCandidate[] candidates = getCandidates();

            if ((candidates != null) && (candidates.length != 0))
            {
                for (LocalCandidate c : candidates)
                {
                    if (candidate.equals(c))
                        return true;
                }
            }
        }
        return false;
    }

    /**
     * Creates new Candidates determined by a specific STUN
     * Response.
     *
     * @param response the received STUN Response
     */
    protected void createCandidates(Response response)
    {
        createServerReflexiveCandidate(response);
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
     */
    protected Message createKeepAliveMessage(LocalCandidate candidate)
        throws StunException
    {
        /*
         * We'll not be keeping a STUN Binding alive for now. If we decide to in
         * the future, we'll have to create a Binding Indication and add support
         * for sending it.
         */
        if (CandidateType.SERVER_REFLEXIVE_CANDIDATE.equals(
                candidate.getType()))
            return null;
        else
        {
            throw
                new StunException(StunException.ILLEGAL_ARGUMENT, "candidate");
        }
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
     */
    protected Request createRequestToRetry(Request request)
    {
        switch (request.getMessageType())
        {
        case Message.BINDING_REQUEST:
            return MessageFactory.createBindingRequest();
        default:
            throw new IllegalArgumentException("request.messageType");
        }
    }

    /**
     * Creates a new Request which is to be sent to
     * {@link StunCandidateHarvester#stunServer} in order to start resolving
     * {@link #hostCandidate}.
     *
     * @return a new Request which is to be sent to
     * {@link StunCandidateHarvester#stunServer} in order to start resolving
     * {@link #hostCandidate}
     */
    protected Request createRequestToStartResolvingCandidate()
    {
        return MessageFactory.createBindingRequest();
    }

    /**
     * Creates and starts the {@link #sendKeepAliveMessageThread} which is to
     * send STUN keep-alive Messages to the STUN server associated with
     * the StunCandidateHarvester of this instance in order to keep the
     * Candidates harvested by this instance alive.
     */
    private void createSendKeepAliveMessageThread()
    {
        synchronized (sendKeepAliveMessageSyncRoot)
        {
            Thread t = new SendKeepAliveMessageThread(this);
            t.setDaemon(true);
            t.setName(
                    getClass().getName() + ".sendKeepAliveMessageThread: "
                        + hostCandidate);

            boolean started = false;

            sendKeepAliveMessageThread = t;
            try
            {
                t.start();
                started = true;
            }
            finally
            {
                if (!started && (sendKeepAliveMessageThread == t))
                    sendKeepAliveMessageThread = null;
            }
        }
    }

    /**
     * Creates a ServerReflexiveCandidate using {@link #hostCandidate}
     * as its base and the XOR-MAPPED-ADDRESS attribute in
     * response for the actual TransportAddress of the new
     * candidate. If the message is malformed and/or does not contain the
     * corresponding attribute, this method simply has no effect.
     *
     * @param response the STUN Response which is supposed to contain
     * the address we should use for the new candidate
     */
    protected void createServerReflexiveCandidate(Response response)
    {
        TransportAddress addr = getMappedAddress(response);

        if (addr != null)
        {
            ServerReflexiveCandidate srvrRflxCand
                = createServerReflexiveCandidate(addr);

            if (srvrRflxCand != null)
            {
                try
                {
                    addCandidate(srvrRflxCand);
                }
                finally
                {
                    // Free srvrRflxCand if it has not been consumed.
                    if (!containsCandidate(srvrRflxCand))
                    {
                        try
                        {
                            srvrRflxCand.free();
                        }
                        catch (Exception ex)
                        {
                            if (logger.isDebugEnabled())
                            {
                                logger.warn("Failed to free ServerReflexiveCandidate: {}", srvrRflxCand, ex);
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * Creates a new ServerReflexiveCandidate instance which is to
     * represent a specific TransportAddress harvested through
     * {@link #hostCandidate} and the STUN server associated with
     * {@link #harvester}.
     *
     * @param transportAddress the TransportAddress to be represented
     * by the new ServerReflexiveCandidate instance
     * @return a new ServerReflexiveCandidate instance which represents
     * the specified TransportAddress harvested through
     * {@link #hostCandidate} and the STUN server associated with
     * {@link #harvester}
     */
    protected ServerReflexiveCandidate createServerReflexiveCandidate(
            TransportAddress transportAddress)
    {
        return
            new ServerReflexiveCandidate(
                    transportAddress,
                    hostCandidate,
                    harvester.stunServer,
                    CandidateExtendedType.STUN_SERVER_REFLEXIVE_CANDIDATE);
    }

    /**
     * Runs in {@link #sendKeepAliveMessageThread} to notify this instance that
     * sendKeepAliveMessageThread is about to exit.
     */
    private void exitSendKeepAliveMessageThread()
    {
        synchronized (sendKeepAliveMessageSyncRoot)
        {
            if (sendKeepAliveMessageThread == Thread.currentThread())
                sendKeepAliveMessageThread = null;

            /*
             * Well, if the currentThread is finishing and this instance is
             * still to send keep-alive messages, we'd better start another
             * Thread for the purpose to continue the work that the
             * currentThread was supposed to carry out.
             */
            if ((sendKeepAliveMessageThread == null)
                    && (sendKeepAliveMessageInterval
                         != SEND_KEEP_ALIVE_MESSAGE_INTERVAL_NOT_SPECIFIED))
            {
                createSendKeepAliveMessageThread();
            }
        }
    }

    /**
     * Gets the number of Candidates harvested for
     * {@link #hostCandidate} during this harvest.
     *
     * @return the number of Candidates harvested for
     * {@link #hostCandidate} during this harvest
     */
    int getCandidateCount()
    {
        return candidates.size();
    }

    /**
     * Gets the Candidates harvested for {@link #hostCandidate} during
     * this harvest.
     *
     * @return an array containing the Candidates harvested for
     * {@link #hostCandidate} during this harvest
     */
    LocalCandidate[] getCandidates()
    {
        return candidates.toArray(NO_CANDIDATES);
    }

    /**
     * Gets the TransportAddress specified in the XOR-MAPPED-ADDRESS
     * attribute of a specific Response.
     *
     * @param response the Response from which the XOR-MAPPED-ADDRESS
     * attribute is to be retrieved and its TransportAddress value is
     * to be returned
     * @return the TransportAddress specified in the XOR-MAPPED-ADDRESS
     * attribute of response
     */
    protected TransportAddress getMappedAddress(Response response)
    {
        Attribute attribute
            = response.getAttribute(Attribute.Type.XOR_MAPPED_ADDRESS);

        if(attribute instanceof XorMappedAddressAttribute)
        {
            return
                ((XorMappedAddressAttribute) attribute)
                    .getAddress(response.getTransactionID());
        }

        // old STUN servers (RFC3489) send MAPPED-ADDRESS address
        attribute
            = response.getAttribute(Attribute.Type.MAPPED_ADDRESS);

        if(attribute instanceof MappedAddressAttribute)
        {
            return
                ((MappedAddressAttribute) attribute)
                    .getAddress();
        }
        else
            return null;
    }

    /**
     * Notifies this StunCandidateHarvest that a specific STUN
     * Request has been challenged for a long-term credential (as the
     * short-term credential mechanism does not utilize challenging) in a
     * specific realm and with a specific nonce.
     *
     * @param realm the realm in which the specified STUN Request has
     * been challenged for a long-term credential
     * @param nonce the nonce with which the specified STUN Request has
     * been challenged for a long-term credential
     * @param request the STUN Request which has been challenged for a
     * long-term credential
     * @param requestTransactionID the TransactionID of
     * request because request only has it as a byte
     * array and TransactionID is required for the
     * applicationData property value
     * @return true if the challenge has been processed and this
     * StunCandidateHarvest is to continue processing STUN
     * Responses; otherwise, false
     * @throws StunException if anything goes wrong while processing the
     * challenge
     */
    private boolean processChallenge(
            byte[] realm,
            byte[] nonce,
            Request request,
            TransactionID requestTransactionID)
        throws StunException
    {
        UsernameAttribute usernameAttribute
            = (UsernameAttribute) request.getAttribute(Attribute.Type.USERNAME);

        if (usernameAttribute == null)
        {
            if (longTermCredentialSession == null)
            {
                LongTermCredential longTermCredential
                    = harvester.createLongTermCredential(this, realm);

                if (longTermCredential == null)
                {
                    // The long-term credential mechanism is not being utilized.
                    return false;
                }
                else
                {
                    longTermCredentialSession
                        = new LongTermCredentialSession(
                                longTermCredential,
                                realm);
                    harvester
                        .getStunStack()
                            .getCredentialsManager()
                                .registerAuthority(longTermCredentialSession);
                }
            }
            else
            {
                /*
                 * If we're going to use the long-term credential to retry the
                 * request, the long-term credential should be for the request
                 * in terms of realm.
                 */
                if (!longTermCredentialSession.realmEquals(realm))
                    return false;
            }
        }
        else
        {
            /*
             * If we sent a USERNAME in our request, then we had the long-term
             * credential at the time we sent the request in question.
             */
            if (longTermCredentialSession == null)
                return false;
            else
            {
                /*
                 * If we're going to use the long-term credential to retry the
                 * request, the long-term credential should be for the request
                 * in terms of username.
                 */
                if (!longTermCredentialSession.usernameEquals(
                        usernameAttribute.getUsername()))
                    return false;
                else
                {
                    // And it terms of realm, of course.
                    if (!longTermCredentialSession.realmEquals(realm))
                        return false;
                }
            }
        }

        /*
         * The nonce is either becoming known for the first time or being
         * updated after the old one has gone stale.
         */
        longTermCredentialSession.setNonce(nonce);

        Request retryRequest = createRequestToRetry(request);
        TransactionID retryRequestTransactionID = null;

        if (retryRequest != null)
        {
            if (requestTransactionID != null)
            {
                Object applicationData
                    = requestTransactionID.getApplicationData();

                if (applicationData != null)
                {
                    byte[] retryRequestTransactionIDAsBytes
                        = retryRequest.getTransactionID();

                    retryRequestTransactionID
                        = (retryRequestTransactionIDAsBytes == null)
                            ? TransactionID.createNewTransactionID()
                            : TransactionID.createTransactionID(
                                    harvester.getStunStack(),
                                    retryRequestTransactionIDAsBytes);
                    retryRequestTransactionID.setApplicationData(
                            applicationData);
                }
            }
            retryRequestTransactionID
                = sendRequest(retryRequest, false, retryRequestTransactionID);
        }
        return (retryRequestTransactionID != null);
    }

    /**
     * Notifies this StunCandidateHarvest that a specific STUN
     * Response has been received and it challenges a specific STUN
     * Request for a long-term credential (as the short-term credential
     * mechanism does not utilize challenging).
     *
     * @param response the STUN Response which has been received
     * @param request the STUN Request to which response
     * responds and which it challenges for a long-term credential
     * @return true if the challenge has been processed and this
     * StunCandidateHarvest is to continue processing STUN
     * Responses; otherwise, false
     * @param transactionID the TransactionID of response and
     * request because response and request only have
     * it as a byte array and TransactionID is required for
     * the applicationData property value
     * @throws StunException if anything goes wrong while processing the
     * challenge
     */
    private boolean processChallenge(
            Response response,
            Request request,
            TransactionID transactionID)
        throws StunException
    {
        boolean retried = false;

        if (response.getAttributeCount() > 0)
        {
            /*
             * The response SHOULD NOT contain a USERNAME or
             * MESSAGE-INTEGRITY attribute.
             */
            EnumSet<Attribute.Type> excludedResponseAttributeTypes
            = EnumSet.of(Attribute.Type.USERNAME,
                            Attribute.Type.MESSAGE_INTEGRITY);
            boolean challenge = true;
            // TODO XXX Paul - possibly where we're failing Edge since it sends a username??
            if (response.containsNoneAttributes(excludedResponseAttributeTypes))
            {
                challenge = false;
            }
            if (challenge)
            {
                // This response MUST include a REALM value.
                RealmAttribute realmAttribute
                    = (RealmAttribute) response.getAttribute(Attribute.Type.REALM);

                if (realmAttribute == null)
                {
                    challenge = false;
                }
                else
                {
                    // The response MUST include a NONCE.
                    NonceAttribute nonceAttribute
                        = (NonceAttribute)
                            response.getAttribute(Attribute.Type.NONCE);

                    if (nonceAttribute == null)
                    {
                        challenge = false;
                    }
                    else
                    {
                        retried
                            = processChallenge(
                                    realmAttribute.getRealm(),
                                    nonceAttribute.getNonce(),
                                    request,
                                    transactionID);
                    }
                }
            }
        }
        return retried;
    }

    /**
     * Notifies this StunCandidateHarvest that a specific
     * Request has either received an error Response or has
     * failed to receive any Response. Allows extenders to override and
     * process unhandled error Responses or failures. The default
     * implementation does no processing.
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
     */
    protected boolean processErrorOrFailure(
            Response response,
            Request request,
            TransactionID transactionID)
    {
        return false;
    }

    /**
     * Notifies this ResponseCollector that a transaction described by
     * the specified BaseStunMessageEvent has failed. The possible
     * reasons for the failure include timeouts, unreachable destination, etc.
     *
     * @param event the BaseStunMessageEvent which describes the failed
     * transaction and the runtime type of which specifies the failure reason
     * @see AbstractResponseCollector#processFailure(BaseStunMessageEvent)
     */
    @Override
    protected void processFailure(BaseStunMessageEvent event)
    {
        TransactionID transactionID = event.getTransactionID();

        logger.trace("A transaction expired: tranid={} localAddr={}", transactionID, hostCandidate);

        /*
         * Clean up for the purposes of the workaround which determines the STUN
         * Request to which a STUN Response responds.
         */
        Request request = requests.remove(transactionID);
        if (request == null)
        {
            Message message = event.getMessage();

            if (message instanceof Request)
                request = (Request) message;
        }

        boolean completedResolvingCandidate = true;
        try
        {
            if (processErrorOrFailure(null, request, transactionID))
                completedResolvingCandidate = false;
        }
        finally
        {
            if (completedResolvingCandidate)
                completedResolvingCandidate(request, null);
        }
    }

    /**
     * Notifies this ResponseCollector that a STUN response described
     * by the specified StunResponseEvent has been received.
     *
     * @param event the StunResponseEvent which describes the received
     * STUN response
     * @see ResponseCollector#processResponse(StunResponseEvent)
     */
    @Override
    public void processResponse(StunResponseEvent event)
    {
        TransactionID transactionID = event.getTransactionID();

        logger.trace("Received a message: tranid={} localCand={}", transactionID, hostCandidate);

        /*
         * Clean up for the purposes of the workaround which determines the STUN
         * Request to which a STUN Response responds.
         */
        requests.remove(transactionID);

        // At long last, do start handling the received STUN Response.
        Response response = event.getResponse();
        Request request = event.getRequest();
        boolean completedResolvingCandidate = true;

        try
        {
            if (response.isSuccessResponse())
            {
                EnumSet<Attribute.Type> includedRequestAttributeTypes
                = EnumSet.of(Attribute.Type.USERNAME, Attribute.Type.MESSAGE_INTEGRITY);
                /*
                 * For a request or indication message, the agent MUST
                 * include the USERNAME and MESSAGE-INTEGRITY attributes in
                 * the message.
                 */
                if (request.containsAllAttributes(includedRequestAttributeTypes))
                {
                    MessageIntegrityAttribute messageIntegrityAttribute
                    = (MessageIntegrityAttribute)
                        response.getAttribute(Attribute.Type.MESSAGE_INTEGRITY);
                    // Authentication and Message-Integrity Mechanisms
                    UsernameAttribute usernameAttribute
                    = (UsernameAttribute) request.getAttribute(Attribute.Type.USERNAME);
                    if (!harvester.getStunStack().validateMessageIntegrity(
                            messageIntegrityAttribute,
                            LongTermCredential.toString(usernameAttribute.getUsername()),
                            request.getAttribute(Attribute.Type.REALM) == null
                            && request.getAttribute(Attribute.Type.NONCE) == null,
                            event.getRawMessage()))
                    {
                        return;
                    }
                }
                else
                {
                    /*
                     * RFC 5389: If MESSAGE-INTEGRITY was absent, the response
                     * MUST be discarded, as if it was never received.
                     */
                    return;
                }
                processSuccess(response, request, transactionID);
            }
            else
            {
                ErrorCodeAttribute errorCodeAttr
                    = (ErrorCodeAttribute)
                        response.getAttribute(Attribute.Type.ERROR_CODE);

                if ((errorCodeAttr != null)
                        && (errorCodeAttr.getErrorClass() == 4))
                {
                    try
                    {
                        switch (errorCodeAttr.getErrorNumber())
                        {
                        case 1: // 401 Unauthorized
                            if (processUnauthorized(
                                    response,
                                    request,
                                    transactionID))
                                completedResolvingCandidate = false;
                            break;
                        case 38: // 438 Stale Nonce
                            if (processStaleNonce(
                                    response,
                                    request,
                                    transactionID))
                                completedResolvingCandidate = false;
                            break;
                        }
                    }
                    catch (StunException sex)
                    {
                        completedResolvingCandidate = true;
                    }
                }
                if (completedResolvingCandidate
                        && processErrorOrFailure(
                                response,
                                request,
                                transactionID))
                    completedResolvingCandidate = false;
            }
        }
        finally
        {
            if (completedResolvingCandidate)
                completedResolvingCandidate(request, response);
        }
    }

    /**
     * Handles a specific STUN error Response with error code
     * "438 Stale Nonce" to a specific STUN Request.
     *
     * @param response the received STUN error Response with error code
     * "438 Stale Nonce" which is to be handled
     * @param request the STUN Request to which response
     * responds
     * @param transactionID the TransactionID of response and
     * request because response and request only have
     * it as a byte array and TransactionID is required for
     * the applicationData property value
     * @return true if the specified STUN error response was
     * successfully handled; false, otherwise
     * @throws StunException if anything goes wrong while handling the specified
     * "438 Stale Nonce" error response
     */
    private boolean processStaleNonce(
            Response response,
            Request request,
            TransactionID transactionID)
        throws StunException
    {
        /*
         * The request MUST contain USERNAME, REALM, NONCE and MESSAGE-INTEGRITY
         * attributes.
         */
        boolean challenge = false;

        if (request.getAttributeCount() > 0)
        {
            EnumSet<Attribute.Type> includedRequestAttributeTypes
            = EnumSet.of(Attribute.Type.USERNAME,
                            Attribute.Type.REALM,
                            Attribute.Type.NONCE,
                            Attribute.Type.MESSAGE_INTEGRITY);

            if (request.containsAllAttributes(includedRequestAttributeTypes))
            {
                challenge = true;
            }
        }
        return
            (challenge && processChallenge(response, request, transactionID));
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
     */
    protected void processSuccess(
            Response response,
            Request request,
            TransactionID transactionID)
    {
        if (!completedResolvingCandidate)
            createCandidates(response);
    }

    /**
     * Handles a specific STUN error Response with error code
     * "401 Unauthorized" to a specific STUN Request.
     *
     * @param response the received STUN error Response with error code
     * "401 Unauthorized" which is to be handled
     * @param request the STUN Request to which response
     * responds
     * @param transactionID the TransactionID of response and
     * request because response and request only have
     * it as a byte array and TransactionID is required for
     * the applicationData property value
     * @return true if the specified STUN error response was
     * successfully handled; false, otherwise
     * @throws StunException if anything goes wrong while handling the specified
     * "401 Unauthorized" error response
     */
    private boolean processUnauthorized(
            Response response,
            Request request,
            TransactionID transactionID)
        throws StunException
    {
        /*
         * If the response is a challenge, retry the request with a new
         * transaction.
         */
        boolean challenge = true;

        /*
         * The client SHOULD omit the USERNAME, MESSAGE-INTEGRITY, REALM, and
         * NONCE attributes from the "First Request".
         */
        if (request.getAttributeCount() > 0)
        {
            EnumSet<Attribute.Type> excludedRequestAttributeTypes
                = EnumSet.of(Attribute.Type.USERNAME,
                            Attribute.Type.MESSAGE_INTEGRITY,
                            Attribute.Type.REALM,
                            Attribute.Type.NONCE);

            if (request.containsAnyAttributes(excludedRequestAttributeTypes))
            {
                challenge = false;
            }
        }

        return
            (challenge && processChallenge(response, request, transactionID));
    }

    /**
     * Runs in {@link #sendKeepAliveMessageThread} and sends STUN
     * keep-alive Messages to the STUN server associated with the
     * StunCandidateHarvester of this instance.
     *
     * @return true if the method is to be invoked again; otherwise,
     * false
     */
    private boolean runInSendKeepAliveMessageThread()
    {
        synchronized (sendKeepAliveMessageSyncRoot)
        {
            // Since we're going to #wait, make sure we're not canceled yet.
            if (sendKeepAliveMessageThread != Thread.currentThread())
                return false;
            if (sendKeepAliveMessageInterval
                    == SEND_KEEP_ALIVE_MESSAGE_INTERVAL_NOT_SPECIFIED)
            {
                return false;
            }

            // Determine the amount of milliseconds that we'll have to #wait.
            long timeout;

            if (sendKeepAliveMessageTime == -1)
            {
                /*
                 * If we're just starting, don't just go and send a new STUN
                 * keep-alive message but rather wait for the whole interval.
                 */
                timeout = sendKeepAliveMessageInterval;
            }
            else
            {
                timeout
                    = sendKeepAliveMessageTime
                        + sendKeepAliveMessageInterval
                        - System.currentTimeMillis();
            }
            // At long last, #wait if necessary.
            if (timeout > 0)
            {
                try
                {
                    sendKeepAliveMessageSyncRoot.wait(timeout);
                }
                catch (InterruptedException iex)
                {
                }
                /*
                 * Apart from being the time to send the STUN keep-alive
                 * message, it could be that we've experienced a spurious
                 * wake-up or that we've been canceled.
                 */
                return true;
            }
        }

        sendKeepAliveMessageTime = System.currentTimeMillis();
        try
        {
            sendKeepAliveMessage();
        }
        catch (StunException sex)
        {
            if (logger.isInfoEnabled()) {
                logger.warn("Failed to send STUN keep-alive message", sex);
            }
        }
        return true;
    }

    /**
     * Sends a new STUN Message to the STUN server associated with the
     * StunCandidateHarvester of this instance in order to keep a
     * LocalCandidate harvested by this instance alive.
     *
     * @throws StunException if anything goes wrong while sending a new
     * keep-alive STUN Message
     */
    protected void sendKeepAliveMessage()
        throws StunException
    {
        for (LocalCandidate candidate : getCandidates())
            if (sendKeepAliveMessage(candidate))
                break;
    }

    /**
     * Sends a new STUN Message to the STUN server associated with the
     * StunCandidateHarvester of this instance in order to keep a
     * specific LocalCandidate alive.
     *
     * @param candidate the LocalCandidate to send a new keep-alive
     * STUN Message for
     * @return true if a new STUN Message was sent to the
     * STUN server associated with the StunCandidateHarvester of this
     * instance or false if the STUN kee-alive functionality was not
     * been used for the specified candidate
     * @throws StunException if anything goes wrong while sending the new
     * keep-alive STUN Message for the specified candidate
     */
    protected boolean sendKeepAliveMessage(LocalCandidate candidate)
        throws StunException
    {
        Message keepAliveMessage = createKeepAliveMessage(candidate);

        /*
         * The #createKeepAliveMessage method javadoc says it returns null when
         * the STUN keep-alive functionality of this StunCandidateHarvest is to
         * not be utilized.
         */
        if (keepAliveMessage == null)
        {
            return false;
        }
        else if (keepAliveMessage instanceof Request)
        {
            return
                (sendRequest((Request) keepAliveMessage, false, null) != null);
        }
        else
        {
            throw new StunException(
                    StunException.ILLEGAL_ARGUMENT,
                    "Failed to create keep-alive STUN message for candidate: "
                            + candidate);
        }
    }

    /**
     * Sends a specific Request to the STUN server associated with this
     * StunCandidateHarvest.
     *
     * @param request the Request to send to the STUN server associated
     * with this StunCandidateHarvest
     * @param firstRequest true if the specified request
     * should be sent as the first request in the terms of STUN; otherwise,
     * false
     * @return the TransactionID of the STUN client transaction through
     * which the specified Request has been sent to the STUN server
     * associated with this StunCandidateHarvest
     * @param transactionID the TransactionID of request
     * because request only has it as a byte array and
     * TransactionID is required for the applicationData
     * property value
     * @throws StunException if anything goes wrong while sending the specified
     * Request to the STUN server associated with this
     * StunCandidateHarvest
     */
    protected TransactionID sendRequest(
            Request request,
            boolean firstRequest,
            TransactionID transactionID)
        throws StunException
    {
        logger.warn("sendRequest {}", transactionID);
        if (!firstRequest && (longTermCredentialSession != null))
            longTermCredentialSession.addAttributes(request);

        StunStack stunStack = harvester.getStunStack();
        TransportAddress stunServer = harvester.stunServer;
        TransportAddress hostCandidateTransportAddress
            = hostCandidate.getTransportAddress();

        if (transactionID == null)
        {
            byte[] transactionIDAsBytes = request.getTransactionID();
            logger.warn("transactionIDAsBytes {}", (transactionIDAsBytes != null ? transactionIDAsBytes.length : null));

            transactionID
                = (transactionIDAsBytes == null)
                    ? TransactionID.createNewTransactionID()
                    : TransactionID.createTransactionID(
                            harvester.getStunStack(),
                            transactionIDAsBytes);
        }
        logger.warn("Request transaction id: {} rfc3489: {}", transactionID.toString(), transactionID.isRFC3489Compatible());
        try
        {
            transactionID
                = stunStack
                    .sendRequest(
                        request,
                        stunServer,
                        hostCandidateTransportAddress,
                        this,
                        transactionID);
        }
        catch (IllegalArgumentException iaex)
        {
            if (logger.isInfoEnabled())
            {
                logger.info("Failed to send "
                            + request
                            + " through " + hostCandidateTransportAddress
                            + " to " + stunServer,
                        iaex);
            }
            throw new StunException(
                    StunException.ILLEGAL_ARGUMENT,
                    iaex.getMessage(),
                    iaex);
        }
        catch (IOException ioex)
        {
            if (logger.isInfoEnabled())
            {
                logger.info("Failed to send "
                            + request
                            + " through " + hostCandidateTransportAddress
                            + " to " + stunServer,
                        ioex);
            }
            throw new StunException(
                    StunException.NETWORK_ERROR,
                    ioex.getMessage(),
                    ioex);
        }

        requests.put(transactionID, request);
        return transactionID;
    }

    /**
     * Sets the interval in milliseconds at which a new STUN keep-alive message
     * is to be sent to the STUN server associated with the
     * StunCandidateHarvester of this instance in order to keep one of
     * the Candidates harvested by this instance alive.
     *
     * @param sendKeepAliveMessageInterval the interval in milliseconds at which
     * a new STUN keep-alive message is to be sent to the STUN server associated
     * with the StunCandidateHarvester of this instance in order to
     * keep one of the Candidates harvested by this instance alive or
     * {@link #SEND_KEEP_ALIVE_MESSAGE_INTERVAL_NOT_SPECIFIED} if the keep-alive
     * functionality is to not be utilized
     */
    protected void setSendKeepAliveMessageInterval(
            long sendKeepAliveMessageInterval)
    {
        if ((sendKeepAliveMessageInterval
                    != SEND_KEEP_ALIVE_MESSAGE_INTERVAL_NOT_SPECIFIED)
                && (sendKeepAliveMessageInterval < 1))
            throw new IllegalArgumentException("sendKeepAliveMessageInterval");

        synchronized (sendKeepAliveMessageSyncRoot)
        {
            this.sendKeepAliveMessageInterval = sendKeepAliveMessageInterval;
            if (sendKeepAliveMessageThread == null)
            {
                if (this.sendKeepAliveMessageInterval
                        != SEND_KEEP_ALIVE_MESSAGE_INTERVAL_NOT_SPECIFIED)
                    createSendKeepAliveMessageThread();
            }
            else
                sendKeepAliveMessageSyncRoot.notify();
        }
    }

    /**
     * Starts the harvesting of Candidates to be performed for
     * {@link #hostCandidate}.
     *
     * @return true if this StunCandidateHarvest has started
     * the harvesting of Candidates for {@link #hostCandidate};
     * otherwise, false
     * @throws Exception if anything goes wrong while starting the harvesting of
     * Candidates to be performed for {@link #hostCandidate}
     */
    boolean startResolvingCandidate()
        throws Exception
    {
        Request requestToStartResolvingCandidate;

        if (!completedResolvingCandidate
                && ((requestToStartResolvingCandidate
                            = createRequestToStartResolvingCandidate())
                        != null))
        {
            // Short-Term Credential Mechanism
            addShortTermCredentialAttributes(requestToStartResolvingCandidate);

            sendRequest(requestToStartResolvingCandidate, true, null);
            return true;
        }
        else
            return false;
    }

    /**
     * Close the harvest.
     */
    public void close()
    {
        // stop keep alive thread
        setSendKeepAliveMessageInterval(
            SEND_KEEP_ALIVE_MESSAGE_INTERVAL_NOT_SPECIFIED);
    }

    /**
     * Sends STUN keep-alive Messages to the STUN server associated
     * with the StunCandidateHarvester of this instance.
     *
     * @author Lyubomir Marinov
     */
    private static class SendKeepAliveMessageThread
        extends Thread
    {
        /**
         * The StunCandidateHarvest which has initialized this
         * instance. The StunCandidateHarvest is referenced by a
         * WeakReference in an attempt to reduce the risk that the
         * Thread may live regardless of the fact that the specified
         * StunCandidateHarvest may no longer be reachable.
         */
        private final WeakReference<StunCandidateHarvest> harvest;

        /**
         * Initializes a new SendKeepAliveMessageThread instance with a
         * specific StunCandidateHarvest.
         *
         * @param harvest the StunCandidateHarvest to initialize the
         * new instance with
         */
        public SendKeepAliveMessageThread(StunCandidateHarvest harvest)
        {
            this.harvest = new WeakReference<>(harvest);
        }

        @Override
        public void run()
        {
            try
            {
                do
                {
                    StunCandidateHarvest harvest = this.harvest.get();

                    if ((harvest == null)
                            || !harvest.runInSendKeepAliveMessageThread())
                    {
                        break;
                    }
                }
                while (true);
            }
            finally
            {
                StunCandidateHarvest harvest = this.harvest.get();

                if (harvest != null)
                    harvest.exitSendKeepAliveMessageThread();
            }
        }
    }
}
