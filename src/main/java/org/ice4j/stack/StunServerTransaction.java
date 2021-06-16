/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal. Copyright @ 2015 Atlassian Pty Ltd Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or
 * agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under the License.
 */
package org.ice4j.stack;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import org.ice4j.StunException;
import org.ice4j.TransportAddress;
import org.ice4j.message.Response;

/**
 * A STUN client retransmits requests as specified by the protocol.
 *
 * Once formulated and sent, the client sends the Binding Request.  Reliability
 * is accomplished through request retransmissions.  The ClientTransaction
 * retransmits the request starting with an interval of 100ms, doubling
 * every retransmit until the interval reaches 1.6s.  Retransmissions
 * continue with intervals of 1.6s until a response is received, or a
 * total of 9 requests have been sent. If no response is received by 1.6
 * seconds after the last request has been sent, the client SHOULD
 * consider the transaction to have failed. In other words, requests
 * would be sent at times 0ms, 100ms, 300ms, 700ms, 1500ms, 3100ms,
 * 4700ms, 6300ms, and 7900ms. At 9500ms, the client considers the
 * transaction to have failed if no response has been received.
 *
 * A server transaction is therefore responsible for retransmitting the same
 * response that was saved for the original request, and not let any
 * retransmissions go through to the user application.
 *
 * @author Emil Ivov
 */
public class StunServerTransaction {
    /**
     * The time that we keep server transactions active.
     */
    static final long LIFETIME = 9500L;

    /**
     * The StunStack that created us.
     */
    private final StunStack stunStack;

    /**
     * The address that we are sending responses to.
     */
    private TransportAddress responseDestination;

    /**
     * The address that we are receiving requests from.
     */
    private final TransportAddress requestSource;

    /**
     * The response sent in response to the request.
     */
    private Response response;

    /**
     * The TransportAddress that we received our request on.
     */
    private final TransportAddress localListeningAddress;

    /**
     * The TransportAddress we use when sending responses
     */
    private TransportAddress localSendingAddress;

    /**
     * The id of the transaction.
     */
    private final TransactionID transactionID;

    /**
     * The time in milliseconds when the next retransmission should follow.
     */
    private AtomicLong expirationTime = new AtomicLong(Long.MAX_VALUE);

    /**
     * Determines whether or not the transaction has expired.
     */
    private AtomicBoolean expired = new AtomicBoolean(false);

    /**
     * Determines whether or not the transaction is in a retransmitting state. In other words whether a response has already been sent once to the
     * transaction request.
     */
    private boolean isRetransmitting;

    /**
     * Creates a server transaction
     * @param stunStack the stack that created us
     * @param tranID the transaction id contained by the request that was the cause for this transaction
     * @param localListeningAddress the TransportAddress that this transaction is receiving requests on
     * @param requestSource the TransportAddress that this transaction is receiving requests from
     */
    public StunServerTransaction(StunStack stunStack, TransactionID tranID, TransportAddress localListeningAddress, TransportAddress requestSource) {
        this.stunStack = stunStack;
        this.transactionID = tranID;
        this.localListeningAddress = localListeningAddress;
        this.requestSource = requestSource;
    }

    /**
     * Start the transaction. This launches the count down to the moment the transaction would expire.
     */
    public void start() {
        if (!expirationTime.compareAndSet(Long.MAX_VALUE, (System.currentTimeMillis() + LIFETIME))) {
            throw new IllegalStateException("StunServerTransaction " + getTransactionID() + " has already been started!");
        }
    }

    /**
     * Sends the specified response through the <code>sendThrough</code> NetAccessPoint descriptor to the specified destination and changes
     * the transaction's state to retransmitting.
     *
     * @param response the response to send the transaction to.
     * @param sendThrough the local address through which responses are to be sent
     * @param sendTo the destination for responses of this transaction
     * @throws IOException  if an error occurs while sending message bytes through the network socket
     * @throws IllegalArgumentException if the apDescriptor references an access point that had not been installed
     * @throws StunException if message encoding fails
     */
    public void sendResponse(Response response, TransportAddress sendThrough, TransportAddress sendTo) throws StunException, IOException, IllegalArgumentException {
        if (!isRetransmitting) {
            this.response = response;
            // the transaction id might already have been set, but its our job to make sure of that
            response.setTransactionID(transactionID.getBytes());
            this.localSendingAddress = sendThrough;
            this.responseDestination = sendTo;
        }
        isRetransmitting = true;
        retransmitResponse();
    }

    /**
     * Retransmits the response that was originally sent to the request that caused this transaction.
     *
     * @throws IOException  if an error occurs while sending message bytes through the network socket
     * @throws IllegalArgumentException if the apDescriptor references an access point that had not been installed
     * @throws StunException if message encoding fails
     */
    protected void retransmitResponse() throws StunException, IOException, IllegalArgumentException {
        // don't retransmit if we are expired or if the user application hasn't yet transmitted a first response
        if (isExpired() || !isRetransmitting) {
            return;
        }
        stunStack.getNetAccessManager().sendMessage(response, localSendingAddress, responseDestination);
    }

    /**
     * Cancels the transaction. Once this method is called the transaction is considered terminated and will stop retransmissions.
     */
    public void expire() {
        expired.compareAndSet(false, true);
        // StunStack has a background Thread running with the purpose of removing expired StunServerTransactions.
    }

    /**
     * Determines whether this StunServerTransaction is expired now.
     *
     * @return true if this StunServerTransaction is expired now; otherwise, false
     */
    public boolean isExpired() {
        return isExpired(System.currentTimeMillis());
    }

    /**
     * Determines whether this StunServerTransaction will be expired at a specific point in time.
     *
     * @param now the time in milliseconds at which the expired state of this StunServerTransaction is to be returned
     * @return true if this StunServerTransaction will be expired at the specified point in time; otherwise, false
     */
    public boolean isExpired(long now) {
        if (expirationTime.get() < now && expired.compareAndSet(false, true)) {
            // we've expired and expired is set as such
        }
        return expired.get();
    }

    /**
     * Returns the ID of the current transaction.
     *
     * @return the ID of the transaction.
     */
    public TransactionID getTransactionID() {
        return transactionID;
    }

    /**
     * Specifies whether this server transaction is in the retransmitting state.
     * Or in other words - has it already sent a first response or not?
     *
     * @return true if this transaction is still retransmitting and false otherwise
     */
    public boolean isRetransmitting() {
        return isRetransmitting;
    }

    /**
     * Returns the local TransportAddress that this transaction is sending responses from.
     *
     * @return the local TransportAddress that this transaction is sending responses from
     */
    public TransportAddress getSendingAddress() {
        return localSendingAddress;
    }

    /**
     * Returns the remote TransportAddress that this transaction is
     * receiving requests from.
     *
     * @return the remote TransportAddress that this transaction is
     * receiving requests from.
     */
    public TransportAddress getResponseDestinationAddress() {
        return responseDestination;
    }

    /**
     * Returns the local TransportAddress that this transaction is
     * receiving requests on.
     *
     * @return the local TransportAddress that this transaction is
     * receiving requests on.
     */
    public TransportAddress getLocalListeningAddress() {
        return localListeningAddress;
    }

    /**
     * Returns the remote TransportAddress that this transaction is
     * receiving requests from.
     *
     * @return the remote TransportAddress that this transaction is
     * receiving requests from.
     */
    public TransportAddress getRequestSourceAddress() {
        return requestSource;
    }

    /**
     * Returns the Response that the StunStack has sent
     * through this transaction or null if no Response has
     * been sent yet.
     *
     * @return the Response that the StunStack has sent
     * through this transaction or null if no Response has
     * been sent yet.
     */
    protected Response getResponse() {
        return response;
    }

}
