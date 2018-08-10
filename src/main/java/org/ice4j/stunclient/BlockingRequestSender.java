/* See LICENSE.md for license information */
package org.ice4j.stunclient;

import java.io.IOException;
import java.util.concurrent.SynchronousQueue;

import org.ice4j.AbstractResponseCollector;
import org.ice4j.BaseStunMessageEvent;
import org.ice4j.StunException;
import org.ice4j.StunMessageEvent;
import org.ice4j.StunResponseEvent;
import org.ice4j.TransportAddress;
import org.ice4j.message.Request;
import org.ice4j.stack.StunStack;
import org.ice4j.stack.TransactionID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A utility used to flatten the multi-thread architecture of the Stack and execute the discovery process in a synchronized manner. Roughly what
 * happens here is:
 * <code>
 * ApplicationThread:
 *     sendMessage()
 *        wait();
 *
 * StackThread:
 *     processMessage/Timeout()
 *     {
 *          saveMessage();
 *          notify();
 *     }
 *</code>
 *
 * @author Emil Ivov
 * @author Lubomir Marinov
 * @author Aakash Garg
 * @author Paul Gregoire
 */
public class BlockingRequestSender extends AbstractResponseCollector {

    private static final Logger logger = LoggerFactory.getLogger(BlockingRequestSender.class);

    /**
     * The stack that we are using to send requests through.
     */
    private final StunStack stunStack;

    /**
     * The transport address that we are bound on.
     */
    private final TransportAddress localAddress;

    /**
     * The StunMessageEvent that contains the response matching our request.
     */
    private StunMessageEvent responseEvent;

    /**
     * Blocking synchronous queue.
     */
    private final SynchronousQueue<TransactionID> syncQueue = new SynchronousQueue<>();

    /**
     * Creates a new request sender.
     * 
     * @param stunStack the stack that the sender should send requests through
     * @param localAddress the TransportAddress that requests should be leaving from
     */
    public BlockingRequestSender(StunStack stunStack, TransportAddress localAddress) {
        this.stunStack = stunStack;
        this.localAddress = localAddress;
    }

    /**
     * Returns the local Address on which this Blocking Request Sender is bound to.
     *
     * @return the localAddress of this RequestSender
     */
    public TransportAddress getLocalAddress() {
        return localAddress;
    }

    /**
     * Notifies this ResponseCollector that a transaction described by the specified BaseStunMessageEvent has failed. The possible
     * reasons for the failure include timeouts, unreachable destination, etc. Notifies the discoverer so that it may resume.
     *
     * @param event the BaseStunMessageEvent which describes the failed transaction and the runtime type of which specifies the failure reason
     * @see AbstractResponseCollector#processFailure(BaseStunMessageEvent)
     */
    @Override
    protected void processFailure(BaseStunMessageEvent event) {
        logger.warn("processFailure: {}", event);
        // get the tx id and store in the sync queue
        TransactionID txId = event.getTransactionID();
        try {
            syncQueue.put(txId);
        } catch (Throwable t) {
            logger.warn("Transaction failure: {}", txId, t);
        }
    }

    /**
     * Saves the message event and notifies the discoverer thread so that it may resume.
     * 
     * @param event the newly arrived message event
     */
    @Override
    public void processResponse(StunResponseEvent event) {
        logger.debug("processResponse: {}", event);
        // get the tx id and store in the sync queue
        TransactionID txId = event.getTransactionID();
        try {
            syncQueue.put(txId);
            responseEvent = event;
        } catch (Throwable t) {
            logger.warn("Transaction exception: {}", txId, t);
        }
    }

    /**
     * Sends the specified request and blocks until a response has been received or the request transaction has timed out.
     * 
     * @param request the request to send
     * @param serverAddress the request destination address
     * @return the event encapsulating the response or null if no response has been received
     *
     * @throws IOException  if an error occurs while sending message bytes through the network socket
     * @throws IllegalArgumentException if the apDescriptor references an access point that had not been installed
     * @throws StunException if message encoding fails
     */
    public StunMessageEvent sendRequestAndWaitForResponse(Request request, TransportAddress serverAddress) throws StunException, IOException {
        // send the request
        stunStack.sendRequest(request, serverAddress, localAddress, BlockingRequestSender.this);
        TransactionID txId = null;
        try {
            // causes the blocking of this thread
            txId = syncQueue.take();
            if (logger.isDebugEnabled()) {
                if (txId.equals(request.getTransactionID())) {
                    logger.debug("Transaction ids match");
                }
            }
        } catch (Throwable t) {
            logger.warn("Request exception: {}", txId, t);
        }
        StunMessageEvent res = responseEvent;
        // prepare for next message
        responseEvent = null;
        return res;
    }

    /**
     * Sends the specified request and blocks until a response has been received or the request transaction has timed out with given transactionID.
     * 
     * @param request the request to send
     * @param serverAddress the request destination address
     * @param txId the TransactionID to set for this request
     * @return the event encapsulating the response or null if no response has been received
     *
     * @throws IOException if an error occurs while sending message bytes through the network socket
     * @throws IllegalArgumentException if the apDescriptor references an access point that had not been installed
     * @throws StunException if message encoding fails
     */
    public StunMessageEvent sendRequestAndWaitForResponse(Request request, TransportAddress serverAddress, TransactionID txId) throws StunException, IOException {
        // send the request
        stunStack.sendRequest(request, serverAddress, localAddress, BlockingRequestSender.this, txId);
        try {
            // causes the blocking of this thread
            TransactionID queuedTxId = syncQueue.take();
            if (logger.isDebugEnabled()) {
                if (queuedTxId.equals(txId)) {
                    logger.debug("Transaction ids match");
                }
            }
        } catch (Throwable t) {
            logger.warn("Request exception: {}", txId, t);
        }
        StunMessageEvent res = responseEvent;
        // prepare for next message
        responseEvent = null;
        return res;
    }
}
