/* See LICENSE.md for license information */
package org.ice4j;

import java.util.Queue;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.TimeUnit;

import junit.framework.TestCase;

import org.ice4j.message.MessageFactory;
import org.ice4j.message.Request;
import org.ice4j.message.Response;
import org.ice4j.socket.IceSocketWrapper;
import org.ice4j.socket.IceUdpSocketWrapper;
import org.ice4j.stack.RequestListener;
import org.ice4j.stack.StunStack;
import org.junit.After;
import org.junit.Before;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import test.PortUtil;

/**
 * Test event dispatching for both client and server.
 *`
 * @author Emil Ivov
 */
public class MessageEventDispatchingTest extends TestCase {

    private final static Logger logger = LoggerFactory.getLogger(MessageEventDispatchingTest.class);

    /**
     * The stack that we are using for the tests.
     */
    StunStack stunStack;

    /**
     * The address of the client.
     */
    TransportAddress clientAddress;

    /**
     * The Address of the server.
     */
    TransportAddress serverAddress;

    /**
     * The address of the second server.
     */
    TransportAddress serverAddress2;

    /**
     * The socket that the client is using.
     */
    IceSocketWrapper clientSock;

    /**
     * The socket that the server is using
     */
    IceSocketWrapper serverSock;

    /**
     * The second server socket.
     */
    IceSocketWrapper serverSock2;

    /**
     * The request that we will be sending in this test.
     */
    Request bindingRequest;

    /**
     * The response that we will be sending in response to the above request.
     */
    Response bindingResponse;

    /**
     * The request collector that we use to wait for requests.
     */
    PlainRequestCollector requestCollector;

    /**
     * The responses collector that we use to wait for responses.
     */
    PlainResponseCollector responseCollector;

    /**
     * junit setup method.
     *
     * @throws Exception if anything goes wrong.
     */
    @Before
    protected void setUp() throws Exception {
        super.setUp();
        logger.info("-------------------------------------------\nSettting up {}", getClass().getName());
        clientAddress = new TransportAddress("127.0.0.1", PortUtil.getPort(), Transport.UDP);
        serverAddress = new TransportAddress("127.0.0.1", PortUtil.getPort(), Transport.UDP);
        serverAddress2 = new TransportAddress("127.0.0.1", PortUtil.getPort(), Transport.UDP);
        stunStack = new StunStack();
        // create the wrappers
        clientSock = new IceUdpSocketWrapper(clientAddress);
        serverSock = new IceUdpSocketWrapper(serverAddress);
        serverSock2 = new IceUdpSocketWrapper(serverAddress2);
        // add wrappers to the stack
        stunStack.addSocket(clientSock);
        stunStack.addSocket(serverSock);
        stunStack.addSocket(serverSock2);
        // create binding request and response
        bindingRequest = MessageFactory.createBindingRequest();
        bindingResponse = MessageFactory.create3489BindingResponse(clientAddress, clientAddress, serverAddress);
        // create collectors
        requestCollector = new PlainRequestCollector();
        responseCollector = new PlainResponseCollector();
    }

    /**
     * junit tear down method.
     *
     * @throws Exception if anything goes wrong.
     */
    @After
    protected void tearDown() throws Exception {
        stunStack.removeSocket(clientAddress);
        stunStack.removeSocket(serverAddress);
        stunStack.removeSocket(serverAddress2);
        clientSock.close();
        serverSock.close();
        serverSock2.close();
        requestCollector = null;
        responseCollector = null;
        super.tearDown();
    }

    /**
     * Test timeout events.
     *
     * @throws Exception upon a stun failure
     */
    public void testClientTransactionTimeouts() throws Exception {
        String oldRetransValue = System.getProperty(StackProperties.MAX_CTRAN_RETRANSMISSIONS);
        System.setProperty(StackProperties.MAX_CTRAN_RETRANSMISSIONS, "1");
        stunStack.sendRequest(bindingRequest, serverAddress, clientAddress, responseCollector);
        responseCollector.waitForTimeout();
        assertEquals("No timeout was produced upon expiration of a client transaction", 1, responseCollector.receivedResponses.size());
        assertEquals("No timeout was produced upon expiration of a client transaction", "timeout", responseCollector.receivedResponses.remove());
        //restore the retransmissions prop in case others are counting on defaults.
        if (oldRetransValue != null)
            System.getProperty(StackProperties.MAX_CTRAN_RETRANSMISSIONS, oldRetransValue);
        else
            System.clearProperty(StackProperties.MAX_CTRAN_RETRANSMISSIONS);
    }

    /**
     * Test reception of Message events.
     *
     * @throws java.lang.Exception upon any failure
     */
    public void testEventDispatchingUponIncomingRequests() throws Exception {
        //prepare to listen
        stunStack.addRequestListener(requestCollector);
        //send
        stunStack.sendRequest(bindingRequest, serverAddress, clientAddress, responseCollector);
        //wait for retransmissions
        requestCollector.waitForRequest();
        //verify
        assertTrue("No MessageEvents have been dispatched", requestCollector.receivedRequests.size() == 1);
    }

    /**
     * Test that reception of Message events is only received for accesspoints
     * that we have been registered for.
     *
     * @throws java.lang.Exception upon any failure
     */
    public void testSelectiveEventDispatchingUponIncomingRequests() throws Exception {
        // prepare to listen
        stunStack.addRequestListener(serverAddress, requestCollector);
        PlainRequestCollector requestCollector2 = new PlainRequestCollector();
        stunStack.addRequestListener(serverAddress2, requestCollector2);
        // send
        stunStack.sendRequest(bindingRequest, serverAddress2, clientAddress, responseCollector);
        // wait for retransmissions
        requestCollector.waitForRequest();
        requestCollector2.waitForRequest();
        // verify
        assertTrue("A MessageEvent was received by a non-interested selective listener", requestCollector.receivedRequests.size() == 0);
        assertTrue("No MessageEvents have been dispatched for a selective listener", requestCollector2.receivedRequests.size() == 1);
    }

    /**
     * Makes sure that we receive response events.
     * @throws Exception if we screw up.
     */
    public void testServerResponseRetransmissions() throws Exception {
        // prepare to listen
        stunStack.addRequestListener(serverAddress, requestCollector);
        // send
        stunStack.sendRequest(bindingRequest, serverAddress, clientAddress, responseCollector);
        // wait for the message to arrive
        requestCollector.waitForRequest();
        Queue<StunMessageEvent> reqs = requestCollector.receivedRequests;
        assertFalse(reqs.isEmpty());
        StunMessageEvent evt = reqs.remove();
        byte[] tid = evt.getMessage().getTransactionID();
        stunStack.sendResponse(tid, bindingResponse, serverAddress, clientAddress);
        // wait for retransmissions
        responseCollector.waitForResponse();
        // verify that we got the response.
        assertTrue("There were no retransmissions of a binding response", responseCollector.receivedResponses.size() == 1);
    }

    /**
     * A utility class we use to collect incoming requests.
     */
    private class PlainRequestCollector implements RequestListener {
        /** all requests we've received so far. */
        public final BlockingDeque<StunMessageEvent> receivedRequests = new LinkedBlockingDeque<>();

        /**
         * Stores incoming requests.
         *
         * @param evt the event containing the incoming request.
         */
        public void processRequest(StunMessageEvent evt) {
            receivedRequests.offer(evt);
        }

        public void waitForRequest() {
            try {
                StunMessageEvent evt = receivedRequests.poll(50L, TimeUnit.MILLISECONDS);
                if (evt != null) {
                    // put it back on the head
                    receivedRequests.addFirst(evt);
                }
            } catch (InterruptedException e) {
            }
        }
    }

    /**
     * A utility class to collect incoming responses.
     */
    private static class PlainResponseCollector extends AbstractResponseCollector {

        public final BlockingDeque<Object> receivedResponses = new LinkedBlockingDeque<>();

        /**
         * Notifies this ResponseCollector that a transaction described by
         * the specified BaseStunMessageEvent has failed. The possible
         * reasons for the failure include timeouts, unreachable destination, etc.
         *
         * @param event the BaseStunMessageEvent which describes the failed
         * transaction and the runtime type of which specifies the failure reason
         * @see AbstractResponseCollector#processFailure(BaseStunMessageEvent)
         */
        protected void processFailure(BaseStunMessageEvent event) {
            String receivedResponse;
            if (event instanceof StunFailureEvent) {
                receivedResponse = "unreachable";
            } else if (event instanceof StunTimeoutEvent) {
                receivedResponse = "timeout";
            } else {
                receivedResponse = "failure";
            }
            receivedResponses.offer(receivedResponse);
        }

        /**
         * Stores incoming responses.
         *
         * @param response a StunMessageEvent which describes the
         * received STUN Response
         */
        public void processResponse(StunResponseEvent response) {
            receivedResponses.offer(response);
        }

        /**
         * Waits for a short period of time for a response to arrive
         */
        public void waitForResponse() {
            try {
                Object obj = receivedResponses.poll(50L, TimeUnit.MILLISECONDS);
                if (obj != null) {
                    receivedResponses.addFirst(obj);
                }
            } catch (InterruptedException e) {
            }
        }

        /**
         * Waits for a long period of time for a timeout trigger to fire.
         */
        public void waitForTimeout() {
            try {
                Object obj = receivedResponses.poll(7000L, TimeUnit.MILLISECONDS);
                if (obj != null) {
                    receivedResponses.addFirst(obj);
                }
            } catch (InterruptedException e) {
            }
        }
    }
}
