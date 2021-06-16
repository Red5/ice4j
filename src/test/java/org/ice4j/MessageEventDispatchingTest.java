/* See LICENSE.md for license information */
package org.ice4j;

import java.util.Vector;

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
        // a non-controlling / passive stun (server) needs to be bound so it can receive
        //IceUdpTransport.getInstance().registerStackAndSocket(stunStack, serverSock);
        //IceUdpTransport.getInstance().registerStackAndSocket(stunStack, serverSock2);
        // add wrappers to the stack
        stunStack.addSocket(clientSock, clientSock.getRemoteTransportAddress(), false);
        stunStack.addSocket(serverSock, serverSock.getRemoteTransportAddress(), true); // do socket binding
        stunStack.addSocket(serverSock2, serverSock2.getRemoteTransportAddress(), true); // do socket binding
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
        stunStack.removeSocket(clientSock.getId(), clientAddress);
        stunStack.removeSocket(serverSock.getId(), serverAddress);
        stunStack.removeSocket(serverSock2.getId(), serverAddress2);
        clientSock.close();
        serverSock.close();
        serverSock2.close();
        requestCollector = null;
        responseCollector = null;
        //IceUdpTransport.getInstance().stop();
        super.tearDown();
    }

    /**
     * Test timeout events.
     *
     * @throws Exception upon a stun failure
     */
    public void testClientTransactionTimeouts() throws Exception {
        logger.info("----------------------------------------\ntestClientTransactionTimeouts");
        String oldRetransValue = System.getProperty(StackProperties.MAX_CTRAN_RETRANSMISSIONS);
        System.setProperty(StackProperties.MAX_CTRAN_RETRANSMISSIONS, "1");
        stunStack.sendRequest(bindingRequest, serverAddress, clientAddress, responseCollector);
        responseCollector.waitForTimeout();

        assertEquals("No timeout was produced upon expiration of a client transaction", responseCollector.receivedResponses.size(), 1);

        assertEquals("No timeout was produced upon expiration of a client transaction", responseCollector.receivedResponses.get(0), "timeout");

        //restore the retransmissions prop in case others are counting on
        //defaults.
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
        logger.info("----------------------------------------\ntestEventDispatchingUponIncomingRequests");
        //prepare to listen
        stunStack.addRequestListener(requestCollector);
        //stunStack.addRequestListener(clientAddress, requestCollector);
        logger.info("server/to: {} client/from: {}", serverAddress, clientAddress);
        //send
        stunStack.sendRequest(bindingRequest, serverAddress, clientAddress, responseCollector);
        //wait for retransmissions
        requestCollector.waitForRequest();
        //verify
        assertTrue("No MessageEvents have been dispatched", requestCollector.receivedRequests.size() == 1);
    }

    /**
     * Test that reception of Message events is only received for access points
     * that we have been registered for.
     *
     * @throws java.lang.Exception upon any failure
     */
    public void testSelectiveEventDispatchingUponIncomingRequests() throws Exception {
        logger.info("----------------------------------------\ntestSelectiveEventDispatchingUponIncomingRequests");
        //prepare to listen
        stunStack.addRequestListener(serverAddress, requestCollector);

        PlainRequestCollector requestCollector2 = new PlainRequestCollector();
        stunStack.addRequestListener(serverAddress2, requestCollector2);

        //send
        stunStack.sendRequest(bindingRequest, serverAddress2, clientAddress, responseCollector);
        //wait for retransmissions
        requestCollector.waitForRequest();
        requestCollector2.waitForRequest();

        //verify
        assertTrue("A MessageEvent was received by a non-interested selective listener", requestCollector.receivedRequests.size() == 0);
        assertTrue("No MessageEvents have been dispatched for a selective listener", requestCollector2.receivedRequests.size() == 1);
    }

    /**
     * Makes sure that we receive response events.
     * @throws Exception if we screw up.
     */
    public void testServerResponseRetransmissions() throws Exception {
        logger.info("----------------------------------------\ntestServerResponseRetransmissions");
        //prepare to listen
        stunStack.addRequestListener(serverAddress, requestCollector);
        //send
        stunStack.sendRequest(bindingRequest, serverAddress, clientAddress, responseCollector);

        //wait for the message to arrive
        requestCollector.waitForRequest();

        StunMessageEvent evt = requestCollector.receivedRequests.get(0);
        byte[] tid = evt.getMessage().getTransactionID();
        stunStack.sendResponse(tid, bindingResponse, serverAddress, clientAddress);

        //wait for retransmissions
        responseCollector.waitForResponse();

        //verify that we got the response.
        assertTrue("There were no retransmissions of a binding response", responseCollector.receivedResponses.size() == 1);
    }

    /**
     * A utility class we use to collect incoming requests.
     */
    private class PlainRequestCollector implements RequestListener {
        /** all requests we've received so far. */
        public final Vector<StunMessageEvent> receivedRequests = new Vector<>();

        /**
         * Stores incoming requests.
         *
         * @param evt the event containing the incoming request.
         */
        public void processRequest(StunMessageEvent evt) {
            logger.info("processRequest: {}", evt);
            synchronized (this) {
                receivedRequests.add(evt);
                notifyAll();
            }
        }

        public void waitForRequest() {
            logger.info("waitForRequest");
            synchronized (this) {
                if (receivedRequests.size() > 0)
                    return;
                try {
                    wait(50);
                } catch (InterruptedException e) {
                    logger.warn("waitForRequest", e);
                }
            }
        }
    }

    /**
     * A utility class to collect incoming responses.
     */
    private static class PlainResponseCollector extends AbstractResponseCollector {
        public final Vector<Object> receivedResponses = new Vector<>();

        /**
         * Notifies this <pre>ResponseCollector</pre> that a transaction described by
         * the specified <pre>BaseStunMessageEvent</pre> has failed. The possible
         * reasons for the failure include timeouts, unreachable destination, etc.
         *
         * @param event the <pre>BaseStunMessageEvent</pre> which describes the failed
         * transaction and the runtime type of which specifies the failure reason
         * @see AbstractResponseCollector#processFailure(BaseStunMessageEvent)
         */
        protected synchronized void processFailure(BaseStunMessageEvent event) {
            logger.info("processFailure: {}", event);
            String receivedResponse;
            if (event instanceof StunFailureEvent)
                receivedResponse = "unreachable";
            else if (event instanceof StunTimeoutEvent)
                receivedResponse = "timeout";
            else
                receivedResponse = "failure";
            receivedResponses.add(receivedResponse);
            notifyAll();
        }

        /**
         * Stores incoming responses.
         *
         * @param response a <pre>StunMessageEvent</pre> which describes the
         * received STUN <pre>Response</pre>
         */
        public synchronized void processResponse(StunResponseEvent response) {
            logger.info("processResponse: {}", response);
            receivedResponses.add(response);
            notifyAll();
        }

        /**
         * Waits for a short period of time for a response to arrive
         */
        public synchronized void waitForResponse() {
            logger.info("waitForResponse");
            try {
                if (receivedResponses.size() == 0)
                    wait(50);
            } catch (InterruptedException e) {
                logger.warn("waitForResponse", e);
            }
        }

        /**
         * Waits for a long period of time for a timeout trigger to fire.
         */
        public synchronized void waitForTimeout() {
            logger.info("waitForTimeout");
            try {
                if (receivedResponses.size() == 0)
                    wait(12000);
            } catch (InterruptedException e) {
                logger.warn("waitForTimeout", e);
            }
        }
    }
}
