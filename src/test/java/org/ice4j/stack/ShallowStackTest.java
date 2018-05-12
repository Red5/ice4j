/* See LICENSE.md for license information */
package org.ice4j.stack;

import java.net.DatagramPacket;
import java.util.Arrays;

import junit.framework.TestCase;

import org.ice4j.AbstractResponseCollector;
import org.ice4j.BaseStunMessageEvent;
import org.ice4j.MsgFixture;
import org.ice4j.StunFailureEvent;
import org.ice4j.StunMessageEvent;
import org.ice4j.StunResponseEvent;
import org.ice4j.StunTimeoutEvent;
import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.ice.nio.IceTcpTransport;
import org.ice4j.ice.nio.IceUdpTransport;
import org.ice4j.message.MessageFactory;
import org.ice4j.message.Request;
import org.ice4j.message.Response;
import org.ice4j.socket.IceSocketWrapper;
import org.ice4j.socket.IceTcpSocketWrapper;
import org.ice4j.socket.IceUdpSocketWrapper;
import org.ice4j.util.Utils;
import org.junit.After;
import org.junit.Before;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import test.PortUtil;

/**
 * All unit stack tests should be provided later. I just don't have the time now.
 *
 * @author Emil Ivov
 */
public class ShallowStackTest extends TestCase {

    private static final Logger logger = LoggerFactory.getLogger(ShallowStackTest.class);

    private StunStack stunStack;

    private MsgFixture msgFixture;

    private TransportAddress serverAddress;

    private TransportAddress localAddress;

    private DatagramCollector dgramCollector;

    private IceSocketWrapper localSock;

    /**
     * Transport type to be used for the test.
     */
    static Transport selectedTransport = Transport.UDP;

    /**
     * Creates a test instance for the method with the specified name.
     *
     * @param name the name of the test we'd like to create an instance for.
     */
    public ShallowStackTest(String name) {
        super(name);
    }

    /**
     * Initializes whatever sockets we'll be using in our tests.
     *
     * @throws Exception if something goes wrong with socket initialization.
     */
    @Before
    protected void setUp() throws Exception {
        super.setUp();
        logger.info("--------------------------------------------------------------------------------------\nSettting up {}", getClass().getName());
        //logger.info("setup");
        msgFixture = new MsgFixture();
        // XXX Paul: ephemeral port selection using 0 isnt working since the InetSocketAddress used by TransportAddress doesnt show the selected port
        // this causes connector lookups to fail due to port being still set to 0
        int serverPort = PortUtil.getPort();
        serverAddress = new TransportAddress("127.0.0.1", serverPort, selectedTransport);
        // create and start listening here
        dgramCollector = new DatagramCollector();
        dgramCollector.startListening(serverAddress);
        // init the stack
        stunStack = new StunStack();
        // access point
        localAddress = new TransportAddress("127.0.0.1", PortUtil.getPort(), selectedTransport);
        logger.info("Server: {} Client: {}", serverPort, localAddress.getPort());
        if (selectedTransport == Transport.UDP) {
            localSock = new IceUdpSocketWrapper(localAddress);
            // add the wrapper to the stack
            stunStack.addSocket(localSock, null, false);
        } else {
            localSock = new IceTcpSocketWrapper(localAddress);
            // add the wrapper to the stack
            stunStack.addSocket(localSock, serverAddress, false);
        }
    }

    /**
     * Releases the sockets we use here.
     *
     * @throws Exception if closing the sockets fails.
     */
    @After
    protected void tearDown() throws Exception {
        //logger.info("teardown");
        dgramCollector.stopListening();
        stunStack.removeSocket(localAddress);
        localSock.close();
        msgFixture = null;
        stunStack.shutDown();
        super.tearDown();
        logger.info("======================================================================================\nTorn down {}", getClass().getName());
    }

    /**
     * Sends a binding request using the stack to a bare socket, and verifies
     * that it is received and that the contents of the datagram corresponds to
     * the request that was sent.
     *
     * @throws java.lang.Exception if we fail
     */
    public void testSendRequest() throws Exception {
        logger.info("\n SendRequest");
        Request bindingRequest = MessageFactory.createBindingRequest();
        //dgramCollector.startListening(serverAddress);
        stunStack.sendRequest(bindingRequest, serverAddress, localAddress, new SimpleResponseCollector());
        // wait for its arrival
        dgramCollector.waitForPacket();
        DatagramPacket receivedPacket = dgramCollector.collectPacket();
        assertTrue("The stack did not properly send a Binding Request", (receivedPacket.getLength() > 0));
        Request receivedRequest = (Request) Request.decode(receivedPacket.getData(), 0, receivedPacket.getLength());
        assertEquals("The received request did not match the one that was sent", bindingRequest, receivedRequest);
        logger.info("Sent request: {}", Utils.byteArrayToHexString(bindingRequest.encode(stunStack)));
        logger.info("Received request: {}", Utils.byteArrayToHexString(receivedRequest.encode(stunStack)));
        // wait for retransmissions
        //dgramCollector.startListening(serverAddress);
        dgramCollector.waitForPacket();
        receivedPacket = dgramCollector.collectPacket();
        assertTrue("The stack did not retransmit a Binding Request", (receivedPacket.getLength() > 0));
        receivedRequest = (Request) Request.decode(receivedPacket.getData(), 0, receivedPacket.getLength());
        assertEquals("The retransmitted request did not match the original", bindingRequest, receivedRequest);
    }

    /**
     * Sends a byte array containing a bindingRequest, through a datagram socket and verifies that the stack receives it alright.
     *
     * @throws java.lang.Exception if we fail
     */
    public void testReceiveRequest() throws Exception {
        logger.info("\n ReceiveRequest");
        // we're expecting to receive on the ice4j side (non-controlling)
        if (selectedTransport == Transport.UDP) {
            IceUdpTransport.getInstance().registerStackAndSocket(stunStack, localSock);
        } else {
            IceTcpTransport.getInstance().registerStackAndSocket(stunStack, localSock);
        }
        SimpleRequestCollector requestCollector = new SimpleRequestCollector();
        stunStack.addRequestListener(requestCollector);
        dgramCollector.send(msgFixture.bindingRequest2, localAddress);
        // wait for the packet to arrive
        requestCollector.waitForRequest();
        Request collectedRequest = requestCollector.collectedRequest;
        assertNotNull("No request has been received", collectedRequest);
        byte[] expectedReturn = msgFixture.bindingRequest2;
        byte[] actualReturn = collectedRequest.encode(stunStack);
        assertTrue("Received request was not the same as the one that was sent", Arrays.equals(expectedReturn, actualReturn));
        logger.info(Utils.byteArrayToHexString(expectedReturn));
        logger.info(Utils.byteArrayToHexString(actualReturn));
    }

    /**
     * Sends a byte array containing a bindingRequest, through a datagram socket,
     * verifies that the stack receives it properly and then sends a response
     * using the stack. Finally, the response is expected at the other end and
     * compared with the sent one.
     *
     * @throws java.lang.Exception if we fail
     */
    public void testSendResponse() throws Exception {
        logger.info("\n SendResponse");
        // we're expecting to receive on the ice4j side (non-controlling)
        if (selectedTransport == Transport.UDP) {
            IceUdpTransport.getInstance().registerStackAndSocket(stunStack, localSock);
        } else {
            IceTcpTransport.getInstance().registerStackAndSocket(stunStack, localSock);
        }
        //---------- send & receive the request --------------------------------
        SimpleRequestCollector requestCollector = new SimpleRequestCollector();
        stunStack.addRequestListener(requestCollector);
        dgramCollector.send(msgFixture.bindingRequest, localAddress);
        // wait for the packet to arrive
        requestCollector.waitForRequest();
        Request collectedRequest = requestCollector.collectedRequest;
        assertNotNull(collectedRequest);
        byte[] expectedReturn = msgFixture.bindingRequest;
        byte[] actualReturn = collectedRequest.encode(stunStack);
        assertTrue("Received request was not the same as the one that was sent", Arrays.equals(expectedReturn, actualReturn));
        //---------- create the response ---------------------------------------
        Response bindingResponse = MessageFactory.create3489BindingResponse(new TransportAddress(MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS, MsgFixture.ADDRESS_ATTRIBUTE_PORT, Transport.UDP), new TransportAddress(MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS_2, MsgFixture.ADDRESS_ATTRIBUTE_PORT_2, Transport.UDP), new TransportAddress(MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS_3, MsgFixture.ADDRESS_ATTRIBUTE_PORT_3, Transport.UDP));
        //---------- send & receive the response -------------------------------
        //dgramCollector.startListening(serverAddress);
        stunStack.sendResponse(collectedRequest.getTransactionID(), bindingResponse, localAddress, serverAddress);
        // wait for its arrival
        dgramCollector.waitForPacket();
        DatagramPacket receivedPacket = dgramCollector.collectPacket();
        assertTrue("The stack did not properly send a Binding Request", (receivedPacket.getLength() > 0));
        Response receivedResponse = (Response) Response.decode(receivedPacket.getData(), 0, receivedPacket.getLength());
        assertEquals("The received request did not match the one that was sent.", bindingResponse, receivedResponse);
    }

    /**
     * Performs a basic test on message reception
     *
     * @throws Exception if something fails somewhere.
     */
    public void testReceiveResponse() throws Exception {
        logger.info("\n ReceiveResponse");
        SimpleResponseCollector collector = new SimpleResponseCollector();
        //--------------- send the original request ----------------------------
        Request bindingRequest = MessageFactory.createBindingRequest();
        TransactionID transId = stunStack.sendRequest(bindingRequest, serverAddress, localAddress, collector);
        logger.info("Request transaction id: {}", transId);
        // wait for its arrival
        collector.waitForResponse();
        // create the right response
        byte[] response = new byte[msgFixture.bindingResponse.length];
        System.arraycopy(msgFixture.bindingResponse, 0, response, 0, response.length);
        // Set the valid tid.
        System.arraycopy(bindingRequest.getTransactionID(), 0, response, 8, 12);
        // send the response
        dgramCollector.send(response, localAddress);
        // wait for the packet to arrive
        collector.waitForResponse();
        Response collectedResponse = collector.collectedResponse;
        byte[] expectedReturn = response;
        byte[] actualReturn = collectedResponse.encode(stunStack);
        assertTrue("Received request was not the same as the one that was sent", Arrays.equals(expectedReturn, actualReturn));
    }

    /**
     * Created to test Edge provided data, which we know has issues.
     */
    //    public void testEdgeControlled() throws Exception {
    //        logger.info("\nEdge");
    //        // user name
    //        @SuppressWarnings("unused")
    //        final String userName = "7vska1bkv1e9u7:9YVL";
    //        // register our dummy credential authority
    //        stunStack.getCredentialsManager().registerAuthority(new CredentialsAuthority() {
    //
    //            // local key / override the key so our data is valid
    //            byte[] localKey = hexStringToByteArray("363734656A3873726272346C6475316C3736636264676F356D73");
    //
    //            byte[] remoteKey = hexStringToByteArray("364974756553306563335930774959314167714B626A6456");
    //
    //            @Override
    //            public byte[] getLocalKey(String username) {
    //                return localKey;
    //            }
    //
    //            @Override
    //            public byte[] getRemoteKey(String username, String media) {
    //                return remoteKey;
    //            }
    //
    //            @Override
    //            public boolean checkLocalUserName(String username) {
    //                return username.split(":")[0].equals(username);
    //            }
    //
    //        });
    //
    //        byte[] txId = hexStringToByteArray("ED815F6A0BD1AFEF51BA05FF");
    //        // valid sized username == 19
    //        byte[] req1 = hexStringToByteArray("0001005C2112A442ED815F6A0BD1AFEF51BA05FF000600143776736B6131626B7631653975373A3959564C00002400046EFFFEFF802A00080000000000318222805400043100000080700004000000030008001446B190015E4C153EBC92E6EEFF7EDD379AECE6C58028000465E68F73");
    //        // incorrect size for username == 20
    //        //byte[] req2 = hexStringToByteArray("0001005C2112A442ED815F6A0BD1AFEF51BA05FF000600133776736B6131626B7631653975373A3959564C00002400046EFFFEFF802A0008000000000031822280540001310000008070000400000003000800142C8D92719B35E6AC883576CC430F4540DAEABFA180280004E9CC3B69");
    //
    //        Request collectedRequest = (Request) Message.decode(req1, 0, req1.length);
    //        assertTrue("Transaction ids don't match", Arrays.equals(txId, collectedRequest.getTransactionID()));
    //
    //        byte[] actualReturn = collectedRequest.encode(stunStack);
    //        logger.info(byteArrayToHexString(req1));
    //        logger.info(byteArrayToHexString(actualReturn));
    //
    //        assertTrue("Received request was not the same as the one that was sent", Arrays.equals(req1, actualReturn));
    //    }

    /**
     * Created to test Safari provided data.
     */
    //    public void testSafariControlled() throws Exception {
    //        logger.info("\nSafari");
    //        // user name
    //        @SuppressWarnings("unused")
    //        final String userName = "5tm7u1brpgfl50:lwoc";
    //        // register our dummy credential authority
    //        stunStack.getCredentialsManager().registerAuthority(new CredentialsAuthority() {
    //
    //            // local key / override the key so our data is valid
    //            byte[] localKey = hexStringToByteArray("376A3164366C696B6963366D68356C393232766A743473306867");
    //
    //            byte[] remoteKey = hexStringToByteArray("474A6B2F4A3174533864376A6B55376D626E4C736252492B");
    //
    //            @Override
    //            public byte[] getLocalKey(String username) {
    //                return localKey;
    //            }
    //
    //            @Override
    //            public byte[] getRemoteKey(String username, String media) {
    //                return remoteKey;
    //            }
    //
    //            @Override
    //            public boolean checkLocalUserName(String username) {
    //                return username.split(":")[0].equals(username);
    //            }
    //
    //        });
    //
    //        // valid sized username == 19
    //        byte[] req1 = hexStringToByteArray("000100542112A44236703243454B505231374B6C0006001335746D37753162727067666C35303A6C776F6300C05700040000003280290008F80F30B4FC105EEE002400046E001EFF000800145316B909FEA5D754C82F0510656BDE9CBCCD7F7680280004F7116D96");
    //        byte[] txId = hexStringToByteArray("36703243454B505231374B6C");
    //
    //        Request collectedRequest = (Request) Message.decode(req1, 0, req1.length);
    //        assertTrue("Transaction ids don't match", Arrays.equals(txId, collectedRequest.getTransactionID()));
    //
    //        byte[] actualReturn = collectedRequest.encode(stunStack);
    //        logger.info(byteArrayToHexString(req1));
    //        logger.info(byteArrayToHexString(actualReturn));
    //
    //        assertTrue("Received request was not the same as the one that was sent", Arrays.equals(req1, actualReturn));
    //    }

    /**
     * Created to test Chrome provided data.
     */
    //    public void testChromeControlled() throws Exception {
    //        logger.info("\nChrome");
    //        // user name
    //        @SuppressWarnings("unused")
    //        final String userName = "bpvm21bs5v3ecp:dVlI";
    //        // register our dummy credential authority
    //        stunStack.getCredentialsManager().registerAuthority(new CredentialsAuthority() {
    //
    //            // local key / override the key so our data is valid
    //            byte[] localKey = hexStringToByteArray("3166686335376A31366D353231727569733734396F6669736A65");
    //
    //            byte[] remoteKey = hexStringToByteArray("4D304338575A56514E54676B796848452B6D715332653067");
    //
    //            @Override
    //            public byte[] getLocalKey(String username) {
    //                return localKey;
    //            }
    //
    //            @Override
    //            public byte[] getRemoteKey(String username, String media) {
    //                return remoteKey;
    //            }
    //
    //            @Override
    //            public boolean checkLocalUserName(String username) {
    //                return username.split(":")[0].equals(username);
    //            }
    //
    //        });
    //
    //        // valid sized username == 19
    //        byte[] req1 = hexStringToByteArray("000100582112A442676E6D3976584A48576B6841000600136270766D323162733576336563703A64566C4900C057000400000032802A0008E19044DBFFC7814C00250000002400046E001EFF000800146EF5B93E9F4AB9AE415E0D688834962D279787F48028000489247947");
    //        byte[] txId = hexStringToByteArray("676E6D3976584A48576B6841");
    //
    //        Request collectedRequest = (Request) Message.decode(req1, 0, req1.length);
    //        assertTrue("Transaction ids don't match", Arrays.equals(txId, collectedRequest.getTransactionID()));
    //
    //        byte[] actualReturn = collectedRequest.encode(stunStack);
    //        logger.info(byteArrayToHexString(req1));
    //        logger.info(byteArrayToHexString(actualReturn));
    //
    //        assertTrue("Received request was not the same as the one that was sent", Arrays.equals(req1, actualReturn));
    //    }

    //--------------------------------------- listener implementations ---------
    /**
     * A simple utility that allows us to asynchronously collect messages.
     */
    public static class SimpleResponseCollector extends AbstractResponseCollector {

        /**
         * The response that we've just collected or null if none arrived while we were waiting.
         */
        Response collectedResponse;

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
            String msg;
            if (event instanceof StunFailureEvent) {
                msg = "Unreachable";
            } else if (event instanceof StunTimeoutEvent) {
                msg = "Timeout";
            } else {
                msg = "Failure";
            }
            logger.info("SimpleResponseCollector {}", msg);
        }

        /**
         * Logs the received response and notifies the wait method.
         *
         * @param response a StunMessageEvent which describes the
         * received STUN Response
         */
        public void processResponse(StunResponseEvent response) {
            collectedResponse = (Response) response.getMessage();
            logger.debug("Received response: {}", collectedResponse);
        }

        /**
         * Blocks until a request arrives or 50 ms pass.
         * @throws InterruptedException 
         */
        public void waitForResponse() throws InterruptedException {
            do {
                Thread.sleep(50L);
                break;
            } while (collectedResponse == null);
        }
    }

    /**
     * A utility class for asynchronously collecting requests.
     */
    public class SimpleRequestCollector implements RequestListener {
        /**
         * The one request that this collector has received or null if
         * none arrived while we were waiting.
         */
        private Request collectedRequest;

        /**
         * Indicates that a StunRequest has just been received.
         *
         * @param evt the StunMessageEvent containing the details of
         * the newly received request.
         */
        public void processRequest(StunMessageEvent evt) {
            collectedRequest = (Request) evt.getMessage();
            stunStack.removeRequestListener(this);
            logger.debug("Received request: {}", collectedRequest);
        }

        /**
         * Blocks until a request arrives or 50 ms pass.
         */
        public void waitForRequest() {
            if (collectedRequest == null) {
                try {
                    Thread.sleep(100L);
                } catch (InterruptedException e) {
                    logger.warn("oops", e);
                }
            }
        }
    }

}
