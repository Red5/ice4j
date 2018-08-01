package test;

import static org.junit.Assert.assertNotNull;

import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.TimeUnit;

import org.ice4j.AbstractResponseCollector;
import org.ice4j.BaseStunMessageEvent;
import org.ice4j.StunFailureEvent;
import org.ice4j.StunResponseEvent;
import org.ice4j.StunTimeoutEvent;
import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.attribute.Attribute;
import org.ice4j.attribute.MappedAddressAttribute;
import org.ice4j.attribute.XorMappedAddressAttribute;
import org.ice4j.ice.NetworkUtils;
import org.ice4j.message.Message;
import org.ice4j.message.MessageFactory;
import org.ice4j.message.Request;
import org.ice4j.message.Response;
import org.ice4j.socket.IceSocketWrapper;
import org.ice4j.socket.IceTcpSocketWrapper;
import org.ice4j.socket.IceUdpSocketWrapper;
import org.ice4j.stack.StunStack;
import org.ice4j.stunclient.SimpleAddressDetector;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PublicIPTest {

    private static final Logger logger = LoggerFactory.getLogger(PublicIPTest.class);

    //@Test
    public void test() {
        //TransportAddress stunTransportAddress = new TransportAddress("stun.l.google.com", 19302, Transport.UDP);
        TransportAddress stunTransportAddress = new TransportAddress("stun.jitsi.net", 3478, Transport.UDP);
        String publicIP = null;
        // determine the public IP
        SimpleAddressDetector stunah = null;
        IceSocketWrapper iceSocket = null;
        try {
            // create and start the detector
            stunah = new SimpleAddressDetector(stunTransportAddress);
            stunah.start();
            // create an ice socket
            iceSocket = new IceUdpSocketWrapper(new TransportAddress(InetAddress.getLocalHost().getHostAddress(), 49154, Transport.UDP));
            // get the public IP via STUN, this is BLOCKING
            publicIP = stunah.getMappingFor(iceSocket).getHostString();
        } catch (Throwable t) {
            t.printStackTrace();
        } finally {
            if (stunah != null) {
                if (iceSocket != null) {
                    iceSocket.close();
                }
                stunah.shutDown();
            }
        }
        assertNotNull(publicIP);
    }

    @Test
    public void testBR() throws Exception {
        String publicIP = null;
        IceSocketWrapper localSock = null;
        Transport selectedTransport = Transport.UDP;
        TransportAddress serverAddress = new TransportAddress("stun.l.google.com", 19302, selectedTransport);
        // cheap and dirty way to get the preferred local IP
        String localIP = null;
        try (final DatagramSocket socket = new DatagramSocket()) {
            socket.connect(InetAddress.getByName("8.8.8.8"), 10002);
            localIP = socket.getLocalAddress().getHostAddress();
        }
        TransportAddress localAddress = new TransportAddress(localIP, NetworkUtils.getRandomPortNumber(), selectedTransport);
        // collector for responses 
        SimpleResponseCollector responseCollector = new SimpleResponseCollector();
        // init the stack
        StunStack stunStack = new StunStack();
        if (selectedTransport == Transport.UDP) {
            localSock = new IceUdpSocketWrapper(localAddress);
            // add the wrapper to the stack
            stunStack.addSocket(localSock, null, true);
        } else {
            localSock = new IceTcpSocketWrapper(localAddress);
            // add the wrapper to the stack
            stunStack.addSocket(localSock, serverAddress, true);
        }
        Request bindingRequest = MessageFactory.createBindingRequest();
        stunStack.sendRequest(bindingRequest, serverAddress, localAddress, responseCollector);
        // wait for its arrival with a timeout of 3s
        Response res = responseCollector.waitForResponse();
        if (res != null) {
            // in classic STUN, the response contains a MAPPED-ADDRESS
            MappedAddressAttribute maAtt = (MappedAddressAttribute) res.getAttribute(Attribute.Type.MAPPED_ADDRESS);
            if (maAtt != null) {
                publicIP = maAtt.getAddress().getHostString();
            }
            // in STUN bis, the response contains a XOR-MAPPED-ADDRESS
            XorMappedAddressAttribute xorAtt = (XorMappedAddressAttribute) res.getAttribute(Attribute.Type.XOR_MAPPED_ADDRESS);
            if (xorAtt != null) {
                byte xoring[] = new byte[16];
                System.arraycopy(Message.MAGIC_COOKIE, 0, xoring, 0, 4);
                System.arraycopy(res.getTransactionID(), 0, xoring, 4, 12);
                publicIP = xorAtt.applyXor(xoring).getHostString();
            }
        }
        assertNotNull(publicIP);
        System.out.println("Public IP: " + publicIP);
        // clean up
        if (localSock != null) {
            localSock.close();
        }
        stunStack.shutDown();
    }

    public static class SimpleResponseCollector extends AbstractResponseCollector {

        private SynchronousQueue<Response> que = new SynchronousQueue<>();

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
         * Queues the received response.
         *
         * @param response a StunMessageEvent which describes the received STUN Response
         */
        public void processResponse(StunResponseEvent response) {
            que.offer((Response) response.getMessage());
        }

        /**
         * Blocks until a request arrives or 3s pass.
         * 
         * @return queued response or null if timeout occurs
         * @throws InterruptedException if interrupted
         */
        public Response waitForResponse() throws InterruptedException {
            return que.poll(3000L, TimeUnit.MILLISECONDS);
        }
    }

}
