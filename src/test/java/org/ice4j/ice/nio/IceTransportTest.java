package org.ice4j.ice.nio;

import java.io.IOException;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.TimeUnit;

import org.apache.mina.core.future.ConnectFuture;
import org.apache.mina.core.future.IoFutureListener;
import org.apache.mina.core.session.IdleStatus;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.transport.socket.SocketSessionConfig;
import org.apache.mina.transport.socket.nio.NioSocketConnector;
import org.ice4j.AbstractResponseCollector;
import org.ice4j.BaseStunMessageEvent;
import org.ice4j.ResponseCollector;
import org.ice4j.StunFailureEvent;
import org.ice4j.StunResponseEvent;
import org.ice4j.StunTimeoutEvent;
import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.attribute.Attribute;
import org.ice4j.attribute.MappedAddressAttribute;
import org.ice4j.attribute.XorMappedAddressAttribute;
import org.ice4j.message.Message;
import org.ice4j.message.MessageFactory;
import org.ice4j.message.Request;
import org.ice4j.message.Response;
import org.ice4j.socket.IceSocketWrapper;
import org.ice4j.stack.StunStack;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class IceTransportTest {

    private static final Logger log = LoggerFactory.getLogger(IceTransportTest.class);

    private static String GOOGLE_STUN = "stun1.l.google.com";

    private static int GOOGLE_STUN_PORT = 19302;
    
    @Test
    public void testUDP() {
        // udp for this test
        Transport transport = Transport.UDP;
        String localIP = "10.0.0.36", publicIP = "71.38.180.149";
        int port = 49155;
        // ice4j
        System.setProperty("org.ice4j.BIND_RETRIES", "1");
        System.setProperty("org.ice4j.ice.harvest.NAT_HARVESTER_LOCAL_ADDRESS", localIP);
        System.setProperty("org.ice4j.ice.harvest.NAT_HARVESTER_PUBLIC_ADDRESS", publicIP);
        TransportAddress stunTransportAddress = new TransportAddress(GOOGLE_STUN, GOOGLE_STUN_PORT, transport);
        // use ice4j to get our public IP
        try {
            TransportAddress localTransportAddress = new TransportAddress(localIP, port, transport);
            publicIP = resolvePublicIP(localTransportAddress, stunTransportAddress);
        } catch (Throwable t) {
            log.warn("Exception contacting STUN server at: {}", stunTransportAddress, t);
        }
        log.info("Public IP address: {}", publicIP);
        // set up allowed addresses to prevent NIC scanning in HostCandidateHarvester.getAvailableHostAddresses()
        String allowedIPs = null;
        if (localIP.contentEquals(publicIP)) {
            allowedIPs = localIP;
        } else {
            allowedIPs = String.format("%s;%s", localIP, publicIP);
        }
        System.setProperty("org.ice4j.ice.harvest.ALLOWED_ADDRESSES", allowedIPs);
        System.setProperty("org.ice4j.ice.harvest.NAT_HARVESTER_DEFAULT_TRANSPORT", transport.getTransportName());
        // default termination delay to 1s since anything less seems to fail on multiple subscribers on quick connect intervals
        System.setProperty("org.ice4j.TERMINATION_DELAY", "500");
    }


    /**
     * Resolves the servers public IP address using a STUN binding request.
     *
     * @param localTransportAddress
     * @param stunTransportAddress
     * @return public IP address or null if some failure occurs
     * @throws IOException
     * @throws InterruptedException
     */
    private String resolvePublicIP(TransportAddress localTransportAddress, TransportAddress stunTransportAddress) throws IOException, InterruptedException {
        String publicIP = null;
        SynchronousQueue<Response> que = new SynchronousQueue<>();
        // collector for responses
        ResponseCollector responseCollector = new AbstractResponseCollector() {

            /**
             * Notifies this ResponseCollector that a transaction described by the specified BaseStunMessageEvent has failed. The possible
             * reasons for the failure include timeouts, unreachable destination, etc.
             *
             * @param event the BaseStunMessageEvent which describes the failed transaction and the runtime type of which specifies the failure reason
             * @see AbstractResponseCollector#processFailure(BaseStunMessageEvent)
             */
            @Override
            protected void processFailure(BaseStunMessageEvent event) {
                String msg;
                if (event instanceof StunFailureEvent) {
                    msg = "Unreachable";
                } else if (event instanceof StunTimeoutEvent) {
                    msg = "Timeout";
                } else {
                    msg = "Failure";
                }
                log.debug("ResponseCollector: {}", msg);
            }

            /**
             * Queues the received response.
             *
             * @param response a StunMessageEvent which describes the received STUN Response
             */
            @Override
            public void processResponse(StunResponseEvent response) {
                que.offer((Response) response.getMessage());
            }

        };
        // init the stun stack
        StunStack stunStack = new StunStack();
        // create an ice socket wrapper with the transport based on the addresses supplied
        IceSocketWrapper iceSocket = IceSocketWrapper.build(localTransportAddress, stunTransportAddress);
        // add the wrapper to the stack
        if (iceSocket.isUDP()) {
            // when its udp, bind so we'll be listening
            stunStack.addSocket(iceSocket, stunTransportAddress, true);
        } else if (iceSocket.isTCP()) {
            // get the handler
            IceHandler handler = IceTransport.getIceHandler();
            // now connect as a client
            NioSocketConnector connector = new NioSocketConnector(1);
            SocketSessionConfig config = connector.getSessionConfig();
            config.setReuseAddress(true);
            config.setTcpNoDelay(true);
            // set an idle time of 30s (default)
            config.setIdleTime(IdleStatus.BOTH_IDLE, IceTransport.getTimeout());
            // set connection timeout of x milliseconds
            connector.setConnectTimeoutMillis(3000L);
            // add the ice protocol encoder/decoder
            connector.getFilterChain().addLast("protocol", IceTransport.getProtocolcodecfilter());
            // set the handler on the connector
            connector.setHandler(handler);
            // register
            handler.registerStackAndSocket(stunStack, iceSocket);
            // dont bind when using tcp, since java doesn't allow client+server at the same time
            stunStack.addSocket(iceSocket, stunTransportAddress, false);
            // connect
            connector.setDefaultRemoteAddress(stunTransportAddress);
            ConnectFuture future = connector.connect(stunTransportAddress, localTransportAddress);
            future.addListener(new IoFutureListener<ConnectFuture>() {

                @Override
                public void operationComplete(ConnectFuture future) {
                    log.debug("operationComplete {} {}", future.isDone(), future.isCanceled());
                    if (future.isConnected()) {
                        IoSession sess = future.getSession();
                        if (sess != null) {
                            iceSocket.setSession(sess);
                        }
                    } else {
                        log.warn("Exception connecting", future.getException());
                    }
                }

            });
            future.awaitUninterruptibly();
        }
        Request bindingRequest = MessageFactory.createBindingRequest();
        stunStack.sendRequest(bindingRequest, stunTransportAddress, localTransportAddress, responseCollector);
        // wait for its arrival with a timeout of 3s
        Response res = que.poll(3000L, TimeUnit.MILLISECONDS);
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
        // clean up
        if (iceSocket != null) {
            iceSocket.close();
        }
        stunStack.shutDown();
        log.info("Public IP: {}", publicIP);
        return publicIP;
    }    
    
}
