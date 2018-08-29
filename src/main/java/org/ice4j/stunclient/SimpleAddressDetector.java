/* See LICENSE.md for license information */
package org.ice4j.stunclient;

import java.io.IOException;
import java.net.BindException;

import org.ice4j.StunException;
import org.ice4j.StunMessageEvent;
import org.ice4j.TransportAddress;
import org.ice4j.attribute.Attribute;
import org.ice4j.attribute.MappedAddressAttribute;
import org.ice4j.attribute.XorMappedAddressAttribute;
import org.ice4j.message.Message;
import org.ice4j.message.MessageFactory;
import org.ice4j.message.Response;
import org.ice4j.socket.IceSocketWrapper;
import org.ice4j.stack.StunStack;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The class provides basic means of discovering a public IP address. All it does is send a binding request through a specified port and return the
 * mapped address it got back or null if there was no response.
 *
 * @author Emil Ivov
 */
public class SimpleAddressDetector {

    private static final Logger logger = LoggerFactory.getLogger(SimpleAddressDetector.class);

    /**
     * The stack to use for STUN communication.
     */
    private StunStack stunStack;

    /**
     * The address of the stun server
     */
    private TransportAddress serverAddress;

    /**
     * A utility used to flatten the multi-threaded architecture of the Stack
     * and execute the discovery process in a synchronized manner
     */
    private BlockingRequestSender requestSender;

    /**
     * Creates a StunAddressDiscoverer. In order to use it one must start the
     * discoverer.
     * @param serverAddress the address of the server to interrogate.
     */
    public SimpleAddressDetector(TransportAddress serverAddress) {
        this.serverAddress = serverAddress;
    }

    /**
     * Returns the server address that this detector is using to run stun
     * queries.
     *
     * @return StunAddress the address of the stun server that we are running
     * stun queries against.
     */
    public TransportAddress getServerAddress() {
        return serverAddress;
    }

    /**
     * Puts the discoverer into an operational state.
     */
    public void start() {
        stunStack = new StunStack();
    }

    /**
     * Shuts down the underlying stack and prepares the object for garbage collection.
     */
    public void shutDown() {
        stunStack.shutDown();
        stunStack = null;
        requestSender = null;
    }

    /**
     * Creates a listening point for the specified socket and attempts to discover how its local address is NAT mapped.
     * 
     * @param socket the socket whose address needs to be resolved
     * @return a StunAddress object containing the mapped address or null if discovery failed
     * @throws IOException if something fails along the way
     * @throws BindException if we cannot bind the socket
     */
    public TransportAddress getMappingFor(IceSocketWrapper socket) throws IOException, BindException {
        logger.debug("getMappingFor: {}", socket);
        TransportAddress localAddress = socket.getTransportAddress();
        // this should work for both udp and tcp
        stunStack.addSocket(socket, socket.getRemoteTransportAddress(), true); // do socket binding
        requestSender = new BlockingRequestSender(stunStack, localAddress);
        StunMessageEvent evt = null;
        try {
            evt = requestSender.sendRequestAndWaitForResponse(MessageFactory.createBindingRequest(), serverAddress);
            if (evt != null) {
                Response res = (Response) evt.getMessage();
                // in classic STUN, the response contains a MAPPED-ADDRESS
                MappedAddressAttribute maAtt = (MappedAddressAttribute) res.getAttribute(Attribute.Type.MAPPED_ADDRESS);
                if (maAtt != null) {
                    return maAtt.getAddress();
                }
                // in STUN bis, the response contains a XOR-MAPPED-ADDRESS
                XorMappedAddressAttribute xorAtt = (XorMappedAddressAttribute) res.getAttribute(Attribute.Type.XOR_MAPPED_ADDRESS);
                if (xorAtt != null) {
                    byte xoring[] = new byte[16];
                    System.arraycopy(Message.MAGIC_COOKIE, 0, xoring, 0, 4);
                    System.arraycopy(res.getTransactionID(), 0, xoring, 4, 12);
                    return xorAtt.applyXor(xoring);
                }
            }
        } catch (StunException exc) {
            // this shouldn't be happening since we are the one that constructed the request, so let's catch it here and not oblige users to
            // handle exception they are not responsible for.
            logger.warn("Internal Error. We apparently constructed a faulty request", exc);
        } finally {
            stunStack.removeSocket(socket.getId(), localAddress, serverAddress);
        }
        return null;
    }

}
