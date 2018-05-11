/* See LICENSE.md for license information */
package org.ice4j.stunclient;

import java.io.IOException;

import org.ice4j.StunException;
import org.ice4j.StunMessageEvent;
import org.ice4j.TransportAddress;
import org.ice4j.attribute.Attribute;
import org.ice4j.attribute.AttributeFactory;
import org.ice4j.attribute.ChangeRequestAttribute;
import org.ice4j.attribute.ChangedAddressAttribute;
import org.ice4j.attribute.MappedAddressAttribute;
import org.ice4j.ice.nio.IceTransport;
import org.ice4j.message.MessageFactory;
import org.ice4j.message.Request;
import org.ice4j.socket.IceSocketWrapper;
import org.ice4j.stack.StunStack;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>
 * This class implements the STUN Discovery Process as described by section 10.1 of rfc 3489.
 * </p><p>
 * The flow makes use of three tests.  In test I, the client sends a STUN Binding Request to a server, without any flags set in the
 * CHANGE-REQUEST attribute, and without the RESPONSE-ADDRESS attribute. This causes the server to send the response back to the address and
 * port that the request came from.  In test II, the client sends a Binding Request with both the "change IP" and "change port" flags
 * from the CHANGE-REQUEST attribute set.  In test III, the client sends a Binding Request with only the "change port" flag set.
 * </p><p>
 * The client begins by initiating test I.  If this test yields no response, the client knows right away that it is not capable of UDP
 * connectivity.  If the test produces a response, the client examines the MAPPED-ADDRESS attribute.  If this address and port are the same
 * as the local IP address and port of the socket used to send the request, the client knows that it is not natted.  It executes test II.
 * </p><p>
 * If a response is received, the client knows that it has open access to the Internet (or, at least, its behind a firewall that behaves
 * like a full-cone NAT, but without the translation).  If no response is received, the client knows its behind a symmetric UDP firewall.
 * </p><p>
 * In the event that the IP address and port of the socket did not match the MAPPED-ADDRESS attribute in the response to test I, the client
 * knows that it is behind a NAT.  It performs test II.  If a response is received, the client knows that it is behind a full-cone NAT.  If
 * no response is received, it performs test I again, but this time, does so to the address and port from the CHANGED-ADDRESS attribute
 * from the response to test I.  If the IP address and port returned in the MAPPED-ADDRESS attribute are not the same as the ones from the
 * first test I, the client knows its behind a symmetric NAT.  If the address and port are the same, the client is either behind a
 * restricted or port restricted NAT.  To make a determination about which one it is behind, the client initiates test III.  If a response
 * is received, its behind a restricted NAT, and if no response is received, its behind a port restricted NAT.
 * </p><p>
 * This procedure yields substantial information about the operating condition of the client application.  In the event of multiple NATs
 * between the client and the Internet, the type that is discovered will be the type of the most restrictive NAT between the client and the
 * Internet.  The types of NAT, in order of restrictiveness, from most to least, are symmetric, port restricted cone, restricted cone, and
 * full cone.
 * </p><p>
 * Typically, a client will re-do this discovery process periodically to detect changes, or look for inconsistent results.  It is important to
 * note that when the discovery process is redone, it should not generally be done from the same local address and port used in the
 * previous discovery process.  If the same local address and port are reused, bindings from the previous test may still be in existence,
 * and these will invalidate the results of the test.  Using a different local address and port for subsequent tests resolves this problem.
 * An alternative is to wait sufficiently long to be confident that the old bindings have expired (half an hour should more than suffice).
 * </p>
 *
 * @author Emil Ivov
 */
public class NetworkConfigurationDiscoveryProcess {

    private static final Logger logger = LoggerFactory.getLogger(NetworkConfigurationDiscoveryProcess.class);

    /**
     * Indicates whether the underlying stack has been initialized and started and that the discoverer is operational.
     */
    private boolean started;

    /**
     * The point where we'll be listening.
     */
    private TransportAddress localAddress;

    /**
     * The address of the stun server
     */
    private TransportAddress serverAddress;

    /**
     * A utility used to flatten the multithread architecture of the stack and execute the discovery process in a synchronized manner
     */
    private BlockingRequestSender requestSender;

    /**
     * The DatagramSocket that we are going to be running the discovery process through.
     */
    private IceSocketWrapper sock;

    /**
     * The StunStack used by this instance for the purposes of STUN communication.
     */
    private final StunStack stunStack;

    /**
     * Initializes a StunAddressDiscoverer with a specific StunStack. In order to use it one must first start it.
     *
     * @param stunStack the StunStack to be used by the new instance
     * @param localAddress  the address where the stack should bind.
     * @param serverAddress the address of the server to interrogate.
     */
    public NetworkConfigurationDiscoveryProcess(StunStack stunStack, TransportAddress localAddress, TransportAddress serverAddress) {
        if (stunStack == null) {
            throw new NullPointerException("stunStack");
        }
        logger.debug("Discovery process on {} with server {}", localAddress, serverAddress);
        this.stunStack = stunStack;
        this.localAddress = localAddress;
        this.serverAddress = serverAddress;
    }

    /**
     * Shuts down the underlying stack and prepares the object for garbage collection.
     */
    public void shutDown() {
        stunStack.removeSocket(localAddress);
        sock.close();
        sock = null;
        localAddress = null;
        requestSender = null;
        started = false;
    }

    /**
     * Puts the discoverer into an operational state.
     * 
     * @throws IOException if we fail to bind
     * @throws StunException if the stun4j stack fails start for some reason
     */
    public void start() throws IOException, StunException {
        logger.debug("start: {}", localAddress);
        // check for existing binding before creating a new one
        sock = IceTransport.getIceHandler().lookupBinding(localAddress);
        // create a new socket since there isn't one registered for the local address
        if (sock == null) {
            sock = IceSocketWrapper.build(localAddress, serverAddress);
            stunStack.addSocket(sock, serverAddress, true); // do socket binding
        }
        requestSender = new BlockingRequestSender(stunStack, localAddress);
        started = true;
    }

    /**
     * Implements the discovery process itself (see class description).
     * 
     * @return a StunDiscoveryReport containing details about the network configuration of the host where the class is executed
     *
     * @throws StunException ILLEGAL_STATE if the discoverer has not been started
     * @throws IOException if a failure occurs while executing the discovery algorithm
     */
    public StunDiscoveryReport determineAddress() throws StunException, IOException {
        checkStarted();
        StunDiscoveryReport report = new StunDiscoveryReport();
        StunMessageEvent evt = doTestI(serverAddress);
        if (evt == null) {
            //UDP Blocked
            report.setNatType(StunDiscoveryReport.UDP_BLOCKING_FIREWALL);
            return report;
        } else {
            TransportAddress mappedAddress = ((MappedAddressAttribute) evt.getMessage().getAttribute(Attribute.Type.MAPPED_ADDRESS)).getAddress();
            if (mappedAddress == null) {
                // maybe we contact a STUNbis server and which do not understand our request.
                logger.info("Failed to do the network discovery");
                return null;
            }
            logger.debug("mapped address is=" + mappedAddress + ", name=" + mappedAddress.getHostAddress());
            TransportAddress backupServerAddress = ((ChangedAddressAttribute) evt.getMessage().getAttribute(Attribute.Type.CHANGED_ADDRESS)).getAddress();
            logger.debug("backup server address is=" + backupServerAddress + ", name=" + backupServerAddress.getHostAddress());
            report.setPublicAddress(mappedAddress);
            if (mappedAddress.equals(localAddress)) {
                evt = doTestII(serverAddress);
                if (evt == null) {
                    //Sym UDP Firewall
                    report.setNatType(StunDiscoveryReport.SYMMETRIC_UDP_FIREWALL);
                    return report;
                } else {
                    //open internet
                    report.setNatType(StunDiscoveryReport.OPEN_INTERNET);
                    return report;
                }
            } else {
                evt = doTestII(serverAddress);
                if (evt == null) {
                    evt = doTestI(backupServerAddress);
                    if (evt == null) {
                        logger.info("Failed to receive a response frombackup stun server!");
                        return report;
                    }
                    TransportAddress mappedAddress2 = ((MappedAddressAttribute) evt.getMessage().getAttribute(Attribute.Type.MAPPED_ADDRESS)).getAddress();
                    if (mappedAddress.equals(mappedAddress2)) {
                        evt = doTestIII(serverAddress);
                        if (evt == null) {
                            //port restricted cone
                            report.setNatType(StunDiscoveryReport.PORT_RESTRICTED_CONE_NAT);
                            return report;
                        } else {
                            //restricted cone
                            report.setNatType(StunDiscoveryReport.RESTRICTED_CONE_NAT);
                            return report;
                        }
                    } else {
                        //Symmetric NAT
                        report.setNatType(StunDiscoveryReport.SYMMETRIC_NAT);
                        return report;
                    }
                } else {
                    //full cone
                    report.setNatType(StunDiscoveryReport.FULL_CONE_NAT);
                    return report;
                }
            }
        }

    }

    /**
     * Sends a binding request to the specified server address. Both change IP and change port flags are set to false.
     * @param serverAddress the address where to send the bindingRequest.
     * @return The returned message encapsulating event or null if no message was received.
     *
     * @throws StunException if an exception occurs while sending the message
     * @throws IOException if an error occurs while sending bytes through the socket.
     */
    private StunMessageEvent doTestI(TransportAddress serverAddress) throws IOException, StunException {
        Request request = MessageFactory.createBindingRequest();
        /* add a change request attribute */
        ChangeRequestAttribute changeRequest = AttributeFactory.createChangeRequestAttribute();
        changeRequest.setChangeIpFlag(false);
        changeRequest.setChangePortFlag(false);
        request.putAttribute(changeRequest);
        StunMessageEvent evt = null;
        try {
            evt = requestSender.sendRequestAndWaitForResponse(request, serverAddress);
        } catch (StunException ex) {
            //this shouldn't happen since we are the ones that created the request
            logger.warn("Internal Error. Failed to encode a message", ex);
            return null;
        }
        if (evt != null) {
            logger.debug("TEST I res={} - {}", evt.getRemoteAddress().toString(), evt.getRemoteAddress().getHostAddress());
        } else {
            logger.debug("NO RESPONSE received to TEST I.");
        }
        return evt;
    }

    /**
     * Sends a binding request to the specified server address with both change IP and change port flags are set to true.
     * @param serverAddress the address where to send the bindingRequest.
     * @return The returned message encapsulating event or null if no message was received.
     *
     * @throws StunException if an exception occurs while sending the messge
     * @throws IOException if an exception occurs while executing the algorithm.
     */
    private StunMessageEvent doTestII(TransportAddress serverAddress) throws StunException, IOException {
        Request request = MessageFactory.createBindingRequest();
        // add a change request attribute
        ChangeRequestAttribute changeRequest = AttributeFactory.createChangeRequestAttribute();
        changeRequest.setChangeIpFlag(true);
        changeRequest.setChangePortFlag(true);
        request.putAttribute(changeRequest);
        StunMessageEvent evt = requestSender.sendRequestAndWaitForResponse(request, serverAddress);
        if (evt != null) {
            logger.debug("Test II res={} - {}", evt.getRemoteAddress().toString(), evt.getRemoteAddress().getHostAddress());
        } else {
            logger.debug("NO RESPONSE received to Test II.");
        }
        return evt;
    }

    /**
     * Sends a binding request to the specified server address with only change
     * port flag set to true and change IP flag - to false.
     * @param serverAddress the address where to send the bindingRequest.
     * @return The returned message encapsulating event or null if no message
     * was received.
     * @throws StunException if an exception occurs while sending the messge
     * @throws IOException if an exception occurs while sending bytes through
     * the socket.
     */
    private StunMessageEvent doTestIII(TransportAddress serverAddress) throws StunException, IOException {
        Request request = MessageFactory.createBindingRequest();
        // add a change request attribute
        ChangeRequestAttribute changeRequest = AttributeFactory.createChangeRequestAttribute();
        changeRequest.setChangeIpFlag(false);
        changeRequest.setChangePortFlag(true);
        request.putAttribute(changeRequest);
        StunMessageEvent evt = requestSender.sendRequestAndWaitForResponse(request, serverAddress);
        if (evt != null) {
            logger.debug("Test III res={} - {}", evt.getRemoteAddress().toString(), evt.getRemoteAddress().getHostAddress());
        } else {
            logger.debug("NO RESPONSE received to Test III.");
        }
        return evt;
    }

    /**
     * Makes sure the discoverer is operational and throws an
     * StunException.ILLEGAL_STATE if that is not the case.
     * @throws StunException ILLEGAL_STATE if the discoverer is not operational.
     */
    private void checkStarted() throws StunException {
        if (!started) {
            throw new StunException(StunException.ILLEGAL_STATE, "The Discoverer must be started beforelaunching the discovery process!");
        }
    }

}
