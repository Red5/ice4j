/* See LICENSE.md for license information */
package org.ice4j.ice.harvest;

import java.util.Map;

import org.ice4j.TransportAddress;
import org.ice4j.ice.nio.IceTransport;
import org.ice4j.socket.IceSocketWrapper;
import org.ice4j.stunclient.SimpleAddressDetector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@link MappingCandidateHarvester} which uses a STUN servers to discover its public IP address.
 *
 * @author Damian Minkov
 * @author Boris Grozev
 */
public class StunMappingCandidateHarvester extends MappingCandidateHarvester {

    private static final Logger logger = LoggerFactory.getLogger(StunMappingCandidateHarvester.class);

    /**
     * The list of servers we will use to discover our public address.
     */
    private TransportAddress stunServerAddress;

    /**
     * Initializes a new {@link StunMappingCandidateHarvester} instance with a given local address and a STUN server address. Note that the actual
     * discovery of the public address needs to be initiated to a separate call to {@link #discover()}.
     * @param localAddress The local address.
     * @param stunServerAddress The address of the STUN server.
     */
    public StunMappingCandidateHarvester(TransportAddress localAddress, TransportAddress stunServerAddress) {
        face = localAddress;
        this.stunServerAddress = stunServerAddress;
    }

    /**
     * Attempts to discover the the public address (mask) via the STUN server.
     * Note that this will block until we either receive a response from the STUN server, or a timeout occurs.
     * @param context 
     */
    public void discover(Map<String, Object> context) {
        try {
            SimpleAddressDetector sad = new SimpleAddressDetector(stunServerAddress);
            sad.start();
            // check for existing binding before creating a new one
            IceSocketWrapper localSocket = IceTransport.getIceHandler().lookupBinding(face);
            // create a new socket since there isn't one registered for the local address
            if (localSocket == null) {
                localSocket = IceSocketWrapper.build(face, null,context);
            }
            mask = sad.getMappingFor(localSocket, context);
            if (mask != null) {
                logger.info("Discovered public address {} from STUN server {} using local address {}", mask, stunServerAddress, face);
            }
        } catch (Exception exc) {
            //whatever happens, we just log
            logger.info("We failed to obtain addresses for the following reason", exc);
        }
    }
}
