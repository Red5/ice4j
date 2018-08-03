/* See LICENSE.md for license information */
package org.ice4j.ice;

import java.io.IOException;
import java.lang.reflect.UndeclaredThrowableException;

import org.ice4j.TransportAddress;
import org.ice4j.ice.harvest.TurnCandidateHarvest;
import org.ice4j.socket.IceSocketWrapper;
import org.ice4j.socket.RelayedCandidateConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a Candidate obtained by sending a TURN Allocate request from a HostCandidate to a TURN server. The relayed candidate is
 * resident on the TURN server, and the TURN server relays packets back towards the agent.
 *
 * @author Lubomir Marinov
 * @author Paul Gregoire
 */
public class RelayedCandidate extends LocalCandidate {

    private static final Logger logger = LoggerFactory.getLogger(RelayedCandidate.class);

    /**
     * The RelayedCandidateConnection of this RelayedCandidate.
     */
    private RelayedCandidateConnection relayedCandidateConnection;

    /**
     * The application-purposed DatagramSocket associated with this Candidate.
     */
    private IceSocketWrapper socket;

    /**
     * The TurnCandidateHarvest which has harvested this RelayedCandidate.
     */
    private final TurnCandidateHarvest turnCandidateHarvest;

    /**
     * Initializes a new RelayedCandidate which is to represent a specific TransportAddress harvested through a specific HostCandidate and a 
     * TURN server with a specific TransportAddress.
     *
     * @param transportAddress the TransportAddress to be represented by the new instance
     * @param turnCandidateHarvest the TurnCandidateHarvest which has harvested the new instance
     * @param mappedAddress the mapped TransportAddress reported by the TURN server with the delivery of the replayed transportAddress
     * to be represented by the new instance
     */
    public RelayedCandidate(TransportAddress transportAddress, TurnCandidateHarvest turnCandidateHarvest, TransportAddress mappedAddress) {
        super(transportAddress, turnCandidateHarvest.hostCandidate.getParentComponent(), CandidateType.RELAYED_CANDIDATE, CandidateExtendedType.TURN_RELAYED_CANDIDATE, turnCandidateHarvest.hostCandidate.getParentComponent().findLocalCandidate(mappedAddress));
        this.turnCandidateHarvest = turnCandidateHarvest;
        // RFC 5245: The base of a relayed candidate is that candidate itself
        setBase(this);
        setRelayServerAddress(turnCandidateHarvest.harvester.stunServer);
        setMappedAddress(mappedAddress);
    }

    /**
     * Gets the application-purposed IceSocketWrapper associated with this Candidate.
     *
     * @return the IceSocketWrapper associated with this Candidate
     */
    @Override
    public IceSocketWrapper getCandidateIceSocketWrapper() {
        if (socket == null) {
            logger.debug("getCandidateIceSocketWrapper {}", relayedCandidateConnection);
            try {
                if (relayedCandidateConnection == null) {
                    // create the RelayedCandidateConnection of this RelayedCandidate
                    relayedCandidateConnection = new RelayedCandidateConnection(this, turnCandidateHarvest);
                    // use turn server as remote destination and set relayed connection
                    socket = IceSocketWrapper.build(relayedCandidateConnection);
                }
            } catch (IOException e) {
                throw new UndeclaredThrowableException(e);
            }
        }
        return socket;
    }
}
