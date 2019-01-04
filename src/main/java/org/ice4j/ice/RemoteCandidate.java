/* See LICENSE.md for license information */
package org.ice4j.ice;

import org.ice4j.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * RemoteCandidates are candidates that an agent received in an offer or an answer from its peer, and that it would use
 * to form candidate pairs after combining them with its local candidates.
 *
 * @author Emil Ivov
 */
public class RemoteCandidate extends Candidate<RemoteCandidate> {

    private static final Logger logger = LoggerFactory.getLogger(RemoteCandidate.class);
    
    /**
     * Creates a RemoteCandidate instance for the specified transport
     * address and properties.
     *
     * @param transportAddress  the transport address that this candidate is
     * encapsulating.
     * @param parentComponent the Component that this candidate
     * belongs to.
     * @param type the CandidateType for this Candidate.
     * @param foundation the RemoteCandidate's foundation as reported
     * by the session description protocol.
     * @param priority the RemoteCandidate's priority as reported
     * by the session description protocol.
     * @param relatedCandidate the relatedCandidate: null for a host candidate,
     * the base address (host candidate) for a reflexive candidate, the mapped
     * address (the mapped address of the TURN allocate response) for a relayed
     * candidate.
     */
    public RemoteCandidate(TransportAddress transportAddress, Component parentComponent, CandidateType type, String foundation, long priority, RemoteCandidate relatedCandidate) {
        this(transportAddress, parentComponent, type, foundation, priority, relatedCandidate, null);
    }

    /**
     * Creates a RemoteCandidate instance for the specified transport
     * address and properties.
     *
     * @param transportAddress  the transport address that this candidate is
     * encapsulating.
     * @param parentComponent the Component that this candidate
     * belongs to.
     * @param type the CandidateType for this Candidate.
     * @param foundation the RemoteCandidate's foundation as reported
     * by the session description protocol.
     * @param priority the RemoteCandidate's priority as reported
     * by the session description protocol.
     * @param relatedCandidate the relatedCandidate: null for a host candidate,
     * the base address (host candidate) for a reflexive candidate, the mapped
     * address (the mapped address of the TURN allocate response) for a relayed
     * candidate.
     * @param ufrag ufrag for the remote candidate
     */
    public RemoteCandidate(TransportAddress transportAddress, Component parentComponent, CandidateType type, String foundation, long priority, RemoteCandidate relatedCandidate, String ufrag) {
        super(transportAddress, parentComponent, type, relatedCandidate);
        setFoundation(foundation);
        setPriority(priority);
        this.ufrag = ufrag;
        logger.debug("ctor - addr: {} comp: {}\n    remote type: {} priority: {} related candidate: {}", transportAddress, parentComponent, type, priority, relatedCandidate);
    }

    /**
     * Sets the priority of this RemoteCandidate. Priority is a unique
     * priority number that MUST be a positive integer between 1 and
     * (2**32 - 1). This priority will be set and used by ICE algorithms to
     * determine the order of the connectivity checks and the relative
     * preference for candidates.
     *
     * @param priority the priority number between 1 and (2**32 - 1).
     */
    public void setPriority(long priority) {
        super.priority = priority;
    }

    /**
     * Determines whether this Candidate is the default one for its parent component.
     *
     * @return true if this Candidate is the default for its parent component and false if it isn't or if it has no parent
     * Component yet.
     */
    @Override
    public boolean isDefault() {
        Component parentCmp = getParentComponent();
        if (parentCmp == null) {
            return false;
        }
        return equals(parentCmp.getDefaultRemoteCandidate());
    }

    /**
     * Find the candidate corresponding to the address given in parameter.
     *
     * @param relatedAddress The related address:
     * - null for a host candidate,
     * - the base address (host candidate) for a reflexive candidate,
     * - the mapped address (the mapped address of the TURN allocate response)
     * for a relayed candidate.
     * - null for a peer reflexive candidate : there is no way to know the
     * related address.
     *
     * @return The related candidate corresponding to the address given in
     * parameter:
     * - null for a host candidate,
     * - the base address (host candidate) for a reflexive candidate,
     * - the mapped address (the mapped address of the TURN allocate response)
     * for a relayed candidate.
     * - null for a peer reflexive candidate : there is no way to know the
     * related address.
     */
    protected RemoteCandidate findRelatedCandidate(TransportAddress relatedAddress) {
        return getParentComponent().findRemoteCandidate(relatedAddress);
    }
}
