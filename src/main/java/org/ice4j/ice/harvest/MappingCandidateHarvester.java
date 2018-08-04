/* See LICENSE.md for license information */
package org.ice4j.ice.harvest;

import java.util.Collection;
import java.util.HashSet;
import java.util.Objects;

import org.ice4j.TransportAddress;
import org.ice4j.ice.Candidate;
import org.ice4j.ice.CandidateExtendedType;
import org.ice4j.ice.Component;
import org.ice4j.ice.HostCandidate;
import org.ice4j.ice.LocalCandidate;
import org.ice4j.ice.ServerReflexiveCandidate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Uses a list of addresses as a predefined static mask in order to generate {@link TransportAddress}es. This harvester is meant for use in situations
 * where servers are deployed behind a NAT or in a DMZ with static port mapping.
 * <br>
 * Every time the {@link #harvest(Component)} method is called, the mapping harvester will return a list of candidates that provide masked alternatives
 * for every host candidate in the component. Kind of like a STUN server.
 * <br>
 * Example: You run this on a server with address 192.168.0.1, that is behind a NAT with public IP: 93.184.216.119. You allocate a host candidate
 * 192.168.0.1/UDP/5000. This harvester is going to then generate an address 93.184.216.119/UDP/5000
 * <br>
 * This harvester is instant and does not introduce any harvesting latency.
 *
 * @author Emil Ivov
 */
public class MappingCandidateHarvester extends AbstractCandidateHarvester {

    private static final Logger logger = LoggerFactory.getLogger(MappingCandidateHarvester.class);

    /**
     * The addresses that we will use as a mask
     */
    protected TransportAddress mask;

    /**
     * The addresses that we will be masking
     */
    protected TransportAddress face;

    /**
     * Creates a mapping harvester with the specified mask
     *
     * @param mask the TransportAddresses that would be used as a mask
     * @param face the TransportAddresses that we will be masking
     */
    public MappingCandidateHarvester(TransportAddress mask, TransportAddress face) {
        this.mask = Objects.requireNonNull(mask);
        this.face = Objects.requireNonNull(face);
    }

    /**
     * Initializes a {@link MappingCandidateHarvester} instance without specified addresses (only useful in subclasses which override
     * {@link #getMask()} and {@link #getFace()}).
     */
    protected MappingCandidateHarvester() {
    }

    /**
     * Maps all candidates to this harvester's mask and adds them to component.
     *
     * @param component the {@link Component} that we'd like to map candidates to
     * @return  the LocalCandidates gathered by this CandidateHarvester or null if no mask is specified
     */
    @Override
    public Collection<LocalCandidate> harvest(Component component) {
        TransportAddress mask = getMask();
        TransportAddress face = getFace();
        if (face == null || mask == null) {
            logger.info("Harvester not configured: face={}, mask={}", face, mask);
            return null;
        }
        // Report the LocalCandidates gathered by this CandidateHarvester so that the harvest is sure to be considered successful.
        Collection<LocalCandidate> candidates = new HashSet<>();
        for (Candidate<?> cand : component.getLocalCandidates()) {
            if (!(cand instanceof HostCandidate) || !cand.getTransportAddress().getHostAddress().equals(face.getHostAddress()) || cand.getTransport() != face.getTransport()) {
                continue;
            }
            HostCandidate hostCandidate = (HostCandidate) cand;
            TransportAddress mappedAddress = new TransportAddress(mask.getHostAddress(), hostCandidate.getHostAddress().getPort(), hostCandidate.getHostAddress().getTransport());
            ServerReflexiveCandidate mappedCandidate = new ServerReflexiveCandidate(mappedAddress, hostCandidate, hostCandidate.getStunServerAddress(), CandidateExtendedType.STATICALLY_MAPPED_CANDIDATE);
            if (hostCandidate.isSSL()) {
                mappedCandidate.setSSL(true);
            }
            //try to add the candidate to the component and then only add it to the harvest not redundant
            if (!candidates.contains(mappedCandidate) && component.addLocalCandidate(mappedCandidate)) {
                candidates.add(mappedCandidate);
            }
        }
        return candidates;
    }

    /**
     * Returns the public (mask) address, or null.
     * @return the public (mask) address, or null.
     */
    public TransportAddress getMask() {
        return mask;
    }

    /**
     * Returns the local (face) address, or null.
     * @return the local (face) address, or null.
     */
    public TransportAddress getFace() {
        return face;
    }
    
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((face == null) ? 0 : face.hashCode());
        result = prime * result + ((mask == null) ? 0 : mask.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        MappingCandidateHarvester other = (MappingCandidateHarvester) obj;
        if (face == null) {
            if (other.face != null)
                return false;
        } else if (!face.equals(other.face))
            return false;
        if (mask == null) {
            if (other.mask != null)
                return false;
        } else if (!mask.equals(other.mask))
            return false;
        return true;
    }

    @Override
    public String toString() {
        TransportAddress face = getFace();
        TransportAddress mask = getMask();
        return this.getClass().getName() + ", face=" + (face == null ? "null" : face.getAddress()) + ", mask=" + (mask == null ? "null" : mask.getAddress());
    }
}
