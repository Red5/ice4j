/* See LICENSE.md for license information */
package org.ice4j.ice;

import java.net.SocketAddress;

import org.ice4j.TransportAddress;
import org.ice4j.ice.nio.IceTransport;
import org.ice4j.socket.IceSocketWrapper;
import org.ice4j.stack.StunStack;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * LocalCandidates are obtained by an agent for every stream component and are then included in outgoing offers or answers.
 *
 * @author Emil Ivov
 * @author Lyubomir Marinov
 */
public abstract class LocalCandidate extends Candidate<LocalCandidate> {

    protected Logger logger = LoggerFactory.getLogger(getClass());
    
    /**
     * The type of method used to discover this candidate ("host", "upnp", "stun peer reflexive", "stun server reflexive", "turn relayed", "google turn
     * relayed", "google tcp turn relayed" or "jingle node").
     */
    private CandidateExtendedType extendedType;

    /**
     * Whether this LocalCandidate uses SSL.
     */
    private boolean isSSL;
    
    /**
     * Creates a LocalCandidate instance for the specified transport address and properties.
     *
     * @param transportAddress  the transport address that this candidate is encapsulating
     * @param parentComponent the Component that this candidate belongs to
     * @param type the CandidateType for this Candidate
     * @param extendedType The type of method used to discover this candidate ("host", "upnp", "stun peer reflexive", "stun server reflexive", "turn
     * relayed", "google turn relayed", "google tcp turn relayed" or "jingle node")
     * @param relatedCandidate the relatedCandidate: null for a host candidate, the base address (host candidate) for a reflexive candidate, the mapped
     * address (the mapped address of the TURN allocate response) for a relayed candidate
     */
    public LocalCandidate(TransportAddress transportAddress, Component parentComponent, CandidateType type, CandidateExtendedType extendedType, LocalCandidate relatedCandidate) {
        super(transportAddress, parentComponent, type, relatedCandidate);
        this.extendedType = extendedType;
    }

    /**
     * @return the {@link IceSocketWrapper} instance, if any, associated with this candidate. Note that this IS NOT the instance which should be used
     * for reading and writing by the application, and SHOULD NOT be used from outside ice4j (even if a subclass exposes it as public).
     */
    public abstract IceSocketWrapper getCandidateIceSocketWrapper();

    /**
     * @return the {@link IceSocketWrapper} instance for this candidate, associated with a particular remote address.
     * @param remoteAddress the remote address for which to return an associated socket.
     */
    protected IceSocketWrapper getCandidateIceSocketWrapper(SocketAddress remoteAddress) {
        logger.debug("getCandidateIceSocketWrapper remote: {}", remoteAddress);
        // The default implementation just refers to the method which doesn't involve a remove address.
        // Extenders which support multiple instances mapped by remote address should override.
        IceSocketWrapper iceSocket = IceTransport.getIceHandler().lookupBindingByRemote(remoteAddress);
        logger.warn("Wrapper from lookup: {} current: {}", iceSocket, getCandidateIceSocketWrapper());
        return iceSocket != null ? iceSocket : getCandidateIceSocketWrapper();
    }

    /**
     * Creates if necessary and returns a DatagramSocket that would capture all STUN packets arriving on this candidate's socket. If the
     * serverAddress parameter is not null this socket would only intercept packets originating at this address.
     *
     * @param serverAddress the address of the source (STUN server) to receive packets from or null to intercept any servers packets
     * @return the DatagramSocket that this candidate uses when sending and receiving STUN packets, while harvesting STUN candidates or
     * performing connectivity checks.
     */
    public IceSocketWrapper getStunSocket(TransportAddress serverAddress) {
        logger.debug("getStunSocket local: {}", serverAddress);
        IceSocketWrapper hostSocket = getCandidateIceSocketWrapper();
        return hostSocket;
    }

    /**
     * Gets the StunStack associated with this Candidate.
     *
     * @return the StunStack associated with this Candidate
     */
    public StunStack getStunStack() {
        return getParentComponent().getParentStream().getParentAgent().getStunStack();
    }

    /**
     * Frees resources allocated by this candidate such as its DatagramSocket, for example. The socket of this
     * LocalCandidate is closed only if it is not the socket of the base of this LocalCandidate.
     */
    protected void free() {
        logger.warn("free! {} {}", ufrag, propertyMap);
        // Close the socket associated with this LocalCandidate.
        IceSocketWrapper socket = getCandidateIceSocketWrapper();
        if (socket != null) {
            LocalCandidate base = getBase();
            logger.warn("free! {} {} {}", ufrag, socket.getTransportAddress(), base.propertyMap);
            if (base == null || base == this || base.getCandidateIceSocketWrapper() != socket) {
                // remove our socket from the stack
                getStunStack().removeSocket(socket.getId(), getTransportAddress());
                // allow this LocalCandidate implementation to not create a socket if it still hasn't created one
                socket.close();
            }
        }
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
        return (parentCmp != null) && equals(parentCmp.getDefaultCandidate());
    }

    /**
     * Returns the type of method used to discover this candidate ("host", "upnp", "stun peer reflexive", "stun server reflexive", "turn relayed",
     * "google turn relayed", "google tcp turn relayed" or "jingle node").
     *
     * @return The type of method used to discover this candidate
     */
    public CandidateExtendedType getExtendedType() {
        return this.extendedType;
    }

    /**
     * Sets the type of method used to discover this candidate ("host", "upnp", "stun peer reflexive", "stun server reflexive", "turn relayed", "google
     * turn relayed", "google tcp turn relayed" or "jingle node").
     *
     * @param extendedType The type of method used to discover this candidate
     */
    public void setExtendedType(CandidateExtendedType extendedType) {
        this.extendedType = extendedType;
    }

    /**
     * Find the candidate corresponding to the address given in parameter.
     *
     * @param relatedAddress The related address:
     * - null for a host candidate,
     * - the base address (host candidate) for a reflexive candidate,
     * - the mapped address (the mapped address of the TURN allocate response) for a relayed candidate.
     * - null for a peer reflexive candidate : there is no way to know the related address.
     *
     * @return The related candidate corresponding to the address given in parameter:
     * - null for a host candidate,
     * - the base address (host candidate) for a reflexive candidate,
     * - the mapped address (the mapped address of the TURN allocate response) for a relayed candidate.
     * - null for a peer reflexive candidate : there is no way to know the related address.
     */
    @Override
    protected LocalCandidate findRelatedCandidate(TransportAddress relatedAddress) {
        return getParentComponent().findLocalCandidate(relatedAddress);
    }

    /**
     * Gets the value of the 'ssl' flag.
     * @return the value of the 'ssl' flag.
     */
    public boolean isSSL() {
        return isSSL;
    }

    /**
     * Sets the value of the 'ssl' flag.
     * @param isSSL the value to set.
     */
    public void setSSL(boolean isSSL) {
        this.isSSL = isSSL;
    }

}
