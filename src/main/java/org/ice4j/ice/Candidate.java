/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal. Copyright @ 2015 Atlassian Pty Ltd Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or
 * agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under the License.
 */
package org.ice4j.ice;

import java.net.Inet6Address;
import java.net.InetAddress;

import org.ice4j.Transport;
import org.ice4j.TransportAddress;

/**
 * A candidate represents a transport address that is a potential point of
 * contact for receipt of media. Candidates also have properties - their
 * type (server reflexive, relayed or host), priority, foundation,
 * and base.
 * <p>
 * At this point this class only supports UDP candidates. Implementation of
 * support for other transport protocols should mean that this class should
 * become abstract and some transport specific components like to socket for
 * example should be brought down the inheritance chain.
 * </p>
 *
 * @author Emil Ivov
 * @author Lyubomir Marinov
 */
public abstract class Candidate<T extends Candidate<?>> implements Comparable<T> {
    /**
     * The maximum value for a candidate's type preference.
     */
    public static final int MAX_TYPE_PREFERENCE = 126;

    /**
     * The minimum value for a candidate's type preference.
     */
    public static final int MIN_TYPE_PREFERENCE = 0;

    /**
     * The maximum value for a candidate's local preference.
     */
    public static final int MAX_LOCAL_PREFERENCE = 65535;

    /**
     * The minimum value for a candidate's local preference.
     */
    public static final int MIN_LOCAL_PREFERENCE = 0;

    /**
     * The transport address represented by this candidate.
     */
    private final TransportAddress transportAddress;

    /**
     * The type of this candidate. At this point the ICE specification (and hence this implementation) only defines for candidate types: host,
     * server reflexive, peer reflexive and relayed candidates. Others may be added in the future.
     */
    private CandidateType candidateType;

    /**
     * An arbitrary string that is the same for two candidates that have the same type, base IP address, protocol (UDP, TCP,
     * etc.) and STUN or TURN server. If any of these are different then the foundation will be different. Two candidate pairs with the
     * same foundation pairs are likely to have similar network characteristics. Foundations are used in the frozen algorithm.
     */
    private String foundation;

    /**
     * The base of a server reflexive candidate is the host candidate from which it was derived. A host candidate is also said to have
     * a base, equal to that candidate itself. Similarly, the base of a relayed candidate is that candidate itself.
     */
    private T base;

    /**
     * A unique priority number that MUST be a positive integer between 1 and (2**32 - 1). This priority will be set and used by ICE algorithms to
     * determine the order of the connectivity checks and the relative preference for candidates.
     */
    protected long priority = 0;

    /**
     * Specifies whether the address associated with this candidate belongs to a VPN interface. In many cases (e.g. when running on a 1.5 JVM) we won't
     * be able to determine whether an interface is virtual or not. If we are however (that is when running a more recent JVM) we will reflect it in
     * this property.
     */
    private boolean virtual;

    /**
     * The component that this candidate was created for. Every candidate is always associated with a specific component for which it is a candidate.
     */
    private final Component parentComponent;

    /**
     * The address of the STUN server that was used to obtain this Candidate. Will be null if this is not a server reflexive candidate.
     */
    private TransportAddress stunServerAddress;

    /**
     * The address of the relay server (i.e. TURN, Jingle Nodes, ...) that was used to obtain this Candidate. Will be null if this is
     * not a relayed candidate.
     */
    private TransportAddress relayServerAddress;

    /**
     * The address that our TURN/STUN server returned as mapped if this is a relayed or a reflexive Candidate. Will remain null if
     * this is a host candidate.
     */
    private TransportAddress mappedAddress;

    /**
     * The related candidate:
     * - null for a host candidate
     * - the base address (host candidate) for a reflexive candidate
     * - the mapped address (the mapped address of the TURN allocate response) for a relayed candidate
     * - null for a peer reflexive candidate : there is no way to know the related address
     */
    private T relatedCandidate;

    /**
     * The CandidateTcpType for this Candidate.
     */
    private CandidateTcpType tcpType;

    /**
     * Creates a candidate for the specified transport address and properties.
     *
     * @param transportAddress  the transport address that this candidate is encapsulating
     * @param parentComponent the Component that this candidate belongs to
     * @param type the CandidateType for this Candidate
     * @param relatedCandidate The related candidate:
     * - null for a host candidate
     * - the base address (host candidate) for a reflexive candidate
     * - the mapped address (the mapped address of the TURN allocate response) for a relayed candidate
     * - null for a peer reflexive candidate : there is no way to know the related address
     */
    public Candidate(TransportAddress transportAddress, Component parentComponent, CandidateType type, T relatedCandidate) {
        this.transportAddress = transportAddress;
        this.parentComponent = parentComponent;
        this.candidateType = type;
        this.relatedCandidate = relatedCandidate;
    }

    /**
     * Returns the type of this candidate which should be an instance of the {@link CandidateType} enumeration.
     *
     * @return a CandidateType indicating the type of this Candidate.
     */
    public CandidateType getType() {
        return candidateType;
    }

    /**
     * Sets the type of this candidate which should be an instance of the {@link CandidateType} enumeration.
     *
     * @param candidateType a CandidateType instance indicating the type of this Candidate.
     */
    public void setCandidateType(CandidateType candidateType) {
        this.candidateType = candidateType;
    }

    /**
     * Returns a String containing the foundation of this Candidate. A foundation is an arbitrary String that is
     * the same for candidates that have the same type, base IP address, transport protocol (UDP, TCP, etc.) and STUN or TURN server. If any of
     * these are different then the foundation will be different. Two candidate pairs with the same foundation pairs are likely to have similar network
     * characteristics. Typically, candidates for RTP and RTCP streams will share the same foundation. Foundations are used in the frozen algorithm.
     *
     * @return the foundation of this Candidate.
     */
    public String getFoundation() {
        return foundation;
    }

    /**
     * Sets this Candidate's foundation. A foundation is an arbitrary string that is always the same for candidates that have the same type,
     * base IP address, protocol (UDP, TCP, etc.) and STUN or TURN server. If any of these are different then the foundation will be different. Two
     * candidate pairs with the same foundation pairs are likely to have similar network characteristics. Foundations are used in the frozen algorithm.
     *
     * @param foundation the foundation of this Candidate.
     */
    public void setFoundation(String foundation) {
        this.foundation = foundation;
    }

    /**
     * Returns this Candidate's base. The base of a server reflexive candidate is the host candidate from which it was derived.
     * A host candidate is also said to have a base, equal to that candidate itself. Similarly, the base of a relayed candidate is that candidate
     * itself.
     *
     * @return the base Candidate for this Candidate.
     */
    public T getBase() {
        return base;
    }

    /**
     * Sets this Candidate's base. The base of a server reflexive candidate is the host candidate from which it was derived.
     * A host candidate is also said to have a base, equal to that candidate itself. Similarly, the base of a relayed candidate is that candidate
     * itself.
     *
     * @param base the base Candidate of this Candidate.
     */
    public void setBase(T base) {
        this.base = base;
    }

    /**
     * Returns the priority of this candidate. Priority is a unique priority number that MUST be a positive integer between 1 and (2**32 - 1). This
     * priority will be set and used by ICE algorithms to  determine the order of the connectivity checks and the relative preference for candidates.
     *
     * @return a number between 1 and (2**32 - 1) indicating the priority of this candidate.
     */
    public long getPriority() {
        return priority;
    }

    /**
     * Returns the transport address that this candidate is representing.
     *
     * @return the TransportAddress encapsulated by this Candidate.
     */
    public TransportAddress getTransportAddress() {
        return transportAddress;
    }

    /**
     * Indicates whether some other Candidate is "equal to" this one. We consider candidates equal when they are redundant, i.e.
     * <p>
     * @param obj the reference object with which to compare.
     * <p>
     * @return <code>true</code> if this Candidate is equal to the obj argument; <code>false</code> otherwise.
     * @throws java.lang.NullPointerException if obj is null;
     */
    @Override
    public boolean equals(Object obj) throws NullPointerException {
        if (obj == this)
            return true;

        if (!(obj instanceof Candidate))
            return false;

        Candidate<?> candidate = (Candidate<?>) obj;

        //compare candidate addresses
        if (!candidate.getTransportAddress().equals(getTransportAddress()))
            return false;

        //compare bases
        Candidate<?> base = getBase();
        Candidate<?> candidateBase = candidate.getBase();
        boolean baseEqualsCandidateBase;

        if (base == null) {
            if (candidateBase != null)
                return false;
            else
                baseEqualsCandidateBase = true;
        } else {
            // If this and candidate are bases of themselves, their bases are
            // considered equal.
            baseEqualsCandidateBase = (base == this && candidateBase == candidate) || base.equals(candidateBase);
        }

        //compare other properties
        return baseEqualsCandidateBase && getPriority() == candidate.getPriority() && getType() == candidate.getType() && getFoundation().equals(candidate.getFoundation());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {
        // Even if the following hashCode algorithm has drawbacks because of it simplicity, it is better than nothing because at least it allows
        // Candidate and, respectively, CandidatePair to be used as HashMap keys.
        return getParentComponent().hashCode() + getTransportAddress().hashCode();
    }

    /**
     * Returns a reference to the Component that this candidate belongs to.
     *
     * @return a reference to the Component that this candidate belongs to.
     */
    public Component getParentComponent() {
        return parentComponent;
    }

    /**
     * Computes the priority for this Candidate based on the procedures defined in the ICE specification..
     *
     * @return the priority for this Candidate as per the procedures defined in the ICE specification..
     */
    public long computePriority() {
        this.priority = computePriorityForType(getType());
        return this.priority;
    }

    /**
     * Computes the priority this Candidate would have if it were of the specified candidateType and based on the procedures
     * defined in the ICE specification. The reason we need this method in addition to the {@link #computePriority()} one is the need to be able
     * to compute the priority of a peer reflexive candidate that we might learn during connectivity checks through this Candidate.
     *
     * @param candidateType the hypothetical type that we'd like to use when computing the priority for this Candidate
     * @return the priority this Candidate would have had if it were of the specified candidateType
     */
    public long computePriorityForType(CandidateType candidateType) {
        //According to the ICE spec we compute priority this way:
        //priority = (2^24)*(type preference) +
        //           (2^8)*(local preference) +
        //           (2^0)*(256 - component ID)
        return (long) (getTypePreference(candidateType) << 24) + (long) (getLocalPreference() << 8) + (long) (256 - getParentComponent().getComponentID());
    }

    /**
     * Returns the type preference that should be used when computing priority for Candidates of the specified candidateType.
     * The type preference MUST be an integer from 0 to 126 inclusive, and represents the preference for the type of the candidate
     * (where the types are local, server reflexive, peer reflexive and relayed). A 126 is the highest preference, and a 0 is
     * the lowest. Setting the value to a 0 means that candidates of this type will only be used as a last resort. The type preference MUST
     * be identical for all candidates of the same type and MUST be different for candidates of different types. The type preference for peer
     * reflexive candidates MUST be higher than that of server reflexive candidates.
     *
     * @param candidateType the CandidateType that we'd like to obtain a preference for
     * @return the type preference for this Candidate as per the procedures in the ICE specification
     */
    private static int getTypePreference(CandidateType candidateType) {
        /*
         * https://tools.ietf.org/html/rfc5245#page-25 It is RECOMMENDED that default candidates be chosen based on the likelihood of those candidates to work with the peer that is
         * being contacted. It is RECOMMENDED that the default candidates are the relayed candidates (if relayed candidates are available), server reflexive candidates (if server
         * reflexive candidates are available), and finally host candidates.
         */
        int typePreference;
        switch (candidateType) {
            case SERVER_REFLEXIVE_CANDIDATE:
                typePreference = 100;
                break;
            case PEER_REFLEXIVE_CANDIDATE:
                typePreference = 110;
                break;
            case RELAYED_CANDIDATE:
                typePreference = MAX_TYPE_PREFERENCE; // 126
                break;
            case HOST_CANDIDATE:
                typePreference = 40;
                break;
            default:
                typePreference = MIN_TYPE_PREFERENCE;
        }
        return typePreference;
    }

    /**
     * Calculates and returns the local preference for this Candidate
     * <p>
     * The local preference MUST be an integer from 0 to 65535 inclusive. It represents a preference for the particular IP address from
     * which the candidate was obtained, in cases where an agent is multihomed. 65535 represents the highest preference, and a zero, the lowest.
     * When there is only a single IP address, this value SHOULD be set to 65535. More generally, if there are multiple candidates for a
     * particular component for a particular media stream which have the same type, the local preference MUST be unique for each one. In this
     * specification, this only happens for multihomed hosts.  If a host is multihomed because it is dual stacked, the local preference SHOULD be
     * set equal to the precedence value for IP addresses described in RFC 3484.
     * <br>
     * @return the local preference for this Candidate.
     */
    private int getLocalPreference() {
        // ICE spec says: When there is only a single IP address, this value SHOULD be set to.
        if (getParentComponent().countLocalHostCandidates() < 2) {
            return MAX_LOCAL_PREFERENCE;
        }
        // ICE spec also says: Furthermore, if an agent is multi-homed and has multiple IP addresses, the local preference for host candidates
        //from a VPN interface SHOULD have a priority of 0.
        if (isVirtual()) {
            return MIN_LOCAL_PREFERENCE;
        }
        InetAddress addr = getTransportAddress().getAddress();
        // the following tries to reuse precedence from RFC 3484 but that's a bit tricky
        // prefer IPv6 to IPv4
        if (addr instanceof Inet6Address) {
            //prefer link local addresses to global ones
            if (addr.isLinkLocalAddress()) {
                return 30;
            } else {
                return 40;
            }
        } else {
            //IPv4
            return 10;
        }
    }

    /**
     * Determines whether the address associated with this candidate belongs to a VPN interface. In many cases (e.g. when running on a 1.5 JVM) we won't
     * be able to determine whether an interface is virtual or not. If we are however (that is when running a more recent JVM) we will reflect it in
     * this property. Note that the isVirtual property is not really an ICE concept. The ICE specs only mention it and give basic guidelines
     * as to how it should be handled so other implementations maybe dealing with it differently.
     *
     * @return true if we were able to determine that the address associated with this Candidate comes from a virtual interface
     * and false if otherwise.
     */
    public boolean isVirtual() {
        return virtual;
    }

    /**
     * Specifies whether the address associated with this candidate belongs to a VPN interface. In many cases (e.g. when running on a 1.5 JVM) we won't
     * be able to determine whether an interface is virtual or not. If we are however (that is when running a more recent JVM) we will reflect it in
     * this property. Note that the isVirtual property is not really an ICE concept. The ICE specs only mention it and give basic guidelines
     * as to how it should be handled so other implementations maybe dealing with it differently.
     *
     * @param virtual true if we were able to determine that the address associated with this Candidate comes from a virtual
     * interface and false if otherwise.
     */
    public void setVirtual(boolean virtual) {
        this.virtual = virtual;
    }

    /**
     * Returns the address of the STUN server that was used to obtain this Candidate or null if this is not a server reflexive candidate.
     *
     * @return the address of the STUN server
     */
    public TransportAddress getStunServerAddress() {
        return stunServerAddress;
    }

    /**
     * Sets the address of the STUN server that was used to obtain this Candidate. Only makes sense if this is a relayed candidate.
     *
     * @param address the address of the STUN server that was used to obtain this Candidate or null if this is not a server
     * reflexive candidate
     */
    protected void setStunServerAddress(TransportAddress address) {
        this.stunServerAddress = address;
    }

    /**
     * Returns the address of the relay server (i.e. TURN, Jingle Nodes, ...) that was used to obtain this Candidate or null if this
     * is not a relayed candidate.
     *
     * @return the address of the relay server that was used to obtain this Candidate or null if this is not a relayed candidate
     */
    public TransportAddress getRelayServerAddress() {
        return relayServerAddress;
    }

    /**
     * Sets the address of the relay server (i.e. TURN, Jingle Nodes, ...) that was used to obtain this Candidate. Only makes sense if this is a
     * relayed candidate.
     *
     * @param address the address of the relay server that was used to obtain this Candidate or null if this is not a relayed
     * candidate
     */
    protected void setRelayServerAddress(TransportAddress address) {
        this.relayServerAddress = address;
    }

    /**
     * Returns the address that was returned to us a "mapped address" from a
     * TURN or a STUN server in case this Candidate is relayed or
     * reflexive and null otherwise. Note that the address returned by
     * this method would be equal to the transport address for reflexive
     * Candidates but not for relayed ones.
     *
     * @return the address that our TURN/STUN server returned as mapped if this
     * is a relayed or a reflexive Candidate or null if this
     * is a host candidate.
     */
    public TransportAddress getMappedAddress() {
        return mappedAddress;
    }

    /**
     * Sets the address that was returned to us a "mapped address" from a
     * TURN or a STUN server in case this Candidate is relayed.
     *
     * @param address the address that our TURN/STUN server returned as mapped
     * if this is a relayed or a reflexive Candidate.
     */
    protected void setMappedAddress(TransportAddress address) {
        this.mappedAddress = address;
    }

    /**
     * Returns the Transport for this Candidate. This is a
     * convenience method only and it is equivalent to retrieving the transport
     * of this Candidate's transport address.
     *
     * @return the Transport that this Candidate was obtained
     * for/with.
     */
    public Transport getTransport() {
        return getTransportAddress().getTransport();
    }

    /**
     * Returns a TransportAddress related to this Candidate.
     * Related addresses are present for server reflexive, peer reflexive and
     * relayed candidates. If a candidate is server or peer reflexive,
     * the related address is equal to the base of this Candidate.
     * If the candidate is relayed, the returned address is equal to the mapped
     * address. If the candidate is a host candidate then the method returns
     * null.
     *
     * @return the TransportAddress of the base if this is a reflexive
     * candidate, the mapped address in the case of a relayed candidate, and
     * null if this is a host or a remote candidate.
     */
    public TransportAddress getRelatedAddress() {
        if (getRelatedCandidate() != null) {
            return getRelatedCandidate().getTransportAddress();
        }
        return null;
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
    protected abstract T findRelatedCandidate(TransportAddress relatedAddress);

    /**
     * Returns a String representation of this Candidate
     * containing its TransportAddress, base, foundation, priority and
     * whatever other properties may be relevant.
     *
     * @return a String representation of this Candidate.
     */
    @Override
    public String toString() {
        StringBuilder buff = new StringBuilder("candidate:");
        buff.append(getFoundation());
        buff.append(" ").append(getParentComponent().getComponentID());
        buff.append(" ").append(getTransport());
        buff.append(" ").append(getPriority());
        buff.append(" ").append(getTransportAddress().getHostAddress());
        buff.append(" ").append(getTransportAddress().getPort());
        buff.append(" typ ").append(getType());
        CandidateTcpType tcpType = getTcpType();
        if (tcpType != null) {
            buff.append(" tcptype ").append(tcpType);
        }
        TransportAddress relAddr = getRelatedAddress();
        if (relAddr != null) {
            buff.append(" raddr ").append(relAddr.getHostAddress());
            buff.append(" rport ").append(relAddr.getPort());
        }
        return buff.toString();
    }

    /**
     * Returns short String representation of this Candidate.
     * @return short String representation of this Candidate.
     */
    public String toShortString() {
        return getTransportAddress() + "/" + getType();
    }

    /**
     * Returns an integer indicating the preference that this Candidate should be considered with for becoming a default candidate.
     *
     * @return an integer indicating the preference that this Candidate should be considered with for becoming a default candidate.
     */
    protected int getDefaultPreference() {
        // https://tools.ietf.org/html/rfc5245#section-4.1.4
        //
        // It is RECOMMENDED that default candidates be chosen based on the likelihood of those candidates to work with the peer that is being
        // contacted.  It is RECOMMENDED that the default candidates are the relayed candidates (if relayed candidates are available), server
        // reflexive candidates (if server reflexive candidates are available), and finally host candidates.
        switch (getType()) {
            case RELAYED_CANDIDATE:
                return 30;
            case SERVER_REFLEXIVE_CANDIDATE:
                return 20;
            case HOST_CANDIDATE:
                // Prefer IPv4 as default since many servers would still freak out when seeing IPv6 address.
                return getTransportAddress().isIPv6() ? 10 : 15;
            default:
                // WTF?
                return 5;
        }
    }

    /**
     * Determines whether this Candidate'sTransportAddress is theoretically usable for communication with that of dst. Same
     * as calling:
     * <p>
     *  getTransportAddress().canReach(dst.getTransportAddress())
     * <br>
     *
     * @param dst the Candidate that we'd like to check for reachability from this one
     * @return true if this {@link Candidate} shares the same Transport and family as dst or false otherwise
     */
    public boolean canReach(Candidate<?> dst) {
        return getTransportAddress().canReach(dst.getTransportAddress());
    }

    /**
     * Determines whether this Candidate is the default one for its parent component.
     *
     * @return true if this Candidate is the default for its parent component and false if it isn't or if it has no parent
     * Component yet
     */
    public abstract boolean isDefault();

    /**
     * Get the local ufrag.
     *
     * @return local ufrag
     */
    public abstract String getUfrag();

    /**
     * Returns this candidate host address.
     *
     * @return This candidate host address.
     */
    public TransportAddress getHostAddress() {
        switch (getType()) {
            case SERVER_REFLEXIVE_CANDIDATE:
            case PEER_REFLEXIVE_CANDIDATE:
                if (getBase() != null) {
                    return getBase().getHostAddress();
                }
                break;
            case RELAYED_CANDIDATE:
                if (getRelatedCandidate() != null) {
                    return getRelatedCandidate().getHostAddress();
                }
                break;
            default: //host candidate
                return getTransportAddress();
        }
        return null;
    }

    /**
     * Returns this candidate reflexive address.
     *
     * @return This candidate reflexive address. Null if this candidate does not use a peer/server reflexive address.
     */
    public TransportAddress getReflexiveAddress() {
        switch (getType()) {
            case SERVER_REFLEXIVE_CANDIDATE:
            case PEER_REFLEXIVE_CANDIDATE:
                return getTransportAddress();
            case RELAYED_CANDIDATE:
                // Corresponding to getMappedAddress();
                if (getRelatedCandidate() != null) {
                    return getRelatedCandidate().getReflexiveAddress();
                }
                break;
            default: //host candidate
                return null;
        }
        return null;
    }

    /**
     * Returns this candidate relayed address.
     *
     * @return This candidate relayed address. Null if this candidate does not use a relay.
     */
    public TransportAddress getRelayedAddress() {
        switch (getType()) {
            case RELAYED_CANDIDATE:
                return getTransportAddress();
            case SERVER_REFLEXIVE_CANDIDATE:
            case PEER_REFLEXIVE_CANDIDATE:
            default: //host candidate
                return null;
        }
    }

    /**
     * Returns the related candidate corresponding to the address given in parameter:
     * - null for a host candidate
     * - the base address (host candidate) for a reflexive candidate
     * - the mapped address (the mapped address of the TURN allocate response) for a relayed candidate
     * - null for a peer reflexive candidate : there is no way to know the related address
     *
     * @return related candidate corresponding to the address given in parameter
     */
    public T getRelatedCandidate() {
        if (this.relatedCandidate == null) {
            TransportAddress relatedAddress = null;
            switch (getType()) {
                case SERVER_REFLEXIVE_CANDIDATE:
                case PEER_REFLEXIVE_CANDIDATE:
                    if (getBase() != null) {
                        relatedAddress = getBase().getTransportAddress();
                    }
                    break;
                case RELAYED_CANDIDATE:
                    relatedAddress = getMappedAddress();
                    break;
                default:
                    //host candidate
                    return null;
            }
            // Update the related candidate conforming to the related address.
            this.relatedCandidate = findRelatedCandidate(relatedAddress);
        }
        return this.relatedCandidate;
    }

    /**
     * Compares this Candidate with the specified one based on their priority and returns a negative integer, zero, or a positive integer if
     * this Candidate has a lower, equal, or greater priority than the second.
     *
     * @param candidate the second Candidate to compare
     * @return a negative integer, zero, or a positive integer as the first Candidate has a lower, equal, or greater priority than the
     * second
     */
    public int compareTo(T candidate) {
        return CandidatePrioritizer.compareCandidates(this, candidate);
    }

    /**
     * Gets the CandidateTcpType for this Candidate.
     * @return the CandidateTcpType for this Candidate.
     */
    public CandidateTcpType getTcpType() {
        return tcpType;
    }

    /**
     * Sets the CandidateTcpType for this Candidate.
     * @param tcpType the CandidateTcpType to set.
     */
    public void setTcpType(CandidateTcpType tcpType) {
        this.tcpType = tcpType;
    }

}
