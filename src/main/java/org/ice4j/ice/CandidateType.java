/* See LICENSE.md for license information */
package org.ice4j.ice;

/**
 * According to the ICE specification, Candidates have a type property which
 * makes them server reflexive, peer reflexive, relayed or host).
 *
 * @author Emil Ivov
 */
public enum CandidateType {
    /**
     * Peer Reflexive Candidate: A candidate whose IP address and port are
     * a binding allocated by a NAT for an agent when it sent a STUN
     * Binding Request through the NAT to its peer.
     */
    PEER_REFLEXIVE_CANDIDATE("prflx"),

    /**
     * A Server Reflexive Candidate is a candidate whose IP address and port
     * are a binding allocated by a NAT for an agent when it sent a
     * packet through the NAT to a server. Server reflexive candidates
     * can be learned by STUN servers using the Binding Request, or TURN
     * servers, which provides both a Relayed and Server Reflexive
     * candidate.
     */
    SERVER_REFLEXIVE_CANDIDATE("srflx"),

    /**
     * A Relayed Candidate is a candidate obtained by sending a TURN Allocate
     * request from a host candidate to a TURN server. The relayed candidate is
     * resident on the TURN server, and the TURN server relays packets back
     * towards the agent.
     */
    RELAYED_CANDIDATE("relay"),

    /**
     * A candidate obtained by binding to a specific port
     * from an interface on the host. This includes both physical
     * interfaces and logical ones, such as ones obtained through Virtual
     * Private Networks (VPNs) and Realm Specific IP (RSIP) [RFC3102]
     * (which lives at the operating system level).
     */
    HOST_CANDIDATE("host"),

    /**
     * A candidate obtained by binding to a specific port
     * from an interface on the host. This includes both physical
     * interfaces and logical ones, such as ones obtained through Virtual
     * Private Networks (VPNs) and Realm Specific IP (RSIP) [RFC3102]
     * (which lives at the operating system level). This is the old name for
     * "host".
     */
    LOCAL_CANDIDATE("local"),

    /**
     * A Server Reflexive Candidate is a candidate whose IP address and port
     * are a binding allocated by a NAT for an agent when it sent a
     * packet through the NAT to a server. Server reflexive candidates
     * can be learned by STUN servers using the Binding Request, or TURN
     * servers, which provides both a Relayed and Server Reflexive
     * candidate. This is the old name for "srflx".
     */
    STUN_CANDIDATE("stun");

    /**
     * The name of this CandidateType instance.
     */
    private final String typeName;

    /**
     * Creates a CandidateType instance with the specified name.
     *
     * @param typeName the name of the CandidateType instance we'd like to create.
     */
    private CandidateType(String typeName) {
        this.typeName = typeName;
    }

    /**
     * Returns the name of this CandidateType (e.g. "host", "prflx", "srflx", or "relay").
     *
     * @return the name of this CandidateType
     */
    @Override
    public String toString() {
        return typeName;
    }

    /**
     * Returns a CandidateType instance corresponding to the specified
     * candidateTypeName. For example, for name "host", this method
     * would return {@link #HOST_CANDIDATE}.
     *
     * @param candidateTypeName the name that we'd like to parse.
     * @return a CandidateType instance corresponding to the specified
     * candidateTypeName.
     *
     * @throws IllegalArgumentException in case candidateTypeName is
     * not a valid or currently supported candidate type.
     */
    public static CandidateType parse(String candidateTypeName) throws IllegalArgumentException {
        if (PEER_REFLEXIVE_CANDIDATE.toString().equals(candidateTypeName))
            return PEER_REFLEXIVE_CANDIDATE;

        if (SERVER_REFLEXIVE_CANDIDATE.toString().equals(candidateTypeName))
            return SERVER_REFLEXIVE_CANDIDATE;

        if (RELAYED_CANDIDATE.toString().equals(candidateTypeName))
            return RELAYED_CANDIDATE;

        if (HOST_CANDIDATE.toString().equals(candidateTypeName))
            return HOST_CANDIDATE;

        // old name but returns the standard name
        if (STUN_CANDIDATE.toString().equals(candidateTypeName))
            return SERVER_REFLEXIVE_CANDIDATE;

        if (LOCAL_CANDIDATE.toString().equals(candidateTypeName))
            return HOST_CANDIDATE;

        throw new IllegalArgumentException(candidateTypeName + " is not a currently supported CandidateType");
    }
}
