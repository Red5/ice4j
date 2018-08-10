/* See LICENSE.md for license information */
package org.ice4j.ice;

/**
 * Represents the TCP types for ICE TCP candidates.
 * See http://tools.ietf.org/html/rfc6544
 *
 * @author Boris Grozev
 */
public enum CandidateTcpType {
    /**
     * The "active" TCP candidate type.
     */
    ACTIVE("active"),

    /**
     * The "passive" TCP candidate type.
     */
    PASSIVE("passive"),

    /**
     * The "so" (simultaneous-open) TCP candidate type.
     */
    SO("so");

    /**
     * The name of this CandidateTcpType instance.
     */
    private final String name;

    /**
     * Creates a CandidateTcpType instance with the specified name.
     *
     * @param name the name of the CandidateTcpType instance we'd
     * like to create.
     */
    private CandidateTcpType(String name) {
        this.name = name;
    }

    /**
     * Returns the name of this CandidateTcpType (e.g. "active",
     * "passive", or "so").
     *
     * @return the name of this CandidateTcpType (e.g. "active",
     * "passive", or "so").
     */
    @Override
    public String toString() {
        return name;
    }

    /**
     *
     * Parses the string candidateTcpTypeName and return the
     * corresponding CandidateTcpType instance.
     *
     * @param candidateTcpTypeName the string to parse
     * @return candidateTcpTypeName as an Enum
     * @throws IllegalArgumentException in case candidateTcpTypeName is
     * not a valid or currently supported candidate TCP type.
     */
    public static CandidateTcpType parse(String candidateTcpTypeName) throws IllegalArgumentException {
        for (CandidateTcpType type : values())
            if (type.toString().equals(candidateTcpTypeName))
                return type;

        throw new IllegalArgumentException(candidateTcpTypeName + " is not a currently supported CandidateTcpType");
    }
}
