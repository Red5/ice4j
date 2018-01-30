/* See LICENSE.md for license information */
package org.ice4j;

/**
 * The Transport enumeration contains all currently known transports
 * that ICE may be interacting with (but not necessarily support).
 *
 * @author Emil Ivov
 */
public enum Transport {
    /**
     * Represents a TCP transport.
     */
    TCP("tcp"),

    /**
     * Represents a UDP transport.
     */
    UDP("udp"),

    /**
     * Represents a TLS transport.
     */
    TLS("tls"),

    /**
     * Represents a datagram TLS (DTLS) transport.
     */
    DTLS("dtls"),

    /**
     * Represents an SCTP transport.
     */
    SCTP("sctp"),

    /**
     * Represents an Google's SSL TCP transport.
     */
    SSLTCP("ssltcp");

    /**
     * The name of this Transport.
     */
    private final String transportName;

    /**
     * Creates a Transport instance with the specified name.
     *
     * @param transportName the name of the Transport instance we'd
     * like to create.
     */
    private Transport(String transportName) {
        this.transportName = transportName;
    }

    /**
     * Returns the name of this Transport (e.g. "udp" or
     * "tcp").
     *
     * @return the name of this Transport (e.g. "udp" or
     * "tcp").
     */
    @Override
    public String toString() {
        return transportName;
    }

    /**
     * Returns a Transport instance corresponding to the specified
     * transportName. For example, for name "udp", this method
     * would return {@link #UDP}.
     *
     * @param transportName the name that we'd like to parse.
     * @return a Transport instance corresponding to the specified
     * transportName.
     *
     * @throws IllegalArgumentException in case transportName is
     * not a valid or currently supported transport.
     */
    public static Transport parse(String transportName) throws IllegalArgumentException {
        if (UDP.toString().equals(transportName))
            return UDP;

        if (TCP.toString().equals(transportName))
            return TCP;

        if (TLS.toString().equals(transportName))
            return TLS;

        if (SCTP.toString().equals(transportName))
            return SCTP;

        if (DTLS.toString().equals(transportName))
            return DTLS;

        if (SSLTCP.toString().equals(transportName))
            return SSLTCP;

        throw new IllegalArgumentException(transportName + " is not a currently supported Transport");
    }
}
