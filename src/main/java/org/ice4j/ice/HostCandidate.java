/* See LICENSE.md for license information */
package org.ice4j.ice;

import java.net.DatagramSocket;

import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.socket.IceSocketWrapper;

/**
 * HostCandidates are obtained by binding to a specific port from an IP address on the host that is running us. This includes IP addresses on
 * physical interfaces and logical ones, such as ones obtained through Virtual Private Networks (VPNs), Mobile IPv6, Realm Specific IP (RSIP) etc.
 * <br>
 * At this point this class only supports UDP candidates. Implementation of support for other transport protocols should mean that this class should
 * become abstract and some transport specific components like to socket for example should be brought down the inheritance chain.
 *
 * @author Emil Ivov
 */
public class HostCandidate extends LocalCandidate {

    /**
     * If this is a local candidate the field contains the socket that is actually associated with the candidate.
     */
    private final IceSocketWrapper socket;

    /**
     * Creates a HostCandidate for the specified transport address.
     *
     * @param socket the {@link DatagramSocket} that communication associated with this Candidate will be going through.
     * @param parentComponent the Component that this candidate belongs to.
     */
    public HostCandidate(IceSocketWrapper socket, Component parentComponent) {
        this(socket, parentComponent, Transport.UDP);
    }

    /**
     * Creates a HostCandidate for the specified transport address.
     *
     * @param transportAddress the transport address for the new HostCandidate.
     * @param parentComponent the Component that this candidate belongs to.
     */
    public HostCandidate(TransportAddress transportAddress, Component parentComponent) {
        super(transportAddress, parentComponent, CandidateType.HOST_CANDIDATE, CandidateExtendedType.HOST_CANDIDATE, null);
        this.socket = null;
        setBase(this);
    }

    /**
     * Creates a HostCandidate for the specified transport address.
     *
     * @param socket the {@link DatagramSocket} that communication associated with this Candidate will be going through.
     * @param parentComponent the Component that this candidate belongs to.
     * @param transport transport protocol used
     */
    public HostCandidate(IceSocketWrapper socket, Component parentComponent, Transport transport) {
        super(new TransportAddress(socket.getLocalAddress(), socket.getLocalPort(), transport), parentComponent, CandidateType.HOST_CANDIDATE, CandidateExtendedType.HOST_CANDIDATE, null);
        this.socket = socket;
        setBase(this);
    }

    /**
     * {@inheritDoc}
     * SHOULD NOT be used outside ice4j. Only exposed for use in the org.ice4j.socket package.
     */
    @Override
    public IceSocketWrapper getCandidateIceSocketWrapper() {
        logger.debug("getCandidateIceSocketWrapper: {}", socket);
        return socket;
    }
}
