/* See LICENSE.md for license information */
package org.ice4j.ice.harvest;

import java.util.Optional;

import org.ice4j.TransportAddress;
import org.ice4j.ice.Component;
import org.ice4j.ice.HostCandidate;
import org.ice4j.security.LongTermCredential;
import org.slf4j.LoggerFactory;

/**
 * Implements a CandidateHarvester which gathers TURN Candidates for a specified {@link Component}.
 *
 * @author Emil Ivov
 * @author Lubomir Marinov
 */
public class TurnCandidateHarvester extends StunCandidateHarvester {

    {
        logger = LoggerFactory.getLogger(TurnCandidateHarvester.class);
    }

    /**
     * Data for the SSL message sent by the server.
     */
    static final byte[] SSL_SERVER_HANDSHAKE = { 0x16, 0x03, 0x01, 0x00, 0x4a, 0x02, 0x00, 0x00, 0x46, 0x03, 0x01, 0x42, (byte) 0x85, 0x45, (byte) 0xa7, 0x27, (byte) 0xa9, 0x5d, (byte) 0xa0, (byte) 0xb3, (byte) 0xc5, (byte) 0xe7, 0x53, (byte) 0xda, 0x48, 0x2b, 0x3f, (byte) 0xc6, 0x5a, (byte) 0xca, (byte) 0x89, (byte) 0xc1, 0x58, 0x52, (byte) 0xa1, 0x78, 0x3c, 0x5b, 0x17, 0x46, 0x00, (byte) 0x85, 0x3f, 0x20, 0x0e,
            (byte) 0xd3, 0x06, 0x72, 0x5b, 0x5b, 0x1b, 0x5f, 0x15, (byte) 0xac, 0x13, (byte) 0xf9, (byte) 0x88, 0x53, (byte) 0x9d, (byte) 0x9b, (byte) 0xe8, 0x3d, 0x7b, 0x0c, 0x30, 0x32, 0x6e, 0x38, 0x4d, (byte) 0xa2, 0x75, 0x57, 0x41, 0x6c, 0x34, 0x5c, 0x00, 0x04, 0x00 };

    /**
     * Data for the SSL message sent by the client.
     */
    public static final byte[] SSL_CLIENT_HANDSHAKE = { (byte) 0x80, 0x46, 0x01, 0x03, 0x01, 0x00, 0x2d, 0x00, 0x00, 0x00, 0x10, 0x01, 0x00, (byte) 0x80, 0x03, 0x00, (byte) 0x80, 0x07, 0x00, (byte) 0xc0, 0x06, 0x00, 0x40, 0x02, 0x00, (byte) 0x80, 0x04, 0x00, (byte) 0x80, 0x00, 0x00, 0x04, 0x00, (byte) 0xfe, (byte) 0xff, 0x00, 0x00, 0x0a, 0x00, (byte) 0xfe, (byte) 0xfe, 0x00, 0x00, 0x09, 0x00, 0x00, 0x64, 0x00, 0x00,
            0x62, 0x00, 0x00, 0x03, 0x00, 0x00, 0x06, 0x1f, 0x17, 0x0c, (byte) 0xa6, 0x2f, 0x00, 0x78, (byte) 0xfc, 0x46, 0x55, 0x2e, (byte) 0xb1, (byte) 0x83, 0x39, (byte) 0xf1, (byte) 0xea };

    /**
     * The LongTermCredential to be used with the TURN server with which this instance works.
     */
    private final LongTermCredential longTermCredential;

    /**
     * Initializes a new TurnCandidateHarvester instance which is to work with a specific TURN server.
     *
     * @param turnServer the TransportAddress of the TURN server the new instance is to work with
     */
    public TurnCandidateHarvester(TransportAddress turnServer) {
        this(turnServer, (LongTermCredential) null);
    }

    /**
     * Initializes a new TurnCandidateHarvester instance which is to work with a specific TURN server using a specific
     * LongTermCredential.
     *
     * @param turnServer the TransportAddress of the TURN server the new instance is to work with
     * @param longTermCredential the LongTermCredential to use with the specified turnServer or null if the use of the
     * long-term credential mechanism is not determined at the time of the initialization of the new TurnCandidateHarvester instance
     */
    public TurnCandidateHarvester(TransportAddress turnServer, LongTermCredential longTermCredential) {
        super(turnServer, (Optional.ofNullable(longTermCredential).isPresent() ? LongTermCredential.toString(longTermCredential.getUsername()) : null));
        this.longTermCredential = longTermCredential;
        logger.debug("ctor - turnServer: {} longTermCredential: {}", turnServer, longTermCredential);
    }

    /**
     * Initializes a new TurnCandidateHarvester instance which is to work with a specific TURN server using a specific username for the
     * purposes of the STUN short-term credential mechanism.
     *
     * @param turnServer the TransportAddress of the TURN server the new instance is to work with
     * @param shortTermCredentialUsername the username to be used by the new instance for the purposes of the STUN short-term credential mechanism or
     * null if the use of the STUN short-term credential mechanism is not determined at the time of the construction of the new instance
     */
    public TurnCandidateHarvester(TransportAddress turnServer, String shortTermCredentialUsername) {
        super(turnServer, shortTermCredentialUsername);
        this.longTermCredential = null;
    }

    /**
     * Creates a new TurnCandidateHarvest instance which is to perform TURN harvesting of a specific HostCandidate.
     *
     * @param hostCandidate the HostCandidate for which harvesting is to be performed by the new TurnCandidateHarvest instance
     * @return a new TurnCandidateHarvest instance which is to perform TURN harvesting of the specified hostCandidate
     * @see StunCandidateHarvester#createHarvest(HostCandidate)
     */
    @Override
    protected TurnCandidateHarvest createHarvest(HostCandidate hostCandidate) {
        return new TurnCandidateHarvest(this, hostCandidate);
    }

    /**
     * Creates a LongTermCredential to be used by a specific StunCandidateHarvest for the purposes of the long-term
     * credential mechanism in a specific realm of the TURN server associated with this TurnCandidateHarvester. The default
     * implementation returns null and allows an extender to override in order to support the long-term credential mechanism.
     *
     * @param harvest the StunCandidateHarvest which asks for the LongTermCredential
     * @param realm the realm of the TURN server associated with this TurnCandidateHarvester in which harvest will use the
     * returned LongTermCredential
     * @return a LongTermCredential to be used by harvest for the purposes of the long-term credential mechanism in the specified
     * realm of the TURN server associated with this TurnsCandidateHarvester
     * @see StunCandidateHarvester#createLongTermCredential(StunCandidateHarvest,byte[])
     */
    @Override
    protected LongTermCredential createLongTermCredential(StunCandidateHarvest harvest, byte[] realm) {
        return longTermCredential;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((longTermCredential == null) ? 0 : longTermCredential.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!super.equals(obj))
            return false;
        if (getClass() != obj.getClass())
            return false;
        TurnCandidateHarvester other = (TurnCandidateHarvester) obj;
        if (longTermCredential == null) {
            if (other.longTermCredential != null)
                return false;
        } else if (!longTermCredential.equals(other.longTermCredential))
            return false;
        return true;
    }

}
