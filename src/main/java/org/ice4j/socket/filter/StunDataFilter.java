package org.ice4j.socket.filter;

import org.ice4j.TransportAddress;
import org.ice4j.message.Message;

/**
 * Implements a DataFilter which only accepts data which represent STUN messages defined in RFC 5389
 * "Session Traversal Utilities for NAT (STUN)" i.e. with method Binding or the reserved method 0x000 and 0x002/SharedSecret.
 *
 * @author Paul Gregoire
 */
public class StunDataFilter implements DataFilter {

    /**
     * Server address to use for filtering.
     */
    private TransportAddress serverAddress;

    /**
     * Provides a means to filter data from anywhere.
     */
    public StunDataFilter() {
    }

    /**
     * Provides a means to filter data only from a designated address.
     * 
     * @param serverAddress
     */
    public StunDataFilter(TransportAddress serverAddress) {
        this.serverAddress = serverAddress;
    }

    /**
     * Determines whether data in a byte array represents a STUN message.
     * <br>
     * {@inheritDoc}
     */
    @Override
    public boolean accept(byte[] buf) {
        // If this is a STUN packet
        boolean isStunPacket = false;
        // All STUN messages MUST start with a 20-byte header followed by zero or more Attributes
        if (buf.length >= 20) {
            // If the MAGIC COOKIE is present this is a STUN packet (RFC5389 compliant).
            if (buf[4] == Message.MAGIC_COOKIE[0] && buf[5] == Message.MAGIC_COOKIE[1] && buf[6] == Message.MAGIC_COOKIE[2] && buf[7] == Message.MAGIC_COOKIE[3]) {
                isStunPacket = true;
            } else {
                // Else, this packet may be a STUN packet (RFC3489 compliant). To determine this, we must continue the checks.
                // The most significant 2 bits of every STUN message MUST be zeroes.  This can be used to differentiate STUN packets from
                // other protocols when STUN is multiplexed with other protocols on the same port.
                byte b0 = buf[0];
                boolean areFirstTwoBitsValid = ((b0 & 0xC0) == 0);
                // Checks if the length of the data correspond to the length field of the STUN header. The message length field of the
                // STUN header does not include the 20-byte of the STUN header.
                int total_header_length = ((((int) buf[2]) & 0xff) << 8) + (((int) buf[3]) & 0xff) + 20;
                boolean isHeaderLengthValid = (buf.length == total_header_length);
                isStunPacket = areFirstTwoBitsValid && isHeaderLengthValid;
            }
        }
        if (isStunPacket) {
            byte b0 = buf[0];
            byte b1 = buf[1];
            // we only accept the method Binding and the reserved methods 0x000 and 0x002/SharedSecret
            int method = (b0 & 0xFE) | (b1 & 0xEF);
            switch (method) {
                case Message.STUN_METHOD_BINDING:
                case Message.STUN_REQUEST:
                case Message.SHARED_SECRET_REQUEST:
                    return true;
            }
        }
        return false;
    }


    /**
     * Determines whether data in a byte array represents a STUN message.
     * 
     * @param buf
     * @param serverAddress
     */
    public boolean accept(byte[] buf, TransportAddress address) {
        if (serverAddress == null || (serverAddress != null && serverAddress.equals(address))) {
            return accept(buf);
        }
        return false;
    }

}
