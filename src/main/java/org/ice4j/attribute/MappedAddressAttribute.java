/* See LICENSE.md for license information */
package org.ice4j.attribute;

import org.ice4j.TransportAddress;

/**
 * The MAPPED-ADDRESS attribute indicates the mapped IP address and
 * port.  It consists of an eight bit address family, and a sixteen bit
 * port, followed by a fixed length value representing the IP address.
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |x x x x x x x x|    Family     |           Port                |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             Address                           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * The port is a network byte ordered representation of the mapped port.
 * The address family is always 0x01, corresponding to IPv4.  The first
 * 8 bits of the MAPPED-ADDRESS are ignored, for the purposes of
 * aligning parameters on natural boundaries.  The IPv4 address is 32
 * bits.
 *
 * @author Emil Ivov
 */
public class MappedAddressAttribute extends AddressAttribute {

    /**
     * Constructor.
     */
    MappedAddressAttribute() {
        super(Attribute.Type.MAPPED_ADDRESS);
    }

    public MappedAddressAttribute(TransportAddress address) {
        super(Attribute.Type.MAPPED_ADDRESS, address);
    }
}
