/* See LICENSE.md for license information */
package org.ice4j.attribute;

/**
 * The XOR-PEER-ADDRESS attribute is given by a TURN client to indicates the peer destination address of its relayed packet.
 *
 * It has the same format as XOR-MAPPED-ADDRESS.
 *
 * @author Sebastien Vincent
 */
public class XorPeerAddressAttribute extends XorMappedAddressAttribute {

    XorPeerAddressAttribute() {
        super(Attribute.Type.XOR_PEER_ADDRESS);
    }
}
