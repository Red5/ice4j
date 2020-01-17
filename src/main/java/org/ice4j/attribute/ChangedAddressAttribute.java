/* See LICENSE.md for license information */
package org.ice4j.attribute;

import org.ice4j.TransportAddress;

/**
 * The CHANGED-ADDRESS attribute indicates the IP address and port where
 * responses would have been sent from if the "change IP" and "change
 * port" flags had been set in the CHANGE-REQUEST attribute of the
 * Binding Request.  The attribute is always present in a Binding
 * Response, independent of the value of the flags.  Its syntax is
 * identical to MAPPED-ADDRESS.
 *
 * @author Emil Ivov
 */
public class ChangedAddressAttribute extends AddressAttribute {

    /**
     * Creates a CHANGED_ADDRESS attribute
     */
    public ChangedAddressAttribute() {
        super(Attribute.Type.CHANGED_ADDRESS);
    }

    public ChangedAddressAttribute(TransportAddress address) {
        super(Attribute.Type.CHANGED_ADDRESS, address);
    }
}
