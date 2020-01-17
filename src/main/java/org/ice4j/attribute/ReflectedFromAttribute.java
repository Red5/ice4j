/* See LICENSE.md for license information */
package org.ice4j.attribute;

import org.ice4j.TransportAddress;

/**
 * The REFLECTED-FROM attribute is present only in Binding Responses,
 * when the Binding Request contained a RESPONSE-ADDRESS attribute.  The
 * attribute contains the identity (in terms of IP address) of the
 * source where the request came from.  Its purpose is to provide
 * traceability, so that a STUN server cannot be used as a reflector for
 * denial-of-service attacks.
 *
 * Its syntax is identical to the MAPPED-ADDRESS attribute.
 *
 * @author Emil Ivov
 */
public class ReflectedFromAttribute extends AddressAttribute {

    /**
     * Creates a REFLECTED-FROM attribute
     */
    public ReflectedFromAttribute() {
        super(Attribute.Type.REFLECTED_FROM);
    }

    public ReflectedFromAttribute(TransportAddress address) {
        super(Attribute.Type.REFLECTED_FROM, address);
    }
}
