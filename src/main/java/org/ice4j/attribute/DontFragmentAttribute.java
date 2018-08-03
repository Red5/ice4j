/* See LICENSE.md for license information */
package org.ice4j.attribute;

import org.ice4j.*;

/**
 * The DONT-FRAGMENT attribute is used to inform TURN
 * server (if it supports this attribute) that it should set DF bit to 1
 * in IPv4 headers when relaying client data.
 *
 * @author Sebastien Vincent
 */
public class DontFragmentAttribute extends Attribute {

    /**
     * The length of the data contained by this attribute.
     */
    public static final int DATA_LENGTH = 0;

    /**
     * Constructor.
     */
    DontFragmentAttribute() {
        super(Attribute.Type.DONT_FRAGMENT);
    }

    /**
     * Compares two STUN Attributes. Attributes are considered equal when their
     * type, length, and all data are the same.
     * @param obj the object to compare this attribute with.
     * @return true if the attributes are equal and false otherwise.
     */
    public boolean equals(Object obj) {
        if (!(obj instanceof DontFragmentAttribute))
            return false;

        return true;
    }

    /**
     * Returns the length of this attribute's body.
     * @return the length of this attribute's value (8 bytes).
     */
    public int getDataLength() {
        return DATA_LENGTH;
    }

    /**
     * Returns a binary representation of this attribute.
     * @return a binary representation of this attribute.
     */
    public byte[] encode() {
        /* there is no data */
        byte binValue[] = new byte[HEADER_LENGTH];

        //Type
        int type = getAttributeType().getType();
        binValue[0] = (byte) (type >> 8);
        binValue[1] = (byte) (type & 0x00FF);
        //Length
        binValue[2] = (byte) (getDataLength() >> 8);
        binValue[3] = (byte) (getDataLength() & 0x00FF);

        return binValue;
    }

    /**
     * Sets this attribute's fields according to attributeValue array.
     * @param attributeValue a binary array containing this attribute's field
     *                       values and NOT containing the attribute header.
     * @param offset the position where attribute values begin (most often
     *          offset is equal to the index of the first byte after
     *          length)
     * @param length the length of the binary array.
     * @throws StunException if attrubteValue contains invalid data.
     */
    void decodeAttributeBody(byte[] attributeValue, int offset, int length) throws StunException {
        if (length != 0) {
            throw new StunException("length invalid");
        }
    }
}
