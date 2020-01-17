/* See LICENSE.md for license information */
package org.ice4j.attribute;

import java.net.*;
import java.util.Arrays;

import org.ice4j.*;

/**
 * This class is used to represent Stun attributes that contain an address. Such
 * attributes are:
 *<ul>
 * <li>MAPPED-ADDRESS
 * <li>RESPONSE-ADDRESS
 * <li>SOURCE-ADDRESS
 * <li>CHANGED-ADDRESS
 * <li>REFLECTED-FROM
 * <li>ALTERNATE-SERVER
 * <li>XOR-PEER-ADDRESS
 * <li>XOR-RELAYED-ADDRESS
 *</ul>
 *<p>
 * The different attributes are distinguished by the attributeType of
 * {@link Attribute}.
 *<p>
 * Address attributes indicate the mapped IP address and
 * port.  They consist of an eight bit address family, and a sixteen bit
 * port, followed by a fixed length value representing the IP address.
 *<pre>
 *  0                   1                   2                   3   
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |x x x x x x x x|    Family     |           Port                |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             Address                           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * </pre>
 * <p>
 * The port is a network byte ordered representation of the mapped port.
 * The address family is always 0x01, corresponding to IPv4.  The first
 * 8 bits of the MAPPED-ADDRESS are ignored, for the purposes of
 * aligning parameters on natural boundaries.  The IPv4 address is 32
 * bits.
 * </p>
 * @author Emil Ivov
 */
abstract class AddressAttribute extends Attribute {
    /**
     * Indicates that this attribute is transporting an IPv4 address
     */
    static final byte ADDRESS_FAMILY_IPV4 = 0x01;

    /**
     * Indicates that this attribute is transporting an IPv6 address
     */
    static final byte ADDRESS_FAMILY_IPV6 = 0x02;

    // transport type
    protected Transport transport = Transport.UDP;

    // family
    protected byte family = ADDRESS_FAMILY_IPV4;

    // address as bytes
    protected byte[] address;

    // port
    protected int port;

    /**
     * The length of the data contained by this attribute in the case of an IPv6 address.
     */
    private static final int DATA_LENGTH_FOR_IPV6 = 20;

    /**
     * The length of the data contained by this attribute in the case of an IPv4 address.
     */
    private static final int DATA_LENGTH_FOR_IPV4 = 8;

    /**
     * Constructs an address attribute with the specified type.
     *
     * @param attributeType the type
     */
    AddressAttribute(char attributeType) {
        super(attributeType);
    }

    /**
     * Constructs an address attribute with the specified type.
     *
     * @param attributeType the type
     */
    public AddressAttribute(Type attributeType) {
        super(attributeType);
    }

    /**
     * Constructs an address attribute with the specified type.
     *
     * @param attributeType the attribute type
     * @param transportAddress the transport address
     */
    public AddressAttribute(Type attributeType, TransportAddress transportAddress) {
        super(attributeType);
        transport = transportAddress.getTransport();
        address = transportAddress.getAddressBytes();
        port = transportAddress.getPort();
        family = address.length == 16 ? ADDRESS_FAMILY_IPV6 : ADDRESS_FAMILY_IPV4;
    }

    /**
     * Verifies that type is a valid address attribute type.
     * 
     * @param type the type to test
     * @return true if the type is a valid address attribute type and false otherwise
     */
    private boolean isTypeValid(int type) {
        switch (Attribute.Type.valueOf(type)) {
            case MAPPED_ADDRESS:
            case RESPONSE_ADDRESS:
            case SOURCE_ADDRESS:
            case CHANGED_ADDRESS:
            case REFLECTED_FROM:
            case XOR_MAPPED_ADDRESS:
            case ALTERNATE_SERVER:
            case XOR_PEER_ADDRESS:
            case XOR_RELAYED_ADDRESS:
            case DESTINATION_ADDRESS:
                return true;
            default:
                return false;
        }
    }

    /**
     * Sets it as this attribute's type.
     *
     * @param type the new type of the attribute
     */
    protected void setAttributeType(char type) {
        if (!isTypeValid(type)) {
            throw new IllegalArgumentException(((int) type) + "is not a valid address attribute!");
        }
        super.setAttributeType(type);
    }

    /**
    * Compares two STUN Attributes. Attributes are considered equal when their type, length, and all data are the same.
    *
    * @param obj the object to compare this attribute with
    * @return true if the attributes are equal and false otherwise
    */
    public boolean equals(Object obj) {
        if (!(obj instanceof AddressAttribute)) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        AddressAttribute att = (AddressAttribute) obj;
        if (att.getAttributeType() != getAttributeType() || att.getPort() != port || !Arrays.equals(att.getAddressBytes(), address)) {
            return false;
        }
        return true;
    }

    /**
     * Returns the length of this attribute's body.
     * 
     * @return the length of this attribute's value (8 bytes)
     */
    public int getDataLength() {
        if (family == ADDRESS_FAMILY_IPV6) {
            return DATA_LENGTH_FOR_IPV6;
        } else {
            return DATA_LENGTH_FOR_IPV4;
        }
    }

    /**
     * Returns a binary representation of this attribute.
     * 
     * @return a binary representation
     */
    public byte[] encode() {
        int type = getAttributeType().getType();
        if (!isTypeValid(type)) {
            throw new IllegalStateException(type + "is not a valid address attribute!");
        }
        byte binValue[] = new byte[HEADER_LENGTH + getDataLength()];
        //Type
        binValue[0] = (byte) (type >> 8);
        binValue[1] = (byte) (type & 0x00FF);
        //Length
        binValue[2] = (byte) (getDataLength() >> 8);
        binValue[3] = (byte) (getDataLength() & 0x00FF);
        //Not used
        binValue[4] = 0x00;
        //Family
        binValue[5] = getFamily();
        //port
        binValue[6] = (byte) (getPort() >> 8);
        binValue[7] = (byte) (getPort() & 0x00FF);
        //address
        if (getFamily() == ADDRESS_FAMILY_IPV6) {
            System.arraycopy(getAddressBytes(), 0, binValue, 8, 16);
        } else {
            System.arraycopy(getAddressBytes(), 0, binValue, 8, 4);
        }
        return binValue;
    }

    /**
     * Returns the address encapsulated by this attribute.
     *
     * @return the transport address or null if the address is invalid
     */
    public TransportAddress getAddress() {
        // XXX we're only going to create a TA when something requests it
        try {
            return new TransportAddress(address, port, Transport.UDP);
        } catch (UnknownHostException e) {
        }
        return null;
    }

    /**
     * Returns the bytes of the address.
     *
     * @return the byte[] array containing the address
     */
    public byte[] getAddressBytes() {
        return address;
    }

    /**
     * Returns the family that the this.address belongs to.
     * 
     * @return the address family
     */
    public byte getFamily() {
        return family;
    }

    /**
     * Returns the port associated with the address contained by the attribute.
     * 
     * @return the port associated with the address
     */
    public int getPort() {
        return port;
    }

    /**
      * Sets this attribute's fields according to attributeValue array.
      *
      * @param attributeValue a binary array containing this attribute's field
      *                       values and NOT containing the attribute header
      * @param offset the position where attribute values begin (most often
      *                  offset is equal to the index of the first byte after
      *                  length)
      * @param length the length of the binary array
      * @throws StunException if attrubteValue contains invalid data
      */
    void decodeAttributeBody(byte[] attributeValue, int offset, int length) throws StunException {
        // skip through padding
        offset++;
        // family
        family = attributeValue[offset++];
        // port
        port = ((char) ((attributeValue[offset++] << 8) | (attributeValue[offset++] & 0xFF)));
        // address
        if (family == ADDRESS_FAMILY_IPV6) {
            address = new byte[16];
        } else {
            //ipv4
            address = new byte[4];
        }
        System.arraycopy(attributeValue, offset, address, 0, address.length);
    }
}
