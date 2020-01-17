/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal. Copyright @ 2015 Atlassian Pty Ltd Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or
 * agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under the License.
 */
package org.ice4j.attribute;

import java.util.*;

import junit.framework.*;

import org.ice4j.*;

/**
 *
 * @author Emil Ivov
 */
public class AddressAttributeTest extends TestCase {

    private MsgFixture msgFixture;

    public AddressAttributeTest(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
        super.setUp();
        msgFixture = new MsgFixture();
    }

    protected void tearDown() throws Exception {
        msgFixture = null;
        super.tearDown();
    }

    /**
     * Verify that AddressAttribute descendants have correctly set types and
     * names.
     */
    public void testAddressAttributeDescendants() {
        AddressAttribute addressAttribute;
        //MAPPED-ADDRESS
        addressAttribute = new MappedAddressAttribute();
        assertEquals("MappedAddressAttribute does not the right type.", Attribute.Type.MAPPED_ADDRESS, addressAttribute.attributeType);

        //SOURCE-ADDRESS
        addressAttribute = new SourceAddressAttribute();
        assertEquals("SourceAddressAttribute does not the right type.", Attribute.Type.SOURCE_ADDRESS, addressAttribute.attributeType);

        //CHANGED-ADDRESS
        addressAttribute = new ChangedAddressAttribute();
        assertEquals("ChangedAddressAttribute does not the right type.", Attribute.Type.CHANGED_ADDRESS, addressAttribute.attributeType);

        //RESPONSE-ADDRESS
        addressAttribute = new ResponseAddressAttribute();
        assertEquals("ResponseAddressAttribute does not the right type.", Attribute.Type.RESPONSE_ADDRESS, addressAttribute.attributeType);

        //REFLECTED-FROM
        addressAttribute = new ReflectedFromAttribute();
        assertEquals("ReflectedFromAttribute does not the right type.", Attribute.Type.REFLECTED_FROM, addressAttribute.attributeType);

        //REFLECTED-FROM
        addressAttribute = new ReflectedFromAttribute();
        assertEquals("ReflectedFromAttribute does not the right type.", Attribute.Type.REFLECTED_FROM, addressAttribute.attributeType);

        //XOR-MAPPED-ADDRESS
        addressAttribute = new XorMappedAddressAttribute();
        assertEquals("XorMappedAddressAttribute does not the right type.", Attribute.Type.XOR_MAPPED_ADDRESS, addressAttribute.attributeType);

        /* ALTERNATE-SERVER */
        addressAttribute = new AlternateServerAttribute();
        assertEquals("AlternateServerAttribute does not the right type.", Attribute.Type.ALTERNATE_SERVER, addressAttribute.attributeType);

        /* XOR-PEER-ADDRESS */
        addressAttribute = new XorPeerAddressAttribute();
        assertEquals("XorPeerAddressAttribute does not the right type.", Attribute.Type.XOR_PEER_ADDRESS, addressAttribute.attributeType);

        /* XOR-RELAYED-ADDRESS */
        addressAttribute = new XorRelayedAddressAttribute();
        assertEquals("XorRelayedAddressAttribute does not the right type.", Attribute.Type.XOR_RELAYED_ADDRESS, addressAttribute.attributeType);
    }

    /**
     * Verifies that xorred address-es are properly xor-ed for IPv4 addresses.
     */
    public void testXorMappedAddressXoring_v4() {
        TransportAddress testAddress = new TransportAddress("130.79.95.53", 12120, Transport.UDP);
        XorMappedAddressAttribute addressAttribute = new XorMappedAddressAttribute(testAddress);

        //do a xor with an id equal to the v4 address itself so that we get 0000..,
        TransportAddress xorredAddr = addressAttribute.applyXor(new byte[] { (byte) 130, 79, 95, 53, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });

        assertTrue("Xorring the address with itself didn't return 00000...", Arrays.equals(xorredAddr.getAddressBytes(), new byte[] { 0, 0, 0, 0 }));

        assertTrue("Port was not xorred", testAddress.getPort() != xorredAddr.getPort());

        //Test xor-ing the original with the xored - should get the xor code
        addressAttribute = new XorMappedAddressAttribute(testAddress);
        xorredAddr = addressAttribute.applyXor(new byte[] { 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36 });

        xorredAddr = addressAttribute.applyXor(xorredAddr.getAddressBytes());

        assertTrue("Xorring the original with the xor-ed didn't " + "return the code..", Arrays.equals(xorredAddr.getAddressBytes(), new byte[] { 21, 22, 23, 24 }));

        assertTrue("Port was not xorred", testAddress.getPort() != 0xFFFF);

        //Test double xor-ing - should get the original
        addressAttribute = new XorMappedAddressAttribute(testAddress);
        xorredAddr = addressAttribute.applyXor(new byte[] { 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36 });

        addressAttribute = new XorMappedAddressAttribute(xorredAddr);
        xorredAddr = addressAttribute.applyXor(new byte[] { 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36 });

        assertEquals("Double xorring didn't give the original ...", testAddress, xorredAddr);
    }

    /**
     * Verifies that xorred address-es are properly xor-ed for IPv6 addresses.
     */
    public void testXorMappedAddressXoring_v6() {
        TransportAddress testAddress = new TransportAddress("2001:660:4701:1001:202:8aff:febe:130b", 12120, Transport.UDP);
        XorMappedAddressAttribute addressAttribute = new XorMappedAddressAttribute(testAddress);
        
        //do a xor with an id equal to the v4 address itself so that we get 0000..,
        TransportAddress xorredAddr = addressAttribute.applyXor(new byte[] { (byte) 0x20, (byte) 0x01, (byte) 0x06, (byte) 0x60, (byte) 0x47, (byte) 0x01, (byte) 0x10, (byte) 0x01, (byte) 0x02, (byte) 0x02, (byte) 0x8a, (byte) 0xff, (byte) 0xfe, (byte) 0xbe, (byte) 0x13, (byte) 0x0b });

        assertTrue("Xorring the address with itself didn't return 00000...", Arrays.equals(xorredAddr.getAddressBytes(), new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }));

        assertTrue("Port was not xorred", testAddress.getPort() != xorredAddr.getPort());

        //Test xor-ing the original with the xored - should get the xor code
        addressAttribute = new XorMappedAddressAttribute(testAddress);
        xorredAddr = addressAttribute.applyXor(new byte[] { 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36 });

        xorredAddr = addressAttribute.applyXor(xorredAddr.getAddressBytes());

        assertTrue("Xorring the original with the xor-ed didn't return the code..", Arrays.equals(xorredAddr.getAddressBytes(), new byte[] { 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36 }));

        assertTrue("Port was not xorred", testAddress.getPort() != 0xFFFF);

        //Test double xor-ing - should get the original
        addressAttribute = new XorMappedAddressAttribute(testAddress);
        xorredAddr = addressAttribute.applyXor(new byte[] { 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36 });

        addressAttribute = new XorMappedAddressAttribute(xorredAddr);
        xorredAddr = addressAttribute.applyXor(new byte[] { 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36 });

        assertEquals("Double xorring didn't give the original ...", testAddress, xorredAddr);
    }

    /**
     * Test whether sample binary arrays are correctly decoded.
     *
     * @throws StunException if something goes wrong
     */
    public void testDecodeAttributeBody() throws StunException {
        byte[] attributeValue = msgFixture.mappedAddress;
        char offset = Attribute.HEADER_LENGTH;
        char length = (char) (attributeValue.length - offset);

        AddressAttribute addressAttribute = new MappedAddressAttribute();
        addressAttribute.decodeAttributeBody(attributeValue, offset, length);

        assertEquals("AddressAttribute.decode() did not properly decode the port field.", MsgFixture.ADDRESS_ATTRIBUTE_PORT, addressAttribute.getPort());
        assertTrue("AddressAttribute.decode() did not properly decode the address field.", Arrays.equals(MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS, addressAttribute.getAddressBytes()));
    }

    /**
     * Test whetner sample binary arrays are correctly decoded.
     * @throws StunException if something goes wrong
     */
    public void testDecodeAttributeBodyv6() throws StunException {
        byte[] attributeValue = msgFixture.mappedAddressv6;
        char offset = Attribute.HEADER_LENGTH;
        char length = (char) (attributeValue.length - offset);

        AddressAttribute addressAttribute = new MappedAddressAttribute();
        addressAttribute.decodeAttributeBody(attributeValue, offset, length);

        assertEquals("decode() failed for an IPv6 Addr's port.", MsgFixture.ADDRESS_ATTRIBUTE_PORT, addressAttribute.getPort());
        assertTrue("AddressAttribute.decode() failed for an IPv6 address.", Arrays.equals(MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS_V6, addressAttribute.getAddressBytes()));
    }

    /**
     * Test whether attributes are properly encoded.
     *
     * @throws Exception java.lang.Exception if we fail
     */
    public void testEncode() throws Exception {
        byte[] expectedReturn = msgFixture.mappedAddress;
        AddressAttribute addressAttribute = new MappedAddressAttribute(new TransportAddress(MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS, MsgFixture.ADDRESS_ATTRIBUTE_PORT, Transport.UDP));
        byte[] actualReturn = addressAttribute.encode();
        assertTrue("AddressAttribute.encode() did not " + "properly encode a sample attribute", Arrays.equals(expectedReturn, actualReturn));
    }

    /**
     * Test whether attributes are properly encoded.
     *
     * @throws Exception java.lang.Exception if we fail
     */
    public void testEncodev6() throws Exception {
        byte[] expectedReturn = msgFixture.mappedAddressv6;
        AddressAttribute addressAttribute = new MappedAddressAttribute(new TransportAddress(MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS_V6, MsgFixture.ADDRESS_ATTRIBUTE_PORT, Transport.UDP));
        byte[] actualReturn = addressAttribute.encode();
        assertTrue("An AddressAttribute did not properly encode an IPv6 addr.", Arrays.equals(expectedReturn, actualReturn));
    }

    /**
     * Tests the equals method against a null, a different and an identical object.
     *
     * @throws Exception java.lang.Exception if we fail
     */
    public void testEquals() throws Exception {
        AddressAttribute addressAttribute = new MappedAddressAttribute();
        //null test
        AddressAttribute target = null;
        boolean expectedReturn = false;
        boolean actualReturn = addressAttribute.equals(target);
        assertEquals("AddressAttribute.equals() failed against a null target.", expectedReturn, actualReturn);

        //difference test
        char port = (char) (MsgFixture.ADDRESS_ATTRIBUTE_PORT + 1);
        target = new MappedAddressAttribute(new TransportAddress(MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS, port, Transport.UDP));
        addressAttribute = new MappedAddressAttribute(new TransportAddress(MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS, MsgFixture.ADDRESS_ATTRIBUTE_PORT, Transport.UDP));

        expectedReturn = false;
        actualReturn = addressAttribute.equals(target);
        assertEquals("AddressAttribute.equals() failed against a different target.", expectedReturn, actualReturn);

        //equality test
        target = new MappedAddressAttribute(new TransportAddress(MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS, MsgFixture.ADDRESS_ATTRIBUTE_PORT, Transport.UDP));

        expectedReturn = true;
        actualReturn = addressAttribute.equals(target);
        assertEquals("AddressAttribute.equals() failed against an equal target.", expectedReturn, actualReturn);

        //ipv6 equality test
        target = new MappedAddressAttribute(new TransportAddress(MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS_V6, MsgFixture.ADDRESS_ATTRIBUTE_PORT, Transport.UDP));
        addressAttribute = new MappedAddressAttribute(new TransportAddress(MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS_V6, MsgFixture.ADDRESS_ATTRIBUTE_PORT, Transport.UDP));

        expectedReturn = true;
        actualReturn = addressAttribute.equals(target);
        assertEquals("AddressAttribute.equals() failed for IPv6 addresses.", expectedReturn, actualReturn);
    }

    /**
     * Tests whether data length is properly calculated.
     *
     * @throws Exception java.lang.Exception if we fail
     */
    public void testGetDataLength() throws Exception {
        int expectedReturn = 8;//1-padding + 1-family + 2-port + 4-address
        AddressAttribute addressAttribute = new MappedAddressAttribute(new TransportAddress(MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS, MsgFixture.ADDRESS_ATTRIBUTE_PORT, Transport.UDP));
        int actualReturn = addressAttribute.getDataLength();
        assertEquals("Datalength is not propoerly calculated", expectedReturn, actualReturn);
        expectedReturn = 20;//1-padding + 1-family + 2-port + 16-address
        addressAttribute = new MappedAddressAttribute(new TransportAddress(MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS_V6, MsgFixture.ADDRESS_ATTRIBUTE_PORT, Transport.UDP));
        actualReturn = addressAttribute.getDataLength();
        assertEquals("Datalength is not propoerly calculated", expectedReturn, actualReturn);
    }

    /**
     * Tests that the address family is always 1.
     *
     * @throws Exception java.lang.Exception if we fail
     */
    public void testGetFamily() throws Exception {
        byte expectedReturn = 1;
        AddressAttribute addressAttribute = new MappedAddressAttribute(new TransportAddress(MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS, MsgFixture.ADDRESS_ATTRIBUTE_PORT, Transport.UDP));
        byte actualReturn = addressAttribute.getFamily();
        assertEquals("Address family was not 1 for an IPv4", expectedReturn, actualReturn);

        //ipv6
        expectedReturn = 2;
        addressAttribute = new MappedAddressAttribute(new TransportAddress(MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS_V6, MsgFixture.ADDRESS_ATTRIBUTE_PORT, Transport.UDP));
        actualReturn = addressAttribute.getFamily();
        assertEquals("Address family was not 2 for an IPv6 address", expectedReturn, actualReturn);
    }

}
