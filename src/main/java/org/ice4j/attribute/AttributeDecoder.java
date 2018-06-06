/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal. Copyright @ 2015 Atlassian Pty Ltd Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or
 * agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under the License.
 */
package org.ice4j.attribute;

import org.ice4j.*;

/**
 * The class provides utilities for decoding a binary stream into an Attribute
 * class.
 *
 * @author Emil Ivov
 * @author Sebastien Vincent
 * @author Aakash Garg
 */
public class AttributeDecoder {

    /**
     * Decodes the specified binary array and returns the corresponding
     * attribute object.
     *
     * @param bytes the binary array that should be decoded.
     * @param offset the index where the message starts.
     * @param length the number of bytes that the message is long.
     *
     * @return An object representing the attribute encoded in bytes or null if
     * the attribute was not recognized.
     *
     * @throws StunException if bytes is not a valid STUN attribute.
     */
    public static Attribute decode(byte[] bytes, int offset, int length) throws StunException {
        if (bytes == null || bytes.length < Attribute.HEADER_LENGTH) {
            throw new StunException(StunException.ILLEGAL_ARGUMENT, "Could not decode the specified binary array.");
        }

        //Discover attribute type
        Attribute.Type attributeType = Attribute.Type.valueOf((((bytes[offset] & 0xFF) << 8) | (bytes[offset + 1] & 0xFF)));
        int attributeLength = (((bytes[offset + 2] & 0xFF) << 8) | (bytes[offset + 3] & 0xFF));

        if (attributeLength > bytes.length - offset)
            throw new StunException(StunException.ILLEGAL_ARGUMENT, "Could not decode the specified binary array.");

        Attribute decodedAttribute = null;

        switch (attributeType) {
        /* STUN attributes */
            case CHANGE_REQUEST:
                decodedAttribute = new ChangeRequestAttribute();
                break;
            case CHANGED_ADDRESS:
                decodedAttribute = new ChangedAddressAttribute();
                break;
            case MAPPED_ADDRESS:
                decodedAttribute = new MappedAddressAttribute();
                break;
            case ERROR_CODE:
                decodedAttribute = new ErrorCodeAttribute();
                break;
            case MESSAGE_INTEGRITY:
                decodedAttribute = new MessageIntegrityAttribute();
                break;
            //case PASSWORD: //handle as an unknown attribute
            case REFLECTED_FROM:
                decodedAttribute = new ReflectedFromAttribute();
                break;
            case RESPONSE_ADDRESS:
                decodedAttribute = new ResponseAddressAttribute();
                break;
            case SOURCE_ADDRESS:
                decodedAttribute = new SourceAddressAttribute();
                break;
            case UNKNOWN_ATTRIBUTES:
                decodedAttribute = new UnknownAttributesAttribute();
                break;
            case XOR_MAPPED_ADDRESS:
                decodedAttribute = new XorMappedAddressAttribute();
                break;
            case XOR_ONLY:
                decodedAttribute = new XorOnlyAttribute();
                break;
            case SOFTWARE:
                decodedAttribute = new SoftwareAttribute();
                break;
            case USERNAME:
                decodedAttribute = new UsernameAttribute();
                break;
            case REALM:
                decodedAttribute = new RealmAttribute();
                break;
            case NONCE:
                decodedAttribute = new NonceAttribute();
                break;
            case FINGERPRINT:
                decodedAttribute = new FingerprintAttribute();
                break;
            case ALTERNATE_SERVER:
                decodedAttribute = new AlternateServerAttribute();
                break;
            case CHANNEL_NUMBER:
                decodedAttribute = new ChannelNumberAttribute();
                break;
            case LIFETIME:
                decodedAttribute = new LifetimeAttribute();
                break;
            case XOR_PEER_ADDRESS:
                decodedAttribute = new XorPeerAddressAttribute();
                break;
            case DATA:
                decodedAttribute = new DataAttribute();
                break;
            case XOR_RELAYED_ADDRESS:
                decodedAttribute = new XorRelayedAddressAttribute();
                break;
            case EVEN_PORT:
                decodedAttribute = new EvenPortAttribute();
                break;
            case REQUESTED_TRANSPORT:
                decodedAttribute = new RequestedTransportAttribute();
                break;
            case DONT_FRAGMENT:
                decodedAttribute = new DontFragmentAttribute();
                break;
            case RESERVATION_TOKEN:
                decodedAttribute = new ReservationTokenAttribute();
                break;
            case PRIORITY:
                decodedAttribute = new PriorityAttribute();
                break;
            case ICE_CONTROLLING:
                decodedAttribute = new IceControllingAttribute();
                break;
            case ICE_CONTROLLED:
                decodedAttribute = new IceControlledAttribute();
                break;
            case USE_CANDIDATE:
                decodedAttribute = new UseCandidateAttribute();
                break;
            case REQUESTED_ADDRESS_FAMILY:
                decodedAttribute = new RequestedAddressFamilyAttribute();
                break;
            case CONNECTION_ID:
                decodedAttribute = new ConnectionIdAttribute();
                break;
            default:
                //According to rfc3489 we should silently ignore unknown attributes.
                decodedAttribute = new OptionalAttribute();
                break;
        }

        decodedAttribute.setAttributeType(attributeType);
        decodedAttribute.setLocationInMessage(offset);

        decodedAttribute.decodeAttributeBody(bytes, (Attribute.HEADER_LENGTH + offset), attributeLength);

        return decodedAttribute;
    }
}
