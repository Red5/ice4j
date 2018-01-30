/* See LICENSE.md for license information */
package org.ice4j.socket.filter;

import java.net.*;

import org.ice4j.*;
import org.ice4j.message.*;

/**
 * Implements a DatagramPacketFilter which accepts
 * DatagramPackets which represent TURN messages defined in
 * RFC 5766 "Traversal Using Relays around NAT (TURN): Relay Extensions to
 * Session Traversal Utilities for NAT (STUN)" and which are part of the
 * communication with a specific TURN server. TurnDatagramPacketFilter
 * does not accept TURN ChannelData messages because they require knowledge of
 * the value of the "Channel Number" field.
 *
 * @author Lubomir Marinov
 */
public class TurnDatagramPacketFilter extends StunDatagramPacketFilter {

    /**
     * Initializes a new TurnDatagramPacketFilter which will accept
     * DatagramPackets which represent TURN messages and which are part
     * of the communication with a specific TURN server.
     *
     * @param turnServer the TransportAddress of the TURN server
     * DatagramPackets representing TURN messages from and to which
     * will be accepted by the new instance
     */
    public TurnDatagramPacketFilter(TransportAddress turnServer) {
        super(turnServer);
    }

    /**
     * Determines whether a specific DatagramPacket represents a TURN
     * message which is part of the communication with the TURN server
     * associated with this instance.
     *
     * @param p the DatagramPacket to be checked whether it represents
     * a TURN message which is part of the communicator with the TURN server
     * associated with this instance
     * @return true if the specified DatagramPacket represents
     * a TURN message which is part of the communication with the TURN server
     * associated with this instance; otherwise, false
     */
    @Override
    public boolean accept(DatagramPacket p) {
        if (super.accept(p)) {
            // The specified DatagramPacket represents a STUN message with a TURN method.
            return true;
        } else {
            // The specified DatagramPacket does not come from or is not being sent to the TURN server associated with this instance 
            // or is a ChannelData message which is not supported by TurnDatagramPacketFilter.
            return false;
        }
    }

    /**
     * Determines whether this DatagramPacketFilter accepts a
     * DatagramPacket which represents a STUN message with a specific
     * STUN method. TurnDatagramPacketFilter accepts TURN methods.
     *
     * @param method the STUN method of a STUN message represented by a
     * DatagramPacket to be checked whether it is accepted by this
     * DatagramPacketFilter
     * @return true if this DatagramPacketFilter accepts the
     * DatagramPacket which represents a STUN message with the
     * specified STUN method; otherwise, false
     * @see StunDatagramPacketFilter#acceptMethod(char)
     */
    @Override
    protected boolean acceptMethod(char method) {
        if (super.acceptMethod(method)) {
            return true;
        } else {
            switch (method) {
                case Message.TURN_METHOD_ALLOCATE:
                case Message.TURN_METHOD_CHANNELBIND:
                case Message.TURN_METHOD_CREATEPERMISSION:
                case Message.TURN_METHOD_DATA:
                case Message.TURN_METHOD_REFRESH:
                case Message.TURN_METHOD_SEND:
                case 0x0005: /* old TURN DATA indication */
                    return true;
                default:
                    return false;
            }
        }
    }
}
