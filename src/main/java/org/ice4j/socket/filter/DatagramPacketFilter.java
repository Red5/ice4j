/* See LICENSE.md for license information */
package org.ice4j.socket.filter;

import java.net.*;

/**
 * Represents a filter which selects or deselects DatagramPackets.
 *
 * @author Lubomir Marinov
 */
public interface DatagramPacketFilter {
    /**
     * Determines whether a specific DatagramPacket is accepted by this filter i.e. whether the caller should include the specified
     * DatagramPacket in a selection based on this filter.
     *
     * @param p the DatagramPacket which is to be checked whether it is accepted by this filter
     * @return true if this filter accepts the specified DatagramPacket i.e. if the caller should include the specified
     * DatagramPacket in a selection based on this filter; otherwise, false
     */
    public boolean accept(DatagramPacket p);
}
