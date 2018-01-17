/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal. Copyright @ 2015 Atlassian Pty Ltd Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or
 * agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under the License.
 */
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
