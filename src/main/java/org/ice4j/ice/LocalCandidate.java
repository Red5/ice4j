/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal. Copyright @ 2015 Atlassian Pty Ltd Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or
 * agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under the License.
 */
package org.ice4j.ice;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SocketChannel;

import org.ice4j.TransportAddress;
import org.ice4j.socket.IceSocketWrapper;
import org.ice4j.socket.IceTcpSocketWrapper;
import org.ice4j.socket.IceUdpSocketWrapper;
import org.ice4j.socket.MultiplexingDatagramSocket;
import org.ice4j.socket.MultiplexingSocket;
import org.ice4j.socket.filter.DatagramPacketFilter;
import org.ice4j.socket.filter.StunDatagramPacketFilter;
import org.ice4j.stack.StunStack;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * LocalCandidates are obtained by an agent for every stream component
 * and are then included in outgoing offers or answers.
 *
 * @author Emil Ivov
 * @author Lyubomir Marinov
 */
public abstract class LocalCandidate extends Candidate<LocalCandidate> {

    /**
     * The type of method used to discover this candidate ("host", "upnp", "stun
     * peer reflexive", "stun server reflexive", "turn relayed", "google turn
     * relayed", "google tcp turn relayed" or "jingle node").
     */
    private CandidateExtendedType extendedType;

    /**
     * Ufrag for the local candidate.
     */
    private String ufrag;

    /**
     * Whether this LocalCandidate uses SSL.
     */
    private boolean isSSL;

    /**
     * The {@link Logger} used by {@link LocalCandidate} instances.
     */
    private final static Logger logger = LoggerFactory.getLogger(LocalCandidate.class);

    /**
     * Creates a LocalCandidate instance for the specified transport
     * address and properties.
     *
     * @param transportAddress  the transport address that this candidate is
     * encapsulating.
     * @param parentComponent the Component that this candidate
     * belongs to.
     * @param type the CandidateType for this Candidate.
     * @param extendedType The type of method used to discover this candidate
     * ("host", "upnp", "stun peer reflexive", "stun server reflexive", "turn
     * relayed", "google turn relayed", "google tcp turn relayed" or "jingle
     * node").
     * @param relatedCandidate the relatedCandidate: null for a host candidate,
     * the base address (host candidate) for a reflexive candidate, the mapped
     * address (the mapped address of the TURN allocate response) for a relayed
     * candidate.
     */
    public LocalCandidate(TransportAddress transportAddress, Component parentComponent, CandidateType type, CandidateExtendedType extendedType, LocalCandidate relatedCandidate) {
        super(transportAddress, parentComponent, type, relatedCandidate);
        this.extendedType = extendedType;
    }

    /**
     * @return the {@link IceSocketWrapper} instance, if any, associated with
     * this candidate. Note that this IS NOT the instance which should be used
     * for reading and writing by the application, and SHOULD NOT be used from
     * outside ice4j (even if a subclass exposes it as public).
     */
    protected abstract IceSocketWrapper getCandidateIceSocketWrapper();

    /**
     * @return the {@link IceSocketWrapper} instance for this candidate,
     * associated with a particular remote address.
     * @param remoteAddress the remote address for which to return an
     * associated socket.
     */
    protected IceSocketWrapper getCandidateIceSocketWrapper(SocketAddress remoteAddress) {
        // The default implementation just refers to the method which doesn't
        // involve a remove address. Extenders which support multiple instances
        // mapped by remote address should override.
        return getCandidateIceSocketWrapper();
    }

    /**
     * Creates if necessary and returns a DatagramSocket that would
     * capture all STUN packets arriving on this candidate's socket. If the
     * serverAddress parameter is not null this socket would
     * only intercept packets originating at this address.
     *
     * @param serverAddress the address of the source we'd like to receive
     * packets from or null if we'd like to intercept all STUN packets.
     *
     * @return the DatagramSocket that this candidate uses when sending
     * and receiving STUN packets, while harvesting STUN candidates or
     * performing connectivity checks.
     */
    public IceSocketWrapper getStunSocket(TransportAddress serverAddress) {
        IceSocketWrapper hostSocket = getCandidateIceSocketWrapper();
        if (hostSocket != null) {
            SelectableChannel channel = hostSocket.getChannel();
            if (channel instanceof DatagramChannel) {
                DatagramSocket udpSocket = ((DatagramChannel) channel).socket();
                DatagramSocket udpStunSocket = null;
                if (udpSocket instanceof MultiplexingDatagramSocket) {
                    DatagramPacketFilter stunDatagramPacketFilter = createStunDatagramPacketFilter(serverAddress);
                    Throwable exception = null;
                    try {
                        udpStunSocket = ((MultiplexingDatagramSocket) udpSocket).getSocket(stunDatagramPacketFilter);
                    } catch (SocketException sex) {
                        logger.warn("Failed to acquire DatagramSocket specific to STUN communication", sex);
                        exception = sex;
                    }
                    if (udpStunSocket == null) {
                        throw new IllegalStateException("Failed to acquire DatagramSocket specific to STUN communication", exception);
                    }
                } else {
                    throw new IllegalStateException("The socket of " + getClass().getSimpleName() + " must be a MultiplexingDatagramSocket instance");
                }
                return new IceUdpSocketWrapper(udpStunSocket);
            } else {
                Socket tcpSocket = ((SocketChannel) channel).socket();
                Socket tcpStunSocket = null;
                if (tcpSocket instanceof MultiplexingSocket) {
                    DatagramPacketFilter stunDatagramPacketFilter = createStunDatagramPacketFilter(serverAddress);
                    Throwable exception = null;
                    try {
                        tcpStunSocket = ((MultiplexingSocket) tcpSocket).getSocket(stunDatagramPacketFilter);
                    } catch (SocketException sex) {
                        logger.warn("Failed to acquire Socket specific to STUN communication", sex);
                        exception = sex;
                    }
                    if (tcpStunSocket == null) {
                        throw new IllegalStateException("Failed to acquire Socket specific to STUN communication", exception);
                    }
                } else {
                    throw new IllegalStateException("The socket of " + getClass().getSimpleName() + " must be a MultiplexingSocket instance");
                }
                IceTcpSocketWrapper stunSocket = null;
                try {
                    stunSocket = new IceTcpSocketWrapper(tcpStunSocket);
                } catch (IOException e) {
                    logger.info("Failed to create IceTcpSocketWrapper " + e);
                }
                return stunSocket;
            }
        }
        return null;
    }

    /**
     * Gets the StunStack associated with this Candidate.
     *
     * @return the StunStack associated with this Candidate
     */
    public StunStack getStunStack() {
        return getParentComponent().getParentStream().getParentAgent().getStunStack();
    }

    /**
     * Creates a new StunDatagramPacketFilter which is to capture STUN
     * messages and make them available to the DatagramSocket returned
     * by {@link #getStunSocket(TransportAddress)}.
     *
     * @param serverAddress the address of the source we'd like to receive
     * packets from or null if we'd like to intercept all STUN packets
     * @return the StunDatagramPacketFilter which is to capture STUN
     * messages and make them available to the DatagramSocket returned
     * by {@link #getStunSocket(TransportAddress)}
     */
    protected StunDatagramPacketFilter createStunDatagramPacketFilter(TransportAddress serverAddress) {
        return new StunDatagramPacketFilter(serverAddress);
    }

    /**
     * Frees resources allocated by this candidate such as its
     * DatagramSocket, for example. The socket of this
     * LocalCandidate is closed only if it is not the socket
     * of the base of this LocalCandidate.
     */
    protected void free() {
        // Close the socket associated with this LocalCandidate.
        IceSocketWrapper socket = getCandidateIceSocketWrapper();
        if (socket != null) {
            LocalCandidate base = getBase();
            if (base == null || base == this || base.getCandidateIceSocketWrapper() != socket) {
                //remove our socket from the stack.
                getStunStack().removeSocket(getTransportAddress());
                // Allow this LocalCandidate implementation to not create a socket if it still hasn't created one.
                socket.close();
            }
        }
    }

    /**
     * Determines whether this Candidate is the default one for its
     * parent component.
     *
     * @return true if this Candidate is the default for its
     * parent component and false if it isn't or if it has no parent
     * Component yet.
     */
    @Override
    public boolean isDefault() {
        Component parentCmp = getParentComponent();

        return (parentCmp != null) && equals(parentCmp.getDefaultCandidate());
    }

    /**
     * Set the local ufrag.
     *
     * @param ufrag local ufrag
     */
    public void setUfrag(String ufrag) {
        this.ufrag = ufrag;
    }

    /**
     * Get the local ufrag.
     *
     * @return local ufrag
     */
    @Override
    public String getUfrag() {
        return ufrag;
    }

    /**
     * Returns the type of method used to discover this candidate ("host",
     * "upnp", "stun peer reflexive", "stun server reflexive", "turn relayed",
     * "google turn relayed", "google tcp turn relayed" or "jingle node").
     *
     * @return The type of method used to discover this candidate ("host",
     * "upnp", "stun peer reflexive", "stun server reflexive", "turn relayed",
     * "google turn relayed", "google tcp turn relayed" or "jingle node").
     */
    public CandidateExtendedType getExtendedType() {
        return this.extendedType;
    }

    /**
     * Sets the type of method used to discover this candidate ("host", "upnp",
     * "stun peer reflexive", "stun server reflexive", "turn relayed", "google
     * turn relayed", "google tcp turn relayed" or "jingle node").
     *
     * @param extendedType The type of method used to discover this candidate
     * ("host", "upnp", "stun peer reflexive", "stun server reflexive", "turn
     * relayed", "google turn relayed", "google tcp turn relayed" or "jingle
     * node").
     */
    public void setExtendedType(CandidateExtendedType extendedType) {
        this.extendedType = extendedType;
    }

    /**
     * Find the candidate corresponding to the address given in parameter.
     *
     * @param relatedAddress The related address:
     * - null for a host candidate,
     * - the base address (host candidate) for a reflexive candidate,
     * - the mapped address (the mapped address of the TURN allocate response)
     * for a relayed candidate.
     * - null for a peer reflexive candidate : there is no way to know the
     * related address.
     *
     * @return The related candidate corresponding to the address given in
     * parameter:
     * - null for a host candidate,
     * - the base address (host candidate) for a reflexive candidate,
     * - the mapped address (the mapped address of the TURN allocate response)
     * for a relayed candidate.
     * - null for a peer reflexive candidate : there is no way to know the
     * related address.
     */
    @Override
    protected LocalCandidate findRelatedCandidate(TransportAddress relatedAddress) {
        return getParentComponent().findLocalCandidate(relatedAddress);
    }

    /**
     * Gets the value of the 'ssl' flag.
     * @return the value of the 'ssl' flag.
     */
    public boolean isSSL() {
        return isSSL;
    }

    /**
     * Sets the value of the 'ssl' flag.
     * @param isSSL the value to set.
     */
    public void setSSL(boolean isSSL) {
        this.isSSL = isSSL;
    }
}
