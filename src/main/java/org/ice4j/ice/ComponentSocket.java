/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal. Copyright @ 2015-2016 Atlassian Pty Ltd Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law
 * or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See
 * the License for the specific language governing permissions and limitations under the License.
 */
package org.ice4j.ice;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.net.DatagramPacket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.atomic.AtomicBoolean;

import org.ice4j.TransportAddress;
import org.ice4j.socket.IceSocketWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Extends {@link MergingDatagramSocket} with functionality specific to an ICE {@link Component}.
 */
public class ComponentSocket implements PropertyChangeListener {

    private final static Logger logger = LoggerFactory.getLogger(ComponentSocket.class);

    /**
     * The owning {@link Component}.
     */
    private Component component;

    /**
     * Whether we have invoked {@link #initializeActive}.
     */
    private AtomicBoolean initializedActive = new AtomicBoolean(false);

    /**
     * The set of remote addresses, which this socket is allowed to receive from. These should be the addresses which we have confirmed
     * (e.g. by having received a STUN message with correct authentication fields).
     */
    private CopyOnWriteArraySet<SocketAddress> authorizedAddresses = new CopyOnWriteArraySet<>();

    private IceSocketWrapper socketWrapper;

    /**
     * Initializes a new {@link MergingDatagramSocket} instance.
     * @throws SocketException
     */
    ComponentSocket(Component component) throws SocketException {
        this.component = component;
        component.getParentStream().addPairChangeListener(this);
    }

    /**
     * {@inheritDoc}
     * <br>
     * Verifies that the source of the packet is an authorized remote address.
     */
    protected boolean accept(DatagramPacket p) {
        return authorizedAddresses.contains(p.getSocketAddress());
    }

    /**
     * Adds a specific address to the list of authorized remote addresses.
     * @param address the address to add.
     */
    private void addAuthorizedAddress(SocketAddress address) {
        if (!authorizedAddresses.contains(address)) {
            logger.debug("Adding allowed address: {}", address);
            authorizedAddresses.add(address);
        }
    }

    /**
     * {@inheritDoc}
     * <br>
     * Handles property change events coming from ICE pairs.
     * @param event
     */
    @Override
    public void propertyChange(PropertyChangeEvent event) {
        logger.debug("propertyChange: {}", event);
        if (event.getSource() instanceof CandidatePair) {
            CandidatePair pair = (CandidatePair) event.getSource();
            if (!pair.getParentComponent().equals(component)) {
                // Events are fired by the IceMediaStream, which might have multiple components. Make sure that we only handle events
                // for our own component.
                return;
            }
            String propertyName = event.getPropertyName();
            if (IceMediaStream.PROPERTY_PAIR_STATE_CHANGED.equals(propertyName)) {
                CandidatePairState newState = (CandidatePairState) event.getNewValue();
                if (CandidatePairState.SUCCEEDED.equals(newState)) {
                    addAuthorizedAddress(pair.getRemoteCandidate().getTransportAddress());
                }
            } else if (IceMediaStream.PROPERTY_PAIR_NOMINATED.equals(propertyName)) {
                if (initializedActive.compareAndSet(false, true)) {
                    // Find the remote address and the correct socket to be used by the pair.
                    LocalCandidate localCandidate = pair.getLocalCandidate();
                    LocalCandidate base = localCandidate.getBase();
                    if (base != null) {
                        localCandidate = base;
                    }
                    TransportAddress remoteAddress = null;
                    RemoteCandidate remoteCandidate = pair.getRemoteCandidate();
                    if (remoteCandidate != null) {
                        remoteAddress = remoteCandidate.getTransportAddress();
                    }
                    // The local candidate may have more than one associated socket.
                    // Make sure we get the one for the remote address that we are going to use.
                    socketWrapper = localCandidate.getCandidateIceSocketWrapper(remoteAddress);
                    // The remote address of the last received packet.
                    // Note that this is updated only when a packet is received from this {@link SocketContainer} via {@link #receive(DatagramPacket)}, and
                    // not when a packet is received from the underlying socket by its read thread. This is in order to prevent poisoning of the remote
                    // address, since the verification of the address is performed by the {@link MergingDatagramSocket} after it invokes {@link #receive(DatagramPacket)}.
                    socketWrapper.setRemoteTransportAddress(remoteAddress);
                }
            }
        }
    }

    public void close() {
        if (socketWrapper != null) {
            socketWrapper.close();
        }
        Component component = this.component;
        if (component != null) {
            component.getParentStream().removePairStateChangeListener(this);
            this.component = null;
        }
    }

    /**
     * Sets the active socket wrapper.
     * 
     * @param socketWrapper
     */
    public void setSocket(IceSocketWrapper socketWrapper) {
        this.socketWrapper = socketWrapper;
    }

    /**
     * Returns the active socket wrapper.
     * 
     * @return socketWrapper
     */
    public IceSocketWrapper getSocket() {
        return socketWrapper;
    }

}
