/* See LICENSE.md for license information */
package org.ice4j.ice;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.net.SocketAddress;
import java.net.SocketException;
import java.util.concurrent.CopyOnWriteArraySet;

import org.ice4j.socket.IceSocketWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Extends IoSession with functionality specific to an ICE {@link Component}.
 */
public class ComponentSocket implements PropertyChangeListener {

    private final static Logger logger = LoggerFactory.getLogger(ComponentSocket.class);

    /**
     * The owning {@link Component}.
     */
    private Component component;

    /**
     * The set of remote addresses, which this socket is allowed to receive from. These should be the addresses which we have confirmed
     * (e.g. by having received a STUN message with correct authentication fields).
     */
    private CopyOnWriteArraySet<SocketAddress> authorizedAddresses = new CopyOnWriteArraySet<>();

    /**
     * IceSocketWrapper associated with this ComponentSocket.
     */
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
     * Adds a specific address to the list of authorized remote addresses.
     * 
     * @param address the authorized address
     */
    public void addAuthorizedAddress(SocketAddress address) {
        if (!authorizedAddresses.contains(address)) {
            logger.debug("Adding allowed address: {}", address);
            authorizedAddresses.add(address);
        }
    }

    /**
     * {@inheritDoc}
     * <br>
     * Handles property change events coming from ICE pairs.
     * 
     * @param event
     */
    @Override
    public void propertyChange(PropertyChangeEvent event) {
        logger.debug("propertyChange: {}", event);
        if (event.getSource() instanceof CandidatePair) {
            CandidatePair pair = (CandidatePair) event.getSource();
            if (!pair.getParentComponent().equals(component)) {
                // Events are fired by the IceMediaStream, ensure that we only handle events for our component
                return;
            }
            String propertyName = event.getPropertyName();
            if (IceMediaStream.PROPERTY_PAIR_STATE_CHANGED.equals(propertyName)) {
                CandidatePairState newState = (CandidatePairState) event.getNewValue();
                if (CandidatePairState.SUCCEEDED.equals(newState)) {
                    addAuthorizedAddress(pair.getRemoteCandidate().getTransportAddress());
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
        authorizedAddresses.clear();
    }

    /**
     * Sets the active socket wrapper.
     * 
     * @param socketWrapper
     */
    public void setSocketWrapper(IceSocketWrapper socketWrapper) {
        this.socketWrapper = socketWrapper;
    }

    /**
     * Returns the active socket wrapper.
     * 
     * @return socketWrapper
     */
    public IceSocketWrapper getSocketWrapper() {
        return socketWrapper;
    }

}
