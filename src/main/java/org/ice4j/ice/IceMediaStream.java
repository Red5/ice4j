/* See LICENSE.md for license information */
package org.ice4j.ice;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Queue;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentLinkedQueue;

import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The class represents a media stream from the ICE perspective, i.e. a collection of components.
 *
 * @author Emil Ivov
 * @author Namal Senarathne
 */
public class IceMediaStream {

    private final static Logger logger = LoggerFactory.getLogger(IceMediaStream.class);

    /**
     * The property name that we use when delivering events notifying listeners that the consent freshness of a pair has changed.
     */
    public static final String PROPERTY_PAIR_CONSENT_FRESHNESS_CHANGED = "PairConsentFreshnessChanged";

    /**
     * The property name that we use when delivering events notifying listeners of newly nominated pairs.
     */
    public static final String PROPERTY_PAIR_NOMINATED = "PairNominated";

    /**
     * The property name that we use when delivering events notifying listeners that a pair has changed states.
     */
    public static final String PROPERTY_PAIR_STATE_CHANGED = "PairStateChanged";

    /**
     * The property name that we use when delivering events notifying listeners of newly validated pairs.
     */
    public static final String PROPERTY_PAIR_VALIDATED = "PairValidated";

    /**
     * Use builder pattern to provide an immutable IceMediaStream instance.
     *
     * @param name the name of the media stream
     * @param parentAgent the agent that is handling the session that this media stream is a part of
     * @return IceMediaStream
     */
    public static IceMediaStream build(Agent parentAgent, String name) {
        return new IceMediaStream(parentAgent, name);
    }

    /**
     * The name of this media stream. The name is equal to the value specified in the SDP description.
     */
    private final String name;

    /**
     * Returns the list of components that this media stream consists of. A component is a piece of a media stream requiring a single transport
     * address; a media stream may require multiple components, each of which has to work for the media stream as a whole to work.
     */
    private final ConcurrentLinkedQueue<Component> components = new ConcurrentLinkedQueue<>();

    /**
     * An ordered set of candidate pairs for a media stream that have been validated by a successful STUN transaction. This list is empty at the
     * start of ICE processing, and fills as checks are performed, resulting in valid candidate pairs.
     */
    private final TreeSet<CandidatePair> validList = new TreeSet<>();

    /**
     * The id that was last assigned to a component. The next id that we give to a component would be lastComponendID + 1;
     */
    private int lastComponentID = 0;

    /**
     * The CHECK-LIST for this agent described in the ICE specification: There is one check list per in-use media stream resulting from the offer/answer
     * exchange.
     */
    private final CheckList checkList;

    /**
     * The agent that this media stream belongs to.
     */
    private final Agent parentAgent;

    /**
     * Contains {@link PropertyChangeListener}s registered with this {@link Agent} and following the various events it may be generating.
     */
    private final Queue<PropertyChangeListener> streamListeners = new ConcurrentLinkedQueue<>();

    /**
     * The maximum number of candidate pairs that we should have in our check list. This value depends on the total number of media streams which is
     * why it should be set by the agent:
     * In addition, in order to limit the attacks described in Section 18.5.2, an agent MUST limit the total number of connectivity checks they perform
     * across all check lists to a specific value, and this value MUST be configurable.  A default of 100 is RECOMMENDED.
     */
    private int maxCheckListSize = Agent.DEFAULT_MAX_CHECK_LIST_SIZE;

    /**
     * The user fragment that we received from the remote party.
     */
    private String remoteUfrag;

    /**
     * The password that we received from the remote party.
     */
    private String remotePassword;

    /**
     * Initializes a new IceMediaStream object.
     *
     * @param name the name of the media stream
     * @param parentAgent the agent that is handling the session that this media stream is a part of
     */
    protected IceMediaStream(Agent parentAgent, String name) {
        this.name = name;
        this.parentAgent = parentAgent;
        checkList = new CheckList(this);
    }

    /**
     * Creates and adds a component to this media-stream The component ID is incremented to the next integer value
     * when creating the component so make sure you keep that in mind in case assigning a specific component ID is important to you.
     *
     * @param keepAliveStrategy the keep-alive strategy, which dictates which candidates pairs are going to be kept alive.
     * @return the newly created stream Component after adding it to the stream first.
     */
    protected Component createComponent(KeepAliveStrategy keepAliveStrategy) {
        Component component = new Component(++lastComponentID, this, keepAliveStrategy);
        components.add(component);
        return component;
    }

    /**
     * Returns the name of this IceMediaStream.
     *
     * @return the name of this IceMediaStream.
     */
    public String getName() {
        return name;
    }

    /**
     * Returns a String representation of this media stream.
     *
     * @return a String representation of this media stream.
     */
    @Override
    public String toString() {
        StringBuilder buff = new StringBuilder("media stream:").append(getName());
        buff.append(" (component count=").append(getComponentCount()).append(")");
        for (Component cmp : getComponents()) {
            buff.append("\n").append(cmp);
        }
        return buff.toString();
    }

    /**
     * Returns the Component with the specified id or null if no such component exists in this stream.
     *
     * @param id the identifier of the component we are looking for.
     * @return  the Component with the specified id or null if no such component exists in this stream.
     */
    public Component getComponent(int id) {
        for (Component component : components) {
            if (component.getComponentID() == id) {
                return component;
            }
        }
        return null;
    }

    /**
     * Returns the list of Components currently registered with this stream.
     *
     * @return a non-null list of Components currently registered with this stream.
     */
    public List<Component> getComponents() {
        return new ArrayList<>(components);
    }

    /**
     * Returns the number of Components currently registered with this stream.
     *
     * @return the number of Components currently registered with this stream.
     */
    public int getComponentCount() {
        return components.size();
    }

    /**
     * Returns a reference to the Agent that this stream belongs to.
     *
     * @return a reference to the Agent that this stream belongs to.
     */
    public Agent getParentAgent() {
        return parentAgent;
    }

    /**
     * Removes this stream and all Candidates associated with its child Components.
     */
    protected void free() {
        for (Component component : components) {
            component.free();
        }
        components.clear();
    }

    /**
     * Removes component and all its Candidates from the this stream and releases all associated resources that they had
     * allocated (like sockets for example)
     *
     * @param component the Component we'd like to remove and free.
     */
    public void removeComponent(Component component) {
        if (components.remove(component)) {
            component.free();
        }
    }

    /**
     * Creates, initializes and orders the list of candidate pairs that would be used for the connectivity checks for all components in this stream.
     */
    protected void initCheckList() {
        // first init the check list
        //logger.debug("initCheckList: {}", checkList);
        //checkList.clear();
        createCheckList(checkList);
        pruneCheckList(checkList);
        logger.trace("Checklist initialized");
    }

    /**
     * Creates and adds to checkList all the CandidatePairs in all Components of this stream.
     *
     * @param checkList the list that we need to update with the new pairs.
     */
    protected void createCheckList(Queue<CandidatePair> checkList) {
        for (Component cmp : getComponents()) {
            createCheckList(cmp, checkList);
        }
    }

    /**
     * Creates and adds to checkList all the CandidatePairs in component.
     *
     * @param component the Component whose candidates we need to pair and extract.
     * @param checkList the list that we need to update with the new pairs.
     */
    private void createCheckList(final Component component, final Queue<CandidatePair> checkList) {
        List<LocalCandidate> localCnds = component.getLocalCandidates();
        List<RemoteCandidate> remoteCnds = component.getRemoteCandidates();
        for (LocalCandidate localCnd : localCnds) {
            for (RemoteCandidate remoteCnd : remoteCnds) {
                if (localCnd.canReach(remoteCnd) && remoteCnd.getTransportAddress().getPort() != 0) {
                    CandidatePair pair = getParentAgent().createCandidatePair(localCnd, remoteCnd);
                    checkList.add(pair);
                }
            }
        }
    }

    /**
     *  Removes or, as per the ICE spec, "prunes" pairs that we don't need to run checks for. For example, since we cannot send requests directly
     *  from a reflexive candidate, but only from its base, we go through the sorted list of candidate pairs and in every pair where the local
     *  candidate is server reflexive, we replace the local server reflexive candidate with its base. Once this has been done, we remove each pair
     *  where the local and remote candidates are identical to the local and remote candidates of a pair higher up on the priority list.
     *  <br>
     *  In addition, in order to limit the attacks described in Section 18.5.2 of the ICE spec, we limit the total number of pairs and hence
     *  (connectivity checks) to a specific value, (a total of 100 by default).
     *
     * @param checkList the checklist to prune
     */
    @SuppressWarnings("incomplete-switch")
    protected void pruneCheckList(Queue<CandidatePair> checkList) {
        //logger.trace("Pruning checklist: {}", checkList);
        // a list that we only use for storing pairs that we've already gone through. The list is destroyed at the end of this method.
        Set<CandidatePair> tmpCheckList = new HashSet<>(checkList.size());
        for (CandidatePair pair : checkList) {
            //logger.trace("Candidate pair: {}", pair);
            // drop all pairs above MAX_CHECK_LIST_SIZE
            if (tmpCheckList.size() > maxCheckListSize) {
                break;
            }
            // replace local server reflexive candidates with their base.
            LocalCandidate localCnd = pair.getLocalCandidate();
            switch (localCnd.getType()) {
                case SERVER_REFLEXIVE_CANDIDATE:
                case PEER_REFLEXIVE_CANDIDATE:
                    pair.setLocalCandidate(localCnd.getBase());
                    // if the new pair corresponds to another one with a higher priority, then remove it.
                    if (tmpCheckList.contains(pair)) {
                        logger.debug("Removing duplicate pair: {}", pair);
                        continue;
                    }
                    break;
            }
            // if the local candidate is TCP and tcptype is not set, configure it
            if (localCnd.getTransport() == Transport.TCP && localCnd.getTcpType() == null) {
                // if the remote is passive, set ours to active and anything else (passive or so) we go passive
                switch (pair.getRemoteCandidate().getTcpType()) {
                    case PASSIVE:
                        localCnd.setTcpType(CandidateTcpType.ACTIVE);
                        break;
                    default:
                        localCnd.setTcpType(CandidateTcpType.PASSIVE);
                }
            }
            tmpCheckList.add(pair);
        }
        // clear original
        checkList.clear();
        // add those that are in the temporary set
        checkList.addAll(tmpCheckList);
        logger.debug("Pruned checklist: {}", checkList);
        // clear the temporary list
        tmpCheckList.clear();
        tmpCheckList = null;
    }

    /**
     * Returns the list of CandidatePairs to be used in checks for this stream.
     *
     * @return the list of CandidatePairs to be used in checks for this stream
     */
    public CheckList getCheckList() {
        return checkList;
    }

    /**
     * Sets the maximum number of pairs that we should have in our check list.
     *
     * @param nSize the size of our check list
     */
    protected void setMaxCheckListSize(int nSize) {
        this.maxCheckListSize = nSize;
    }

    /**
     * Returns the local LocalCandidate with the specified localAddress if it belongs to any of this stream's components
     * or null otherwise.
     *
     * @param localAddress the {@link TransportAddress} we are looking for
     * @return  the local LocalCandidate with the specified localAddress if it belongs to any of this stream's components
     * or null otherwise
     */
    public LocalCandidate findLocalCandidate(TransportAddress localAddress) {
        for (Component cmp : components) {
            LocalCandidate cnd = cmp.findLocalCandidate(localAddress);
            if (cnd != null) {
                return cnd;
            }
        }
        return null;
    }

    /**
     * Returns the local Candidate with the specified remoteAddress if it belongs to any of this stream's {@link
     * Component}s or null if it doesn't.
     *
     * @param remoteAddress the {@link TransportAddress} we are looking for.
     * @return the local Candidate with the specified remoteAddress if it belongs to any of this stream's {@link
     * Component}s or null if it doesn't.
     *
     */
    public RemoteCandidate findRemoteCandidate(TransportAddress remoteAddress) {
        for (Component cmp : components) {
            RemoteCandidate cnd = cmp.findRemoteCandidate(remoteAddress);
            if (cnd != null) {
                return cnd;
            }
        }
        return null;
    }

    /**
     * Returns the {@link CandidatePair} with the specified remote and local addresses or null if neither of the {@link CheckList}s in this
     * stream contain such a pair.
     *
     * @param localAddress the local {@link TransportAddress} of the pair we are looking for.
     * @param remoteAddress the remote {@link TransportAddress} of the pair we are looking for.     *
     * @return the {@link CandidatePair} with the specified remote and local addresses or null if neither of the {@link CheckList}s in this
     * stream contain such a pair.
     */
    public CandidatePair findCandidatePair(TransportAddress localAddress, TransportAddress remoteAddress) {
        for (CandidatePair pair : checkList) {
            if (pair.getLocalCandidate().getTransportAddress().equals(localAddress) && pair.getRemoteCandidate().getTransportAddress().equals(remoteAddress)) {
                return pair;
            }
        }
        return null;
    }

    /**
     * Returns the {@link CandidatePair} with the specified remote and local
     * addresses or null if neither of the {@link CheckList}s in this
     * stream contain such a pair.
     *
     * @param localUFrag local user fragment
     * @param remoteUFrag remote user fragment
     * @return the {@link CandidatePair} with the specified remote and local
     * addresses or null if neither of the {@link CheckList}s in this
     * stream contain such a pair.
     */
    public CandidatePair findCandidatePair(String localUFrag, String remoteUFrag) {
        for (CandidatePair pair : checkList) {
            LocalCandidate local = pair.getLocalCandidate();
            RemoteCandidate remote = pair.getRemoteCandidate();
            if (local.getUfrag().equals(remoteUFrag) && remote.getUfrag().equals(localUFrag)) {
                return pair;
            }
        }
        return null;
    }

    /**
     * Returns the number of host {@link Candidate}s in this stream.
     *
     * @return the number of host {@link Candidate}s in this stream.
     */
    protected int countHostCandidates() {
        int num = 0;
        for (Component cmp : components) {
            num += cmp.countLocalHostCandidates();
        }
        return num;
    }

    /**
     * Adds candidatePair to this stream's check list. The method is meant for use during the connectivity checks phase when new pairs
     * with remote PEER-REFLEXIVE-CANDIDATEs are discovered.
     *
     * @param candidatePair the pair that we'd like to add to this streams.
     */
    protected void addToCheckList(CandidatePair candidatePair) {
        checkList.offer(candidatePair);
    }

    /**
     * Adds pair to the valid list that this stream is maintaining.
     *
     * @param pair the {@link CandidatePair} to add to our valid list.
     */
    protected void addToValidList(CandidatePair pair) {
        synchronized (validList) {
            if (!validList.contains(pair)) {
                validList.add(pair);
            }
        }
        pair.validate();
    }

    /**
     * Returns true if this stream's validList contains a pair with the specified foundation and false otherwise.
     *
     * @param foundation the foundation String we'd like to search our validList for.
     * @return true if this stream's validList contains a pair with the specified foundation and false otherwise.
     */
    protected boolean validListContainsFoundation(String foundation) {
        synchronized (validList) {
            for (CandidatePair pair : validList) {
                if (pair.getFoundation().equals(foundation)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Returns true if this stream's validList contains a pair that is nominated for the specified Component and
     * false otherwise.
     *
     * @param component the Component we'd like to search our validList for.
     * @return true if this stream's validList contains a pair that is nominated for the specified Component and
     * false otherwise.
     */
    protected boolean validListContainsNomineeForComponent(Component component) {
        synchronized (validList) {
            for (CandidatePair pair : validList) {
                if (pair.isNominated() && pair.getParentComponent() == component) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Returns true if this stream's valid list contains at least one {@link CandidatePair} for each {@link Component} of the stream and
     * false otherwise.
     *
     * @return true if this stream's valid list contains at least one {@link CandidatePair} for each {@link Component} of the stream and
     * false otherwise.
     */
    protected boolean validListContainsAllComponents() {
        for (Component cmp : getComponents()) {
            if (getValidPair(cmp) == null) {
                //it looks like there's at least one component we don't have a valid candidate for.
                return false;
            }
        }
        return true;
    }

    /**
     * Returns true if there is at least one nominated {@link CandidatePair} in the valid list for every {@link Component} of this
     * stream and false otherwise.
     *
     * @return true if there is at least one nominated {@link CandidatePair} in the valid list for every {@link Component} of this
     * stream and false otherwise.
     */
    protected boolean allComponentsAreNominated() {
        List<Component> components = getComponents();
        synchronized (validList) {
            for (CandidatePair pair : validList) {
                if (pair.isNominated()) {
                    components.remove(pair.getParentComponent());
                }
            }
        }
        return components.isEmpty();
    }

    /**
     * Returns false if there is at least one nominated {@link CandidatePair} who doesn't have a selected address yet, and true
     * otherwise.
     *
     * @return false if there is at least one nominated {@link CandidatePair} who doesn't have a selected address yet, and true
     * otherwise.
     */
    protected boolean allComponentsHaveSelected() {
        for (Component component : getComponents()) {
            if (component.getSelectedPair() == null) {
                return false;
            }
        }
        return true;
    }

    /**
     * Returns the first {@link CandidatePair} stored in this stream's valid list, that belongs to the specified component.
     *
     * @param component the {@link Component} we'd like to obtain a valid pair for.
     *
     * @return a valid {@link CandidatePair} for the specified component if at least one exists, and null otherwise.
     */
    protected CandidatePair getValidPair(Component component) {
        synchronized (validList) {
            for (CandidatePair pair : validList) {
                if (pair.getParentComponent() == component) {
                    return pair;
                }
            }
        }
        return null;
    }

    /**
     * Adds l to the list of listeners registered for property changes if {@link CandidatePair}s. We add such listeners in the stream, rather
     * than having them in the candidate pair itself, because we don't want all pairs to keep lists of references to the same listeners.
     *
     * @param l the listener to register.
     */
    public void addPairChangeListener(PropertyChangeListener l) {
        if (!streamListeners.contains(l)) {
            streamListeners.add(l);
        }
    }

    /**
     * Removes l from the list of listeners registered for property changes.
     *
     * @param l the listener to remove.
     */
    public void removePairStateChangeListener(PropertyChangeListener l) {
        streamListeners.remove(l);
    }

    /**
     * Creates a new {@link PropertyChangeEvent} and delivers it to all currently registered state listeners.
     *
     * @param source the {@link CandidatePair} whose property has just changed.
     * @param propertyName the name of the property that changed.
     * @param oldValue the old value of the property that changed.
     * @param newValue the new value of the property that changed.
     */
    protected void firePairPropertyChange(CandidatePair source, String propertyName, Object oldValue, Object newValue) {
        PropertyChangeEvent ev = new PropertyChangeEvent(source, propertyName, oldValue, newValue);
        for (PropertyChangeListener l : streamListeners) {
            l.propertyChange(ev);
        }
    }

    /**
     * Specifies the user name that we received from the remote peer.
     *
     * @param remoteUfrag the user name that we received from the remote peer.
     */
    public void setRemoteUfrag(String remoteUfrag) {
        this.remoteUfrag = remoteUfrag;
    }

    /**
     * Returns the user name that we received from the remote peer or null if we haven't received a user name from them yet.
     *
     * @return the user name that we received from the remote peer or null if we haven't received a user name from them yet.
     */
    public String getRemoteUfrag() {
        return remoteUfrag;
    }

    /**
     * Specifies the password that we received from the remote peer.
     *
     * @param remotePassword the user name that we received from the remote peer.
     */
    public void setRemotePassword(String remotePassword) {
        this.remotePassword = remotePassword;
    }

    /**
     * Returns the password that we received from the remote peer or null if we haven't received a password from them yet.
     *
     * @return the password that we received from the remote peer or null if we haven't received a password from them yet.
     */
    public String getRemotePassword() {
        return remotePassword;
    }
}
