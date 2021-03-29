/* See LICENSE.md for license information */
package org.ice4j.ice;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.PriorityQueue;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

import org.ice4j.StackProperties;
import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.socket.IceSocketWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A component is a piece of a media stream requiring a single transport address; a media stream may require multiple components, each of which has
 * to work for the media stream as a whole to work. For media streams based on RTP, there are two components per media stream (1 RTP & 1 RTCP).
 * <p>
 *
 * @author Emil Ivov
 * @author Sebastien Vincent
 * @author Boris Grozev
 * @author Paul Gregoire
 */
public class Component implements PropertyChangeListener {

    private final static Logger logger = LoggerFactory.getLogger(Component.class);

    /**
     * Whether or not to skip remote candidates originating from private network hosts.
     */
    private static boolean skipPrivateNetworkHostCandidate = StackProperties.getBoolean("SKIP_REMOTE_PRIVATE_HOSTS", false);

    /**
     * Comparator allowing sort by priority and preference.
     */
    private final static Comparator<? super LocalCandidate> candidateComparator = new Comparator<LocalCandidate>() {

        @Override
        public int compare(LocalCandidate cand1, LocalCandidate cand2) {
            int result = 0;
            if (cand1.getComponentId() < cand2.getComponentId()) {
                result -= 1;
            } else if (cand1.getComponentId() > cand2.getComponentId()) {
                result += 1;
            }
            if (cand1.priority < cand2.priority) {
                result -= 1;
            } else if (cand1.priority > cand2.priority) {
                result += 1;
            }
            if (cand1.getDefaultPreference() < cand2.getDefaultPreference()) {
                result -= 1;
            } else if (cand1.getDefaultPreference() > cand2.getDefaultPreference()) {
                result += 1;
            }
            // add network-id and network-cost to the mix
            if (cand1.getNetworkId() < cand2.getNetworkId()) {
                result -= 1;
                if (cand1.getNetworkCost() < cand2.getNetworkCost()) {
                    result -= 1;
                }
            } else if (cand1.getNetworkId() > cand2.getNetworkId()) {
                result += 1;
                if (cand1.getNetworkCost() > cand2.getNetworkCost()) {
                    result += 1;
                }
            }
            return result;
        }

    };

    /**
     * A component id is a positive integer between 1 and 256 which identifies the specific component of the media stream for which this is a candidate.
     * It MUST start at 1 and MUST increment by 1 for each component of a particular candidate. For media streams based on RTP, candidates for the
     * actual RTP media MUST have a component ID of 1, and candidates for RTCP MUST have a component ID of 2. Other types of media streams which
     * require multiple components MUST develop specifications which define the mapping of components to component IDs. See Section 14 of RFC5245 for
     * additional discussion on extending ICE to new media streams.
     */
    private final int componentID;

    /**
     * The IceMediaStream that this Component belongs to.
     */
    private final IceMediaStream parentStream;

    /**
     * The list locally gathered candidates for this media stream.
     */
    private final Queue<LocalCandidate> localCandidates = new PriorityQueue<>(3, candidateComparator);

    /**
     * The list of candidates that the peer agent sent for this stream.
     */
    private final Queue<RemoteCandidate> remoteCandidates = new ConcurrentLinkedQueue<>();

    /**
     * The list of candidates that the peer agent sent for this stream after connectivity establishment.
     */
    private final Queue<RemoteCandidate> remoteUpdateCandidates = new ConcurrentLinkedQueue<>();

    /**
     * The default Candidate for this component or in other words, the candidate that we would have used without ICE.
     */
    private LocalCandidate defaultCandidate;

    /**
     * The pair that has been selected for use by ICE processing
     */
    private CandidatePair selectedPair;

    /**
     * The default RemoteCandidate for this component or in other words, the candidate that we would have used to communicate with the
     * remote peer if we hadn't been using ICE.
     */
    private Candidate<?> defaultRemoteCandidate;

    /**
     * The single {@link ComponentSocket} instance for this {@link Component}.
     */
    private final ComponentSocket componentSocket;

    /**
     * The {@link KeepAliveStrategy} used by this component to select which pairs are to be kept alive.
     */
    private final KeepAliveStrategy keepAliveStrategy;

    /**
     * The set of pairs which this component wants to keep alive.
     */
    private final Set<CandidatePair> keepAlivePairs = Collections.newSetFromMap(new ConcurrentHashMap<CandidatePair, Boolean>());

    /**
     * Creates a new Component with the specified componentID as a child of the specified IceMediaStream.
     *
     * @param componentID the id of this component.
     * @param mediaStream the {@link IceMediaStream} instance that would be the parent of this component.
     */
    protected Component(int componentID, IceMediaStream mediaStream, KeepAliveStrategy keepAliveStrategy) {
        // the max value for componentID is 256
        this.componentID = componentID;
        this.parentStream = mediaStream;
        this.keepAliveStrategy = Objects.requireNonNull(keepAliveStrategy, "keepAliveStrategy");
        try {
            componentSocket = new ComponentSocket(this);
        } catch (SocketException se) {
            throw new RuntimeException(se);
        }
        mediaStream.addPairChangeListener(this);
    }

    /**
     * Add a local candidate to this component. The method should only be accessed and local candidates added by the candidate harvesters
     * registered with the agent.
     *
     * @param candidate the candidate object to be added
     * @return true if we actually added the new candidate or false in case we didn't because it was redundant to an existing candidate.
     */
    public boolean addLocalCandidate(LocalCandidate candidate) {
        Agent agent = getParentStream().getParentAgent();
        // assign foundation
        agent.getFoundationsRegistry().assignFoundation(candidate);
        // compute priority
        candidate.computePriority();
        // check if we already have such a candidate (redundant)
        Optional<LocalCandidate> existingCandidate = localCandidates.stream().filter(existing -> (existing.toShortString().equals(candidate.toShortString()))).findFirst();
        if (existingCandidate.isPresent()) {
            logger.debug("Candidate entry already exists - {} {}", candidate, existingCandidate.get());
        } else {
            return localCandidates.add(candidate);
        }
        return false;
    }

    /**
     * Removes candidates matching the supplied types. Example of how to remove reflexive candidates:
     * <pre>
     *     component.removeLocalCandidateByType(EnumSet.of(CandidateType.PEER_REFLEXIVE_CANDIDATE, CandidateType.SERVER_REFLEXIVE_CANDIDATE));
     * </pre>
     * 
     * @param candidateTypes EnumSet of CandidateType to match
     */
    public void removeLocalCandidateByType(EnumSet<CandidateType> candidateTypes) {
        localCandidates.forEach(candidate -> {
            if (candidateTypes.contains(candidate.getType())) {
                // free the candidate; this may also close the candidates socket
                free(candidate);
                // remove it
                if (localCandidates.remove(candidate)) {
                    logger.debug("Candidate freed and removed: {}", candidate);
                }
            }
        });
    }

    /**
     * Returns a copy of the list containing all local candidates currently registered in this component.
     *
     * @return Returns a copy of the list containing all local candidates currently registered
     */
    public List<LocalCandidate> getLocalCandidates() {
        return new ArrayList<>(localCandidates);
    }

    /**
     * Returns the number of local host candidates currently registered in this Component.
     *
     * @return the number of local host candidates currently registered
     */
    public int countLocalHostCandidates() {
        int count = 0;
        for (Candidate<?> cand : localCandidates) {
            if ((cand.getType() == CandidateType.HOST_CANDIDATE) && !cand.isVirtual()) {
                count++;
            }
        }
        return count;
    }

    /**
     * Returns the number of all local candidates currently registered in this Component.
     *
     * @return the number of all local candidates currently registered
     */
    public int getLocalCandidateCount() {
        return localCandidates.size();
    }

    /**
     * Adds a remote Candidates to this media-stream Component.
     *
     * @param candidate the Candidate instance to add
     */
    public void addRemoteCandidate(RemoteCandidate candidate) {
        logger.debug("Add remote candidate for {}: {}", toShortString(), candidate.toShortString());
        // skip private network host candidates
        if (skipPrivateNetworkHostCandidate && ((InetSocketAddress) candidate.getTransportAddress()).getAddress().isSiteLocalAddress()) {
            logger.debug("Skipping remote candidate with private IP address: {}", candidate);
        } else {
            // check if we already have such a candidate (redundant)
            Optional<RemoteCandidate> existingCandidate = remoteCandidates.stream().filter(existing -> (existing.toShortString().equals(candidate.toShortString()))).findFirst();
            if (existingCandidate.isPresent()) {
                logger.debug("Candidate entry already exists - {} {}", candidate, existingCandidate.get());
            } else {
                remoteCandidates.add(candidate);
            }
        }
    }

    /**
     * Update the media-stream Component with the specified Candidates. This would happen when performing trickle ICE.
     *
     * @param candidate new Candidate to add.
     */
    public void addUpdateRemoteCandidates(RemoteCandidate candidate) {
        logger.debug("Update remote candidate for {}: {}", toShortString(), candidate.getTransportAddress());
        List<RemoteCandidate> existingCandidates = new LinkedList<>();
        existingCandidates.addAll(remoteCandidates);
        existingCandidates.addAll(remoteUpdateCandidates);
        // Make sure we add no duplicates
        TransportAddress transportAddress = candidate.getTransportAddress();
        CandidateType type = candidate.getType();
        for (RemoteCandidate existingCandidate : existingCandidates) {
            if (transportAddress.equals(existingCandidate.getTransportAddress()) && type == existingCandidate.getType()) {
                logger.debug("Not adding duplicate remote candidate: {}", candidate.getTransportAddress());
                return;
            }
        }
        remoteUpdateCandidates.add(candidate);
    }

    /**
     * Update ICE processing with new Candidates.
     */
    public void updateRemoteCandidates() {
        Queue<CandidatePair> checkList = new PriorityQueue<>();
        List<RemoteCandidate> newRemoteCandidates;
        if (remoteUpdateCandidates.size() == 0) {
            return;
        }
        newRemoteCandidates = new LinkedList<>(remoteUpdateCandidates);
        List<LocalCandidate> localCnds = getLocalCandidates();
        for (LocalCandidate localCnd : localCnds) {
            //pair each of the new remote candidates with each of our locals
            for (RemoteCandidate remoteCnd : remoteUpdateCandidates) {
                if (localCnd.canReach(remoteCnd) && remoteCnd.getTransportAddress().getPort() != 0) {
                    // A single LocalCandidate might be/become connected to more than one remote address, and that's ok
                    // (that is, we need to form pairs with them all).
                    CandidatePair pair = getParentStream().getParentAgent().createCandidatePair(localCnd, remoteCnd);
                    logger.debug("new Pair added: {}. Local ufrag {}", pair.toShortString(), parentStream.getParentAgent().getLocalUfrag());
                    checkList.add(pair);
                }
            }
        }
        remoteUpdateCandidates.clear();
        remoteCandidates.addAll(newRemoteCandidates);
        // prune update checklist
        parentStream.pruneCheckList(checkList);
        if (parentStream.getCheckList().getState().equals(CheckListState.RUNNING)) {
            //add the updated CandidatePair list to the currently running checklist
            CheckList streamCheckList = parentStream.getCheckList();
            for (CandidatePair pair : checkList) {
                streamCheckList.add(pair);
            }
        }
    }

    /**
     * Returns a copy of the list containing all remote candidates currently registered in this component.
     *
     * @return Returns a copy of the list containing all remote candidates
     * currently registered in this Component.
     */
    public List<RemoteCandidate> getRemoteCandidates() {
        return new ArrayList<>(remoteCandidates);
    }

    /**
     * Adds a List of remote Candidates as reported by a remote agent.
     *
     * @param candidates the List of Candidates reported by
     * the remote agent for this component.
     */
    public void addRemoteCandidates(List<RemoteCandidate> candidates) {
        remoteCandidates.addAll(candidates);
    }

    /**
     * Returns the number of all remote candidates currently registered in this Component.
     *
     * @return the number of all remote candidates currently registered
     */
    public int getRemoteCandidateCount() {
        return remoteCandidates.size();
    }

    /**
     * Returns a reference to the IceMediaStream that this Component belongs to.
     *
     * @return a reference to the IceMediaStream that this Component belongs to.
     */
    public IceMediaStream getParentStream() {
        return parentStream;
    }

    /**
     * Returns the ID of this Component. For RTP/RTCP flows this would be 1 for RTP and 2 for RTCP.
     *
     * @return the ID of this Component.
     */
    public int getComponentID() {
        return componentID;
    }

    /**
     * Returns a String representation of this Component containing its ID, parent stream name and any existing candidates.
     *
     * @return  a String representation of this Component
     * containing its ID, parent stream name and any existing candidates.
     */
    public String toString() {
        StringBuilder buff = new StringBuilder("Component id=").append(getComponentID());
        buff.append(" parent stream=").append(getParentStream().getName());
        // local candidates
        int localCandidatesCount = getLocalCandidateCount();
        if (localCandidatesCount > 0) {
            buff.append("\n").append(localCandidatesCount).append(" Local candidates:");
            buff.append("\ndefault candidate: ").append(getDefaultCandidate());
            for (Candidate<?> cand : localCandidates) {
                buff.append('\n').append(cand.toString());
            }
        } else {
            buff.append("\nno local candidates.");
        }
        //remote candidates
        int remoteCandidatesCount = getRemoteCandidateCount();
        if (remoteCandidatesCount > 0) {
            buff.append("\n").append(remoteCandidatesCount).append(" Remote candidates:");
            buff.append("\ndefault remote candidate: ").append(getDefaultRemoteCandidate());
            for (RemoteCandidate cand : remoteCandidates) {
                buff.append("\n").append(cand);
            }
        } else {
            buff.append("\nno remote candidates.");
        }
        return buff.toString();
    }

    /**
     * Returns a short String representation of this Component.
     *
     * @return a short String representation of this Component.
     */
    public String toShortString() {
        return parentStream.getName() + '.' + componentID;
    }

    /**
     * Returns the Candidate that has been selected as the default for this Component or null if no such
     * Candidate has been selected yet. A candidate is said to be default if it would be the target of media from a non-ICE peer;
     *
     * @return the Candidate that has been selected as the default for this Component or null if no such Candidate
     * has been selected yet
     */
    public LocalCandidate getDefaultCandidate() {
        return defaultCandidate;
    }

    /**
     * Returns the Candidate that the remote party has reported as default for this Component or null if no such
     * Candidate has been reported yet. A candidate is said to be default if it would be the target of media from a non-ICE peer;
     *
     * @return the Candidate that the remote party has reported as default for this Component or null if no such
     * Candidate has reported yet.
     */
    public Candidate<?> getDefaultRemoteCandidate() {
        return defaultRemoteCandidate;
    }

    /**
     * Sets the Candidate that the remote party has reported as default for this Component. A candidate is said to be
     * default if it would be the target of media from a non-ICE peer;
     *
     * @param candidate the Candidate that the remote party has reported as default for this Component.
     */
    public void setDefaultRemoteCandidate(Candidate<?> candidate) {
        this.defaultRemoteCandidate = candidate;
    }

    /**
     * Selects a Candidate that should be considered as the default for this Component. A candidate is said to be default if it
     * would be the target of media from a non-ICE peer;
     * <p>
     * The ICE specification RECOMMENDEDs that default candidates be chosen based on the likelihood of those candidates to work with the peer that is
     * being contacted. It is RECOMMENDED that the default candidates are the relayed candidates (if relayed candidates are available), server
     * reflexive candidates (if server reflexive candidates are available), and finally host candidates.
     * <br>
     */
    protected void selectDefaultCandidate() {
        for (LocalCandidate cand : localCandidates) {
            if (defaultCandidate == null || defaultCandidate.getDefaultPreference() < cand.getDefaultPreference()) {
                defaultCandidate = cand;
            }
        }
    }

    /**
     * Releases all resources allocated by this Component and its Candidates like sockets for example.
     */
    protected void free() {
        // Free at last
        localCandidates.forEach(candidate -> {
            free(candidate);
        });
        localCandidates.clear();
        getParentStream().removePairStateChangeListener(this);
        keepAlivePairs.clear();
        getComponentSocket().close();
    }

    /**
     * Frees a specific LocalCandidate and swallows any Throwable it throws while freeing itself in order to prevent its
     * failure to affect the rest of the execution.
     *
     * @param localCandidate the LocalCandidate to be freed
     */
    private void free(LocalCandidate localCandidate) {
        try {
            localCandidate.free();
        } catch (Throwable t) {
            // Don't let the failing of a single LocalCandidate to free itself to fail the freeing of the other LocalCandidates.
            if (t instanceof ThreadDeath) {
                throw (ThreadDeath) t;
            }
            logger.warn("Failed to free LocalCandidate: {}", localCandidate, t);
        }
    }

    /**
     * Returns the local LocalCandidate with the specified localAddress if it belongs to this component or null if it doesn't.
     *
     * @param localAddress the {@link TransportAddress} we are looking for
     * @return the LocalCandidate with the specified localAddress if it belongs or null if not
     */
    public LocalCandidate findLocalCandidate(TransportAddress localAddress) {
        //        for (LocalCandidate localCnd : localCandidates) {
        //            if (localCnd.getTransportAddress().equals(localAddress)) {
        //                logger.debug("Found local {} candidate for address: {}", localCnd.getType(), localAddress);
        //                return localCnd;
        //            }
        //        }
        //        logger.debug("No local candidate for address: {}", localAddress);
        //        return null;
        return findLocalCandidate(localAddress, null);
    }

    /**
     * Returns the local LocalCandidate with the specified address if it belongs to this component or null
     * if it doesn't. If {@code base} is also specified, tries to find a candidate whose base matches {@code base}.
     *
     * @param address the {@link TransportAddress} we are looking for
     * @param base an optional base to match
     *
     * @return  the local LocalCandidate with the specified address if it belongs to this component or null
     * if it doesn't.
     */
    public LocalCandidate findLocalCandidate(TransportAddress localAddress, LocalCandidate base) {
        for (LocalCandidate localCandidate : localCandidates) {
            if (localCandidate.getTransportAddress().equals(localAddress)) {
                if (base == null || base.equals(localCandidate.getBase())) {
                    logger.debug("Found local {} candidate for address: {}", localCandidate.getType(), localAddress);
                    return localCandidate;
                }
            }
        }
        // In case the above loop failed to find a result because `base` was specified, fallback to the original
        // behavior and return the first candidate matching `address` regardless of `base`.
        for (LocalCandidate localCandidate : localCandidates) {
            if (localCandidate.getTransportAddress().equals(localAddress)) {
                logger.warn("Returning a candidate matching the address, while no candidates match both address ({}) and base ({}): {} with base {}", localAddress, base, localCandidate, localCandidate.getBase());
                return localCandidate;
            }
        }
        return null;
    }

    /**
     * Returns the remote Candidate with the specified remoteAddress if it belongs to this {@link Component} or null if it doesn't.
     *
     * @param remoteAddress the {@link TransportAddress} we are looking for
     * @return the remote RemoteCandidate with the specified remoteAddress if it belongs or null if not
     */
    public RemoteCandidate findRemoteCandidate(TransportAddress remoteAddress) {
        for (RemoteCandidate remoteCnd : remoteCandidates) {
            if (remoteCnd.getTransportAddress().equals(remoteAddress)) {
                return remoteCnd;
            }
        }
        return null;
    }

    /**
     * Sets the {@link CandidatePair} selected for use by ICE processing and that the application would use.
     *
     * @param pair the {@link CandidatePair} selected for use by ICE processing
     */
    protected void setSelectedPair(CandidatePair pair) {
        if (keepAliveStrategy == KeepAliveStrategy.SELECTED_ONLY) {
            keepAlivePairs.clear();
        }
        keepAlivePairs.add(pair);
        this.selectedPair = pair;
    }

    /**
     * Returns the {@link CandidatePair} selected for use by ICE processing or null if no pair has been selected so far or if ICE processing
     * has failed.
     *
     * @return CandidatePair selected for use by ICE processing or null if no pair has been selected so far or if ICE processing
     * has failed
     */
    public CandidatePair getSelectedPair() {
        return selectedPair;
    }

    /**
     * Use builder pattern to allow creation of immutable Component instances, from outside the current package.
     *
     * @param componentID the id of this component.
     * @param mediaStream the {@link IceMediaStream} instance that would be the parent of this component.
     * @return Component
     */
    public static Component build(int componentID, IceMediaStream mediaStream) {
        return new Component(componentID, mediaStream, KeepAliveStrategy.SELECTED_ONLY);
    }

    /**
     * @return the internal merging socket for this component. This is for ice4j use only.
     * For reading/writing application data, use {@link #getSocket()}.
     */
    public ComponentSocket getComponentSocket() {
        return componentSocket;
    }

    /**
     * @return the socket for this {@link Component}, which should be used for reading/writing application data.
     */
    public IceSocketWrapper getSocket() {
        return componentSocket.getSocketWrapper();
    }

    /**
     * @return the set of candidate pairs which are to be kept alive.
     */
    Set<CandidatePair> getKeepAlivePairs() {
        return keepAlivePairs;
    }

    /**
     * {@inheritDoc}
     * <br>
     * Handles events coming from candidate pairs.
     */
    @Override
    public void propertyChange(PropertyChangeEvent event) {
        String propertyName = event.getPropertyName();
        if (!(event.getSource() instanceof CandidatePair)) {
            return;
        }
        CandidatePair pair = (CandidatePair) event.getSource();
        if (!equals(pair.getParentComponent())) {
            // Events are fired by the IceMediaStream, which might have multiple components. Make sure that we only handle events for this component.
            return;
        }
        boolean addToKeepAlive = false;
        // We handle this case in setSelectedPair
        if (keepAliveStrategy == KeepAliveStrategy.SELECTED_ONLY) {
            return;
        }
        if (IceMediaStream.PROPERTY_PAIR_STATE_CHANGED.equals(propertyName)) {
            CandidatePairState newState = (CandidatePairState) event.getNewValue();
            if (CandidatePairState.SUCCEEDED.equals(newState)) {
                if (keepAliveStrategy == KeepAliveStrategy.ALL_SUCCEEDED) {
                    addToKeepAlive = true;
                } else if (keepAliveStrategy == KeepAliveStrategy.SELECTED_AND_TCP) {
                    Transport transport = pair.getLocalCandidate().getTransport();
                    addToKeepAlive = transport == Transport.TCP || transport == Transport.SSLTCP;
                    // Pairs with a remote TCP port 9 cannot be checked.
                    // Instead, the corresponding pair with the peer reflexive candidate needs to be checked. However, we observe
                    // such pairs transition into the SUCCEEDED state. Ignore them.
                    addToKeepAlive &= pair.getRemoteCandidate().getTransportAddress().getPort() != 9;
                }
            }
        }
        if (addToKeepAlive && !keepAlivePairs.contains(pair)) {
            keepAlivePairs.add(pair);
        }
    }

}
