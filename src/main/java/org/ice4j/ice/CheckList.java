/* See LICENSE.md for license information */
package org.ice4j.ice;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.PriorityBlockingQueue;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A check list is a list of CandidatePairs with a state (i.e. a CheckListState). The pairs in a check list are those that an ICE
 * agent will run STUN connectivity checks for. There is one check list per in-use media stream resulting from the offer/answer exchange.
 * <p>
 * Given the asynchronous nature of ICE, be aware that a check list may be accessed from different locations.
 * 
 * @author Emil Ivov
 * @author Paul Gregoire
 */
public class CheckList extends PriorityBlockingQueue<CandidatePair> {

    private final static Logger logger = LoggerFactory.getLogger(CheckList.class);

    /**
     * A dummy serialization id.
     */
    private static final long serialVersionUID = 1L;

    /**
     * The name of the {@link PropertyChangeEvent} that we use to deliver
     * changes on the state of this check list.
     */
    public static final String PROPERTY_CHECK_LIST_STATE = "CheckListState";

    /**
     * The name of the {@link PropertyChangeEvent} that we use to deliver
     * changes on the end of checks of this check list.
     */
    public static final String PROPERTY_CHECK_LIST_CHECKS = "CheckListChecks";

    /**
     * The state of this check list.
     */
    private CheckListState state = CheckListState.RUNNING;

    /**
     * The triggeredCheckQueue is a FIFO queue containing candidate pairs for which checks are to be sent at the next available opportunity.
     * A pair would get into a triggered check queue as soon as we receive a check on its local candidate.
     */
    private final Queue<CandidatePair> triggeredCheckQueue = new ConcurrentLinkedQueue<>();

    /**
     * A reference to the {@link IceMediaStream} that we belong to.
     */
    private final IceMediaStream parentStream;

    /**
     * Contains {@link PropertyChangeListener}s registered with this {@link Agent} and following its changes of state.
     */
    private final Queue<PropertyChangeListener> stateListeners = new ConcurrentLinkedQueue<>();

    /**
     * Contains {@link PropertyChangeListener}s registered with this {@link Agent} and following its changes of state.
     */
    private final Queue<PropertyChangeListener> checkListeners = new ConcurrentLinkedQueue<>();

    /**
     * Creates a check list with the specified name.
     *
     * @param parentStream a reference to the parent {@link IceMediaStream}
     * that created us and that we belong to.
     */
    protected CheckList(IceMediaStream parentStream) {
        this.parentStream = parentStream;
    }

    /**
     * Returns the state of this check list.
     *
     * @return the CheckListState of this check list.
     */
    public CheckListState getState() {
        return state;
    }

    /**
     * Sets the state of this list.
     *
     * @param newState the CheckListState for this list.
     */
    protected void setState(CheckListState newState) {
        CheckListState oldState = this.state;
        this.state = newState;
        fireStateChange(oldState, newState);
    }

    /**
     * Adds pair to the local triggered check queue unless it's already there. Additionally, the method sets the pair's state to
     * {@link CandidatePairState#WAITING}.
     *
     * @param pair the pair to schedule a triggered check for.
     */
    protected void scheduleTriggeredCheck(CandidatePair pair) {
        if (!triggeredCheckQueue.contains(pair)) {
            triggeredCheckQueue.add(pair);
            pair.setStateWaiting();
        }
    }

    /**
     * Returns the first {@link CandidatePair} in the triggered check queue or null if that queue is empty.
     *
     * @return the first pair in the triggered check queue or null if that queue is empty.
     */
    protected CandidatePair popTriggeredCheck() {
        return triggeredCheckQueue.poll();
    }

    /**
     * Returns the next {@link CandidatePair} that is eligible for a regular connectivity check. According to RFC 5245 this would be the highest
     * priority pair that is in the Waiting state or, if there is no such pair, the highest priority Frozen {@link CandidatePair}.
     *
     * @return the next {@link CandidatePair} that is eligible for a regular connectivity check, which would either be the highest priority
     * Waiting pair or, when there's no such pair, the highest priority Frozen pair or null otherwise
     */
    protected synchronized CandidatePair getNextOrdinaryPairToCheck() {
        if (isEmpty()) {
            return null;
        }
        CandidatePair highestPriorityPair = null;
        for (CandidatePair pair : this) {
            if (pair.getState() == CandidatePairState.WAITING) {
                if (highestPriorityPair == null || pair.getPriority() > highestPriorityPair.getPriority()) {
                    highestPriorityPair = pair;
                }
            }
        }
        if (highestPriorityPair != null) {
            return highestPriorityPair;
        }
        for (CandidatePair pair : this) {
            if (pair.getState() == CandidatePairState.FROZEN) {
                if (highestPriorityPair == null || pair.getPriority() > highestPriorityPair.getPriority()) {
                    highestPriorityPair = pair;
                    pair.setStateWaiting();
                }
            }
        }
        return highestPriorityPair; //return even if null
    }

    /**
     * Determines whether this CheckList can be considered active. RFC 5245 says: A check list with at least one pair that is Waiting is
     * called an active check list.
     *
     * @return true if this list is active and false otherwise.
     */
    public boolean isActive() {
        for (CandidatePair pair : this) {
            if (pair.getState() == CandidatePairState.WAITING) {
                return true;
            }
        }
        return false;
    }

    /**
     * Determines whether all checks in this CheckList have ended one way or another.
     *
     * @return true if all checks for pairs in this list have either succeeded or failed (but non are are currently waiting or in progress)
     * or false otherwise..
     */
    public boolean allChecksCompleted() {
        for (CandidatePair pair : this) {
            CandidatePairState pairState = pair.getState();
            if (pairState != CandidatePairState.SUCCEEDED && pairState != CandidatePairState.FAILED) {
                return false;
            }
        }
        return true;
    }

    /**
     * Determines whether this CheckList can be considered frozen. RFC 5245 says: a check list with all pairs Frozen is called a frozen
     * check list.
     *
     * @return true if all pairs in this list are frozen and false otherwise.
     */
    public boolean isFrozen() {
        for (CandidatePair pair : this) {
            if (pair.getState() != CandidatePairState.FROZEN) {
                return false;
            }
        }
        return true;
    }

    /**
     * Returns a String representation of this check list. It consists of a list of the CandidatePairs in the order they
     * were inserted and enclosed in square brackets ("[]"). The method would also call and use the content returned by every member
     * CandidatePair.
     *
     * @return A String representation of this collection.
     */
    @Override
    public String toString() {
        StringBuilder buff = new StringBuilder("CheckList\n");
        for (CandidatePair pair : this) {
            buff.append(pair).append("\n");
        }
        return buff.toString();
    }

    /**
     * Computes and resets states of all pairs in this check list. For all pairs with the same foundation, we set the state of the pair with the lowest
     * component ID to Waiting. If there is more than one such pair, the one with the highest priority is used.
     */
    protected void computeInitialCheckListPairStates() {
        Map<String, CandidatePair> pairsToWait = new Hashtable<>();
        //first, determine the pairs that we'd need to put in the waiting state.
        for (CandidatePair pair : this) {
            // we need to check whether the pair is already in the wait list. if so we'll compare it with this one and determine
            // which of the two needs to stay.
            CandidatePair prevPair = pairsToWait.get(pair.getFoundation());
            if (prevPair == null) {
                //first pair with this foundation.
                pairsToWait.put(pair.getFoundation(), pair);
                continue;
            }
            // we already have a pair with the same foundation. determine which of the two has the lower component id and higher
            // priority and keep that one in the list.
            if (prevPair.getParentComponent() == pair.getParentComponent()) {
                if (pair.getPriority() > prevPair.getPriority()) {
                    //need to replace the pair in the list.
                    pairsToWait.put(pair.getFoundation(), pair);
                }
            } else {
                if (pair.getParentComponent().getComponentID() < prevPair.getParentComponent().getComponentID()) {
                    //need to replace the pair in the list.
                    pairsToWait.put(pair.getFoundation(), pair);
                }
            }
        }
        //now put the pairs we've selected in the Waiting state.
        for (CandidatePair pairToWait : pairsToWait.values()) {
            pairToWait.setStateWaiting();
        }
    }

    /**
     * Recomputes priorities of all pairs in this CheckList. Method is useful when an agent changes its isControlling property as a
     * result of a role conflict.
     */
    protected void recomputePairPriorities() {
        //first, determine the pairs that we'd need to put in the waiting state.
        for (CandidatePair pair : this) {
            pair.computePriority();
        }
    }

    /**
     * Removes from this CheckList and its associated triggered check queue all {@link CandidatePair}s that are in the Waiting and
     * Frozen states and that belong to the same {@link Component} as nominatedPair. Typically this will happen upon confirmation of
     * the nomination of one pair in that component. The procedure implemented here represents one of the cases specified in RFC 5245, Section 8.1.2:
     * <br>
     * The agent MUST remove all Waiting and Frozen pairs in the check list and triggered check queue for the same component as the
     * nominated pairs for that media stream.
     * <br>
     * If an In-Progress pair in the check list is for the same component as a nominated pair, the agent SHOULD cease retransmissions for its check
     * if its pair priority is lower than the lowest-priority nominated pair for that component.
     *
     * @param nominatedPair the {@link CandidatePair} whose nomination we need to handle.
     */
    protected void handleNominationConfirmed(CandidatePair nominatedPair) {
        Component cmp = nominatedPair.getParentComponent();
        if (cmp.getSelectedPair() != null) {
            return;
        }
        logger.info("Selected pair for stream {}: {}", cmp.toShortString(), nominatedPair.toShortString());
        cmp.setSelectedPair(nominatedPair);
        Iterator<CandidatePair> pairsIter = iterator();
        while (pairsIter.hasNext()) {
            CandidatePair pair = pairsIter.next();
            if (pair.getParentComponent() == cmp && (pair.getState() == CandidatePairState.WAITING || pair.getState() == CandidatePairState.FROZEN || (pair.getState() == CandidatePairState.IN_PROGRESS && pair.getPriority() < nominatedPair.getPriority()))) {
                pairsIter.remove();
            }
        }
        Iterator<CandidatePair> triggeredPairsIter = triggeredCheckQueue.iterator();
        while (triggeredPairsIter.hasNext()) {
            CandidatePair pair = triggeredPairsIter.next();
            if (pair.getParentComponent() == cmp && (pair.getState() == CandidatePairState.WAITING || pair.getState() == CandidatePairState.FROZEN || (pair.getState() == CandidatePairState.IN_PROGRESS && pair.getPriority() < nominatedPair.getPriority()))) {
                triggeredPairsIter.remove();
            }
        }
    }

    /**
     * Returns the name of this check list so that we could use it for debugging purposes.
     *
     * @return a name for this check list that we could use to distinguish it from other check lists while debugging.
     */
    public String getName() {
        return parentStream.getName();
    }

    /**
     * Adds l to the list of listeners tracking changes of the {@link CheckListState} of this CheckList
     *
     * @param l the listener to register.
     */
    public void addStateChangeListener(PropertyChangeListener l) {
        if (!stateListeners.contains(l)) {
            this.stateListeners.add(l);
        }
    }

    /**
     * Removes l from the list of listeners tracking changes of the {@link CheckListState} of this CheckList
     *
     * @param l the listener to remove.
     */
    public void removeStateChangeListener(PropertyChangeListener l) {
        this.stateListeners.remove(l);
    }

    /**
     * Creates a new {@link PropertyChangeEvent} and delivers it to all currently registered state listeners.
     *
     * @param oldState the {@link CheckListState} we had before the change
     * @param newState the {@link CheckListState} we had after the change
     */
    private void fireStateChange(CheckListState oldState, CheckListState newState) {
        PropertyChangeEvent evt = new PropertyChangeEvent(this, PROPERTY_CHECK_LIST_STATE, oldState, newState);
        for (PropertyChangeListener l : stateListeners) {
            l.propertyChange(evt);
        }
    }

    /**
     * Add a CheckListener. It will be notified when ordinary checks ended.
     *
     * @param l CheckListener to add
     */
    public void addChecksListener(PropertyChangeListener l) {
        if (!checkListeners.contains(l)) {
            checkListeners.add(l);
        }
    }

    /**
     * Remove a CheckListener.
     *
     * @param l CheckListener to remove
     */
    public void removeChecksListener(PropertyChangeListener l) {
        if (checkListeners.contains(l)) {
            checkListeners.remove(l);

        }
    }

    /**
     * Creates a new {@link PropertyChangeEvent} and delivers it to all currently registered checks listeners.
     */
    protected void fireEndOfOrdinaryChecks() {
        PropertyChangeEvent evt = new PropertyChangeEvent(this, PROPERTY_CHECK_LIST_CHECKS, false, true);
        for (PropertyChangeListener l : checkListeners) {
            l.propertyChange(evt);
        }
    }

    /**
     * Returns a reference to the {@link IceMediaStream} that created and that maintains this check list.
     *
     * @return a reference to the {@link IceMediaStream} that this list belongs to.
     */
    public IceMediaStream getParentStream() {
        return parentStream;
    }

}
