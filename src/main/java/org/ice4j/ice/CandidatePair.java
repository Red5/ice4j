/* See LICENSE.md for license information */
package org.ice4j.ice;

import java.util.Comparator;
import java.util.concurrent.atomic.AtomicReference;

import org.ice4j.stack.TransactionID;

/**
 * CandidatePairs map local to remote Candidates so that they could be added to check lists. Connectivity in ICE is always verified by
 * pairs: i.e. STUN packets are sent from the local candidate of a pair to the remote candidate of a pair. To see which pairs work, an agent schedules a
 * series of ConnectivityChecks. Each check is a STUN request/response transaction that the client will perform on a particular candidate pair by
 * sending a STUN request from the local candidate to the remote candidate.
 *
 * @author Emil Ivov
 * @author Lyubomir Marinov
 * @author Boris Grozev
 */
public class CandidatePair implements Comparable<CandidatePair> {

    //private final static Logger logger = LoggerFactory.getLogger(CandidatePair.class);

    /**
     * The value of the consentFreshness property of CandidatePair which indicates that the time in milliseconds of
     * the latest consent freshness confirmation is unknown.
     */
    public static final long CONSENT_FRESHNESS_UNKNOWN = -1;

    /**
     * The value of Math.pow(2, 32) calculated once for the purposes of optimizing performance.
     */
    private static final long MATH_POW_2_32 = 1L << 32;

    /**
     * A Comparator using the compareTo method of the CandidatePair.
     */
    public static final PairComparator comparator = new PairComparator();

    /**
     * The local candidate of this pair.
     */
    private LocalCandidate localCandidate;

    /**
     * The remote candidate of this pair.
     */
    private RemoteCandidate remoteCandidate;

    /**
     * Priority of the candidate-pair
     */
    private long priority;

    /**
     * A flag indicating whether we have seen an incoming check request that contained the USE-CANDIDATE attribute for this pair.
     */
    private boolean useCandidate;

    /**
     * A flag indicating whether we have sent a check request that contained the USE-CANDIDATE attribute for this pair. It is used in
     * GTalk compatibility mode as it lacks USE-CANDIDATE.
     */
    private boolean useCandidateSent;

    /**
     * Indicates whether this CandidatePair is on any of this agent's valid pair lists.
     */
    private boolean isValid;

    /**
     * If a valid candidate pair has its nominated flag set, it means that it may be selected by ICE for sending and receiving media.
     */
    private boolean isNominated;

    /**
     * Each candidate pair has a state that is assigned once the check list for each media stream has been computed. The ICE RFC defines five
     * potential values that the state can have and they are all represented in the CandidatePairState enumeration. The ICE spec stipulates
     * that the first step of the state initialization process is: The agent sets all of the pairs in each check list to the Frozen state, and hence
     * our default state.
     */
    private AtomicReference<CandidatePairState> state = new AtomicReference<>(CandidatePairState.FROZEN);

    /**
     * The {@link TransactionID} of the client transaction for a connectivity check over this pair in case it is in the
     * {@link CandidatePairState#IN_PROGRESS} state.
     */
    private TransactionID connCheckTranID = null;

    /**
     * The time in milliseconds of the latest consent freshness confirmation.
     */
    private long consentFreshness = CONSENT_FRESHNESS_UNKNOWN;

    /**
     * Creates a CandidatePair instance mapping localCandidate to remoteCandidate.
     *
     * @param localCandidate the local candidate of the pair
     * @param remoteCandidate the remote candidate of the pair
     */
    public CandidatePair(LocalCandidate localCandidate, RemoteCandidate remoteCandidate) {
        this.localCandidate = localCandidate;
        this.remoteCandidate = remoteCandidate;
        computePriority();
    }

    /**
     * Returns the foundation of this CandidatePair. The foundation of a CandidatePair is just the concatenation of the foundations
     * of its two candidates. Initially, only the candidate pairs with unique foundations are tested. The other candidate pairs are marked "frozen".
     * When the connectivity checks for a candidate pair succeed, the other candidate pairs with the same foundation are unfrozen. This avoids
     * repeated checking of components which are superficially more attractive but in fact are likely to fail.
     *
     * @return the foundation of this candidate pair, which is a concatenation of the foundations of the remote and local candidates
     */
    public String getFoundation() {
        return localCandidate.getFoundation() + remoteCandidate.getFoundation();
    }

    /**
     * Returns the LocalCandidate of this CandidatePair.
     *
     * @return the local Candidate of this CandidatePair
     */
    public LocalCandidate getLocalCandidate() {
        return localCandidate;
    }

    /**
     * Sets the LocalCandidate of this CandidatePair.
     *
     * @param localCnd the local Candidate of this CandidatePair
     */
    protected void setLocalCandidate(LocalCandidate localCnd) {
        this.localCandidate = localCnd;
    }

    /**
     * Returns the remote candidate of this CandidatePair.
     *
     * @return the remote Candidate of this CandidatePair.
     */
    public RemoteCandidate getRemoteCandidate() {
        return remoteCandidate;
    }

    /**
     * Sets the RemoteCandidate of this CandidatePair.
     *
     * @param remoteCnd the local Candidate of this
     * CandidatePair.
     */
    protected void setRemoteCandidate(RemoteCandidate remoteCnd) {
        this.remoteCandidate = remoteCnd;
    }

    /**
     * Returns the state of this CandidatePair. Each candidate pair has a state that is assigned once the check list for each media stream has
     * been computed. The ICE RFC defines five potential values that the state can have. They are represented here with the CandidatePairState
     * enumeration.
     *
     * @return the CandidatePairState that this candidate pair is currently in
     */
    public CandidatePairState getState() {
        return state.get();
    }

    /**
     * Sets the CandidatePairState of this pair to {@link CandidatePairState#FAILED}. This method should only be called by
     * the ICE agent, during the execution of the ICE procedures.
     */
    public void setStateFailed() {
        setState(CandidatePairState.FAILED, null);
    }

    /**
     * Sets the CandidatePairState of this pair to {@link CandidatePairState#FROZEN}. This method should only be called by
     * the ICE agent, during the execution of the ICE procedures.
     */
    public void setStateFrozen() {
        setState(CandidatePairState.FROZEN, null);
    }

    /**
     * Sets the CandidatePairState of this pair to {@link CandidatePairState#FROZEN}. This method should only be called by
     * the ICE agent, during the execution of the ICE procedures.
     *
     * @param tranID the {@link TransactionID} that we are using for the connectivity check in case we are entering the In-Progress
     * state and null otherwise
     */
    public void setStateInProgress(TransactionID tranID) {
        setState(CandidatePairState.IN_PROGRESS, tranID);
    }

    /**
     * Sets the CandidatePairState of this pair to {@link CandidatePairState#SUCCEEDED}. This method should only be called
     * by the ICE agent, during the execution of the ICE procedures.
     */
    public void setStateSucceeded() {
        setState(CandidatePairState.SUCCEEDED, null);
    }

    /**
     * Sets the CandidatePairState of this pair to {@link CandidatePairState#WAITING}. This method should only be called by
     * the ICE agent, during the execution of the ICE procedures.
     */
    public void setStateWaiting() {
        setState(CandidatePairState.WAITING, null);
    }

    /**
     * Sets the CandidatePairState of this pair to state. This method should only be called by the ice agent, during the execution of
     * the ICE procedures. Note that passing a null transaction for the {@link CandidatePairState#IN_PROGRESS} or a non-null for any
     * other state would cause an {@link IllegalArgumentException} to be thrown.
     *
     * @param newState the state that this candidate pair is to enter
     * @param tranID the {@link TransactionID} that we are using for the connectivity check in case we are entering the In-Progress
     * state and null otherwise
     * @throws IllegalArgumentException if state is {@link CandidatePairState#IN_PROGRESS} and tranID is null
     */
    private synchronized void setState(CandidatePairState newState, TransactionID tranID) throws IllegalArgumentException {
        CandidatePairState oldState = state.getAndSet(newState);
        if (newState == CandidatePairState.IN_PROGRESS) {
            if (tranID == null) {
                throw new IllegalArgumentException("Putting a pair into the In-Progress state MUST be accompanied with the TransactionID of the connectivity check");
            }
        } else {
            if (tranID != null) {
                throw new IllegalArgumentException("How could you have a transaction for a pair that's not in the In-Progress state?");
            }
        }
        this.connCheckTranID = tranID;
        getParentComponent().getParentStream().firePairPropertyChange(this, IceMediaStream.PROPERTY_PAIR_STATE_CHANGED, oldState, newState);
    }

    /**
     * Determines whether this candidate pair is frozen or not. Initially, only the candidate pairs with unique foundations are tested. The other
     * candidate pairs are marked "frozen". When the connectivity checks for a candidate pair succeed, the other candidate pairs with the same
     * foundation are unfrozen.
     *
     * @return true if this candidate pair is frozen and false otherwise
     */
    public boolean isFrozen() {
        return getState().equals(CandidatePairState.FROZEN);
    }

    /**
     * Returns the candidate in this pair that belongs to the controlling agent.
     *
     * @return a reference to the Candidate instance that comes from the controlling agent
     */
    public Candidate<?> getControllingAgentCandidate() {
        return (getLocalCandidate().getParentComponent().getParentStream().getParentAgent().isControlling()) ? getLocalCandidate() : getRemoteCandidate();
    }

    /**
     * Returns the candidate in this pair that belongs to the controlled agent.
     *
     * @return a reference to the Candidate instance that comes from the controlled agent
     */
    public Candidate<?> getControlledAgentCandidate() {
        return (getLocalCandidate().getParentComponent().getParentStream().getParentAgent().isControlling()) ? getRemoteCandidate() : getLocalCandidate();
    }

    /**
     * A candidate pair priority is computed the following way:
     * <br>
     * Let G be the priority for the candidate provided by the controlling agent. Let D be the priority for the candidate provided by the
     * controlled agent. The priority for a pair is computed as:
     * <br>
     * <i>pair priority = 2^32*MIN(G,D) + 2*MAX(G,D) + (G&gt;D?1:0)</i>
     * <br>
     * This formula ensures a unique priority for each pair. Once the priority is assigned, the agent sorts the candidate pairs in decreasing order of
     * priority. If two pairs have identical priority, the ordering amongst them is arbitrary.
     */
    protected void computePriority() {
        // Use g and d as local and remote candidate priority names to fit the definition in the RFC.
        long g = getControllingAgentCandidate().getPriority();
        long d = getControlledAgentCandidate().getPriority();
        long min, max, expr;
        if (g > d) {
            min = d;
            max = g;
            expr = 1L;
        } else {
            min = g;
            max = d;
            expr = 0L;
        }
        this.priority = MATH_POW_2_32 * min + 2 * max + expr;
    }

    /**
     * Returns the priority of this pair.
     *
     * @return the priority of this pair
     */
    public long getPriority() {
        return priority;
    }

    /**
     * Compares this CandidatePair with the specified object for order. Returns a negative integer, zero, or a positive integer as this
     * CandidatePair's priority is greater than, equal to, or less than the one of the specified object thus insuring that higher priority pairs
     * will come first.<p>
     *
     * @param   candidatePair the Object to be compared
     * @return  a negative integer, zero, or a positive integer as this CandidatePair's priority is greater than, equal to, or less than
     * the one of the specified object
     * @throws ClassCastException if the specified object's type prevents it from being compared to this Object
     */
    public int compareTo(CandidatePair candidatePair) {
        long thisPri = getPriority();
        long otherPri = candidatePair.getPriority();
        return (thisPri < otherPri) ? 1 : (thisPri == otherPri) ? 0 : -1;
    }

    /**
     * Compares this CandidatePair to obj and returns true if pairs have equal local and equal remote candidates and
     * false otherwise.
     *
     * @param obj the Object that we'd like to compare this pair to
     * @return true if pairs have equal local and equal remote candidates and false otherwise
     */
    @Override
    public boolean equals(Object that) {
        if (!(that instanceof CandidatePair)) {
            return false;
        }
        CandidatePair thatPair = (CandidatePair) that;
        //boolean equal = localCandidate.equals(thatPair.localCandidate) && remoteCandidate.equals(thatPair.remoteCandidate);
        //if (logger.isTraceEnabled()) {
        //    logger.trace("Equal: {}\nlocalCandidates:\n\t{}\n\t{}\nremoteCandidates:\n\t{}\n\t{}", equal, localCandidate, thatPair.localCandidate, remoteCandidate, thatPair.remoteCandidate);
        //}
        //return equal;
        // XXX Don't change this to also depend on other pair properties because ConnectivityCheckClient counts on it only using the candidates for comparisons
        //return localCandidate.equals(thatPair.localCandidate) && remoteCandidate.equals(thatPair.remoteCandidate);
        // use the short string, it should be good enough to check pair equality
        return localCandidate.toShortString().equals(thatPair.localCandidate.toShortString()) && remoteCandidate.toShortString().equals(thatPair.remoteCandidate.toShortString());
    }

    /** {@inheritDoc} */
    @Override
    public int hashCode() {
        // Even if the following hashCode algorithm has drawbacks because of it simplicity, it is better than nothing because at least it allows
        // CandidatePair to be used as a HashMap key.
        // XXX While localCandidate is not final, the parentComponent is supposedly effectively final.
        return getLocalCandidate().getParentComponent().hashCode();
    }

    /**
     * Returns a String representation of this CandidatePair.
     *
     * @return a String representation of the object
     */
    @Override
    public String toString() {
        return "CandidatePair (State=" + getState() + " Priority=" + getPriority() + "):\n\tLocalCandidate=" + getLocalCandidate() + "\n\tRemoteCandidate=" + getRemoteCandidate();
    }

    /**
     * Returns a short String representation of this CandidatePair.
     *
     * @return a short String representation of the object
     */
    public String toShortString() {
        return getLocalCandidate().toShortString() + " -> " + getRemoteCandidate().toShortString() + " (" + getParentComponent().toShortString() + ")";
    }

    /**
     * A Comparator using the compareTo method of the CandidatePair
     */
    public static class PairComparator implements Comparator<CandidatePair> {
        /**
         * Compares pair1 and pair2 for order. Returns a negative integer, zero, or a positive integer as pair1's
         * priority is greater than, equal to, or less than the one of the pair2, thus insuring that higher priority pairs will come first.
         *
         * @param pair1 the first CandidatePair to be compared
         * @param pair2 the second CandidatePair to be compared
         * @return  a negative integer, zero, or a positive integer as the first pair's priority priority is greater than, equal to, or less than
         * the one of the second pair.
         * @throws ClassCastException if the specified object's type prevents it from being compared to this Object
         */
        public int compare(CandidatePair pair1, CandidatePair pair2) {
            return pair1.compareTo(pair2);
        }

        /**
         * Indicates whether some other object is &quot;equal to&quot; to this Comparator.  This method must obey the general contract of
         * Object.equals(Object).  Additionally, this method can return true <i>only</i> if the specified Object is also a
         * comparator and it imposes the same ordering as this comparator. Thus, <code>comp1.equals(comp2)</code> implies that
         * sgn(comp1.compare(o1,o2))==sgn(comp2.compare(o1, o2)) for every object reference o1 and o2.<p>
         *
         * Note that it is <i>always</i> safe <i>not</i> to override Object.equals(Object).  However, overriding this method may,
         * in some cases, improve performance by allowing programs to determine that two distinct Comparators impose the same order.
         *
         * @param obj the reference object with which to compare
         * @return true only if the specified object is also a comparator and it imposes the same ordering as this comparator
         * @see java.lang.Object#equals(java.lang.Object)
         * @see java.lang.Object#hashCode()
         */
        @Override
        public boolean equals(Object obj) {
            return obj instanceof PairComparator;
        }
    }

    /**
     * Returns the Component that this pair belongs to.
     *
     * @return the Component that this pair belongs to
     */
    public Component getParentComponent() {
        return getLocalCandidate().getParentComponent();
    }

    /**
     * Returns the {@link TransactionID} used in the connectivity check associated with this {@link CandidatePair} when it's in the
     * {@link CandidatePairState#IN_PROGRESS} or null if it's in any other state.
     *
     * @return the {@link TransactionID} used in the connectivity check associated with this {@link CandidatePair} when it's in the
     * {@link CandidatePairState#IN_PROGRESS} or null if it's in any other state.
     */
    public TransactionID getConnectivityCheckTransaction() {
        return connCheckTranID;
    }

    /**
     * Raises the useCandidateSent flag for this pair.
     */
    public void setUseCandidateSent() {
        this.useCandidateSent = true;
    }

    /**
     * Returns true if someone has previously raised this pair's useCandidateSent flag and false otherwise.
     *
     * @return true if someone has previously raised this pair's useCandidate flag and false otherwise
     */
    public boolean useCandidateSent() {
        return useCandidateSent;
    }

    /**
     * Raises the useCandidate flag for this pair.
     */
    public void setUseCandidateReceived() {
        this.useCandidate = true;
    }

    /**
     * Returns true if someone has previously raised this pair's useCandidate flag and false otherwise.
     *
     * @return true if someone has previously raised this pair's useCandidate flag and false otherwise
     */
    public boolean useCandidateReceived() {
        return useCandidate;
    }

    /**
     * Sets this pair's nominated flag to true. If a valid candidate pair has its nominated flag set, it means that it may be selected by ICE
     * for sending and receiving media.
     */
    public void nominate() {
        this.isNominated = true;
        getParentComponent().getParentStream().firePairPropertyChange(this, IceMediaStream.PROPERTY_PAIR_NOMINATED, false, true);
    }

    /**
     * Returns the value of this pair's nominated flag. If a valid candidate pair has its nominated flag set, it means that it may be selected by ICE
     * for sending and receiving media.
     *
     * @return true if this pair has already been nominated for selection and false otherwise
     */
    public boolean isNominated() {
        return this.isNominated;
    }

    /**
     * Returns true if this pair has been confirmed by a connectivity check response and false otherwise.
     *
     * @return true if this pair has been confirmed by a connectivity check response and false otherwise
     */
    public boolean isValid() {
        return isValid;
    }

    /**
     * Marks this pair as valid. Should only be used internally.
     */
    protected void validate() {
        this.isValid = true;
        getParentComponent().getParentStream().firePairPropertyChange(this, IceMediaStream.PROPERTY_PAIR_VALIDATED, false, true);
    }

    /**
     * Returns whether or not the local and remote candidate bases match.
     * 
     * @return true for a matching transport and false otherwise
     */
    public boolean validTransport() {
        return (localCandidate.getBase().getTransportAddress().getTransport().equals(remoteCandidate.getTransportAddress().getTransport()));
    }

    /**
     * Gets the time in milliseconds of the latest consent freshness confirmation.
     *
     * @return the time in milliseconds of the latest consent freshness confirmation
     */
    public long getConsentFreshness() {
        return consentFreshness;
    }

    /**
     * Sets the time in milliseconds of the latest consent freshness confirmation to now.
     */
    void setConsentFreshness() {
        setConsentFreshness(System.currentTimeMillis());
    }

    /**
     * Sets the time in milliseconds of the latest consent freshness confirmation to a specific time.
     *
     * @param consentFreshness the time in milliseconds of the latest consent freshness to be set on this CandidatePair
     */
    void setConsentFreshness(long consentFreshness) {
        if (this.consentFreshness != consentFreshness) {
            long oldValue = this.consentFreshness;
            this.consentFreshness = consentFreshness;
            long newValue = this.consentFreshness;
            getParentComponent().getParentStream().firePairPropertyChange(this, IceMediaStream.PROPERTY_PAIR_CONSENT_FRESHNESS_CHANGED, oldValue, newValue);
        }
    }

}
