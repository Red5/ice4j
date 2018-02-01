/* See LICENSE.md for license information */
package org.ice4j.ice;

import java.util.Comparator;

/**
 * Compares candidates based on their priority.
 *
 * @author Emil Ivov
 */
class CandidatePrioritizer implements Comparator<Candidate<?>> {
    /**
     * Compares the two Candidates based on their priority and
     * returns a negative integer, zero, or a positive integer as the first
     * Candidate has a lower, equal, or greater priority than the
     * second.
     *
     * @param c1 the first Candidate to compare.
     * @param c2 the second Candidate to compare.
     *
     * @return a negative integer, zero, or a positive integer as the first
     *         Candidate has a lower, equal,
     *         or greater priority than the
     *         second.
     */
    public static int compareCandidates(Candidate<?> c1, Candidate<?> c2) {
        if (c1.getPriority() < c2.getPriority()) {
            return 1;
        } else if (c1.getPriority() == c2.getPriority()) {
            return 0;
        } else {
            //if(c1.getPriority() > c2.getPriority())
            return -1;
        }
    }

    /**
     * Compares the two Candidates based on their priority and
     * returns a negative integer, zero, or a positive integer as the first
     * Candidate has a lower, equal, or greater priority than the
     * second.
     *
     * @param c1 the first Candidate to compare.
     * @param c2 the second Candidate to compare.
     *
     * @return a negative integer, zero, or a positive integer as the first
     *         Candidate has a lower, equal,
     *         or greater priority than the
     *         second.
     */
    public int compare(Candidate<?> c1, Candidate<?> c2) {
        return CandidatePrioritizer.compareCandidates(c1, c2);
    }

    /**
     * Indicates whether some other object is &quot;equal to&quot; this
     * Comparator.  This method must obey the general contract of
     * Object.equals(Object).  Additionally, this method can return
     * true <i>only</i> if the specified Object is also a
     * comparator and it imposes the same ordering as this comparator. Thus,
     * <code>comp1.equals(comp2)</code> implies that
     * sgn(comp1.compare(o1, o2))==sgn(comp2.compare(o1, o2)) for
     * every object reference o1 and o2.<p>
     * <p>
     * Note that it is <i>always</i> safe <i>not</i> to override
     * Object.equals(Object).  However, overriding this method may,
     * in some cases, improve performance by allowing programs to determine
     * that two distinct Comparators impose the same order.
     * <br>
     *
     * @param obj the reference object with which to compare.
     *
     * @return <code>true</code> only if the specified object is also
     *         a comparator and it imposes the same ordering as this
     *         comparator.
     *
     * @see Object#equals(Object)
     * @see Object#hashCode()
     */
    public boolean equals(Object obj) {
        return (obj instanceof CandidatePrioritizer);
    }
}
