/* See LICENSE.md for license information */
package org.ice4j.ice.harvest;

import java.util.*;

import org.ice4j.ice.*;

/**
 * A CandidateHarvester gathers a certain kind of Candidates (e.g. host, reflexive, or relayed) for a specified {@link org.ice4j.ice.Component}.
 *
 * @author Emil Ivov
 * @author Lyubomir Marinov
 * @author Boris Grozev
 */
public interface CandidateHarvester {
    /**
     * Gathers all candidate addresses of the type that this CandidateHarvester supports. The gathered candidate addresses
     * are to be added by this CandidateHarvester to the specified Component using {@link Component#addLocalCandidate(LocalCandidate)}
     * as soon as they are discovered.
     *
     * @param component the {@link Component} that we'd like to gather candidate addresses for
     * @return the LocalCandidates gathered by this CandidateHarvester. Though they are to be added by this
     * CandidateHarvester to the specified component as soon as they are discovered, they should also be returned in order to make
     * sure that the gathering will be considered successful.
     */
    Collection<LocalCandidate> harvest(Component component);

    /**
     * Returns the statistics describing how well the various harvests of this harvester went.
     *
     * @return The {@link HarvestStatistics} describing this harvester's harvests
     */
    HarvestStatistics getHarvestStatistics();

    /**
     * Returns true if this CandidateHarvester is to be considered a harvester for host candidates. Such a harvester should
     * 1. Create local candidates of type HOST_CANDIDATE.
     * 2. Not depend on other local candidates, already harvested for the
     *      component for which it is called.
     * 3. Not perform blocking operations while harvesting.
     *
     * @return true if this CandidateHarvester is a harvester for host candidates
     */
    boolean isHostHarvester();
}
