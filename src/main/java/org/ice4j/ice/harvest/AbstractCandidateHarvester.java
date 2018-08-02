/* See LICENSE.md for license information */
package org.ice4j.ice.harvest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An abstract partial implementation of {@link CandidateHarvester}.
 *
 * @author Emil Ivov
 * @author Lyubomir Marinov
 * @author Boris Grozev
 */
public abstract class AbstractCandidateHarvester implements CandidateHarvester {

    protected Logger logger = LoggerFactory.getLogger(AbstractCandidateHarvester.class);

    /**
     * Manages statistics about harvesting time.
     */
    private HarvestStatistics harvestStatistics = new HarvestStatistics();

    /** {@inheritDoc} */
    @Override
    public HarvestStatistics getHarvestStatistics() {
        return harvestStatistics;
    }

    /** {@inheritDoc} */
    @Override
    public boolean isHostHarvester() {
        return false;
    }

}
