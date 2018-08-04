/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal. Copyright @ 2015 Atlassian Pty Ltd Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or
 * agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under the License.
 */
package org.ice4j.ice.harvest;

import java.util.Collection;

import org.ice4j.ice.Component;
import org.ice4j.ice.LocalCandidate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a CandidateHarvester as an element in a
 * CandidateHarvesterSet.
 *
 * @author Lyubomir Marinov
 * @author Emil Ivov
 */
class CandidateHarvesterSetElement {

    private static final Logger logger = LoggerFactory.getLogger(CandidateHarvesterSetElement.class);

    /**
     * The indicator which determines whether
     * {@link CandidateHarvester#harvest(org.ice4j.ice.Component)} is to be
     * called on {@link #harvester}.
     */
    private boolean enabled = true;

    /**
     * The CandidateHarvester which is an element in a
     * CandidateHarvesterSet.
     */
    private final CandidateHarvester harvester;

    /**
     * Initializes a new CandidateHarvesterSetElement instance
     * which is to represent a specific CandidateHarvester as an
     * element in a CandidateHarvesterSet.
     *
     * @param harvester the CandidateHarvester which is to be
     * represented as an element in a CandidateHarvesterSet by the
     * new instance
     */
    public CandidateHarvesterSetElement(CandidateHarvester harvester) {
        this.harvester = harvester;
        harvester.getHarvestStatistics().harvesterName = harvester.toString();
    }

    /**
     * Calls {@link CandidateHarvester#harvest(org.ice4j.ice.Component)} on the
     * associated CandidateHarvester if enabled.
     *
     * @param component the Component to gather candidates for
     * @param trickleCallback the {@link TrickleCallback} that we will be
     * feeding candidates to, or null in case the application doesn't
     * want us trickling any candidates
     */
    public void harvest(Component component, TrickleCallback trickleCallback) {
        if (isEnabled()) {
            startHarvestTiming();
            Collection<LocalCandidate> candidates = harvester.harvest(component);
            stopHarvestTiming(candidates);
            // If the CandidateHarvester has not gathered any candidates, it is considered failed and will not be used again in order to not
            // risk it slowing down the overall harvesting.
            if ((candidates == null) || candidates.isEmpty()) {
                setEnabled(false);
            } else if (trickleCallback != null) {
                trickleCallback.onIceCandidates(candidates);
            }
        }
    }

    /**
     * Determines whether the associated CandidateHarvester is
     * considered to be the same as a specific CandidateHarvester.
     *
     * @param harvester the CandidateHarvester to be compared to
     * the associated CandidateHarvester
     * @return true if the associated CandidateHarvester
     * is considered to be the same as the specified harvester;
     * otherwise, false
     */
    public boolean harvesterEquals(CandidateHarvester harvester) {
        return this.harvester.equals(harvester);
    }

    /**
     * Gets the indicator which determines whether
     * {@link CandidateHarvester#harvest(Component)} is to be called on the
     * associated CandidateHarvester.
     *
     * @return true if
     * CandidateHarvester#harvest(Component) is to be called on the
     * associated CandidateHarvester; otherwise, false
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Sets the indicator which determines whether
     * {@link CandidateHarvester#harvest(Component)} is to be called on the
     * associated CandidateHarvester.
     *
     * @param enabled true if
     * CandidateHarvester#harvest(Component) is to be called on the
     * associated CandidateHarvester; otherwise, false
     */
    public void setEnabled(boolean enabled) {
        logger.debug("{} {}", (enabled ? "Enabling:" : "Disabling:"), harvester);
        this.enabled = enabled;
    }

    /**
     * Returns the CandidateHarvester encapsulated by this element.
     *
     * @return the CandidateHarvester encapsulated by this element.
     */
    public CandidateHarvester getHarvester() {
        return harvester;
    }

    /**
     * Starts the harvesting timer. Called when the harvest begins.
     */
    private void startHarvestTiming() {
        harvester.getHarvestStatistics().startHarvestTiming();
    }

    /**
     * Stops the harvesting timer. Called when the harvest ends.
     *
     * @param harvest the harvest that we just concluded.
     */
    private void stopHarvestTiming(Collection<LocalCandidate> harvest) {
        harvester.getHarvestStatistics().stopHarvestTiming(harvest);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((harvester == null) ? 0 : harvester.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        CandidateHarvesterSetElement other = (CandidateHarvesterSetElement) obj;
        if (harvester == null) {
            if (other.harvester != null)
                return false;
        } else if (!harvester.equals(other.harvester))
            return false;
        return true;
    }

}
