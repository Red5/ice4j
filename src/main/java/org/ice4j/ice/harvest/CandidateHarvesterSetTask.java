/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal. Copyright @ 2015 Atlassian Pty Ltd Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or
 * agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under the License.
 */
package org.ice4j.ice.harvest;

import java.util.Collection;

import org.ice4j.ice.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a task to be executed by the specified executorService and
 * to call {@link CandidateHarvester#harvest(Component)} on the specified
 * harvesters.
 *
 * @author Lyubomir Marinov
 * @author  Emil Ivov
 */
class CandidateHarvesterSetTask implements Runnable {
    /**
     * The Logger used by the CandidateHarvesterSetTask
     * class and its instances for logging output.
     */
    private static final Logger logger = LoggerFactory.getLogger(CandidateHarvesterSetTask.class);

    /**
     * The CandidateHarvester on which
     * {@link CandidateHarvester#harvest(org.ice4j.ice.Component)} is to be or
     * is being called.
     */
    private CandidateHarvesterSetElement harvester;

    /**
     * The {@link Component}s whose addresses we will be harvesting in this
     * task.
     */
    private Collection<Component> components;

    /**
     * The callback that we will be notifying every time a harvester completes.
     */
    private final TrickleCallback trickleCallback;

    /**
     * Initializes a new CandidateHarvesterSetTask which is to
     * call {@link CandidateHarvester#harvest(org.ice4j.ice.Component)} on a
     * specific harvester and then as many harvesters as possible.
     *
     * @param harvester the CandidateHarvester on which the
     * new instance is to call
     * @param components the Component whose candidates we are currently
     * gathering.
     * CandidateHarvester#harvest(Component) first
     */
    public CandidateHarvesterSetTask(CandidateHarvesterSetElement harvester, Collection<Component> components, TrickleCallback trickleCallback) {
        this.harvester = harvester;
        this.components = components;
        this.trickleCallback = trickleCallback;
    }

    /**
     * Gets the CandidateHarvester on which
     * {@link CandidateHarvester#harvest(org.ice4j.ice.Component)} is being
     * called.
     *
     * @return the CandidateHarvester on which
     * CandidateHarvester#harvest(Component) is being called
     */
    public CandidateHarvesterSetElement getHarvester() {
        return harvester;
    }

    /**
     * Runs the actual harvesting for this component
     */
    public void run() {
        if (harvester == null || !harvester.isEnabled()) {
            return;
        }
        for (Component component : components) {
            try {
                harvester.harvest(component, trickleCallback);
            } catch (Throwable t) {
                logger.warn("Disabling harvester due to exception: {}", t);
                harvester.setEnabled(false);
                if (t instanceof ThreadDeath) {
                    throw (ThreadDeath) t;
                }
            }
        }

        /*
         * CandidateHarvester#harvest(Component) has been called on the harvester and its success or failure has been noted. Now forget the harvester because any failure to
         * continue execution is surely not its fault.
         */
        harvester = null;
    }
}
