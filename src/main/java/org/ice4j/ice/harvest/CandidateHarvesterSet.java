/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal. Copyright @ 2015 Atlassian Pty Ltd Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or
 * agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under the License.
 */
package org.ice4j.ice.harvest;

import java.util.AbstractSet;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.ice4j.StackProperties;
import org.ice4j.ice.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implements {@link Set} of CandidateHarvesters which runs the
 * gathering of candidate addresses performed by its elements in parallel.
 *
 * @author Lyubomir Marinov
 */
public class CandidateHarvesterSet extends AbstractSet<CandidateHarvester> {

    private static final Logger logger = LoggerFactory.getLogger(CandidateHarvesterSet.class);

    /**
     * The CandidateHarvesters which are the elements of this Set.
     */
    private final Collection<CandidateHarvesterSetElement> elements = new ConcurrentLinkedDeque<>();

    /**
     * A pool of thread used for gathering process.
     */
    private static ExecutorService threadPool = Executors.newCachedThreadPool();

    /**
     * Initializes a new CandidateHarvesterSet instance.
     */
    public CandidateHarvesterSet() {
    }

    /**
     * Adds a specific CandidateHarvester to this CandidateHarvesterSet and returns true if it is not already present. Otherwise, leaves this
     * set unchanged and returns false.
     *
     * @param harvester the CandidateHarvester to be added to this CandidateHarvesterSet
     * @return true if this CandidateHarvesterSet did not already contain the specified harvester; otherwise, false
     * @see Set#add(Object)
     */
    @Override
    public boolean add(CandidateHarvester harvester) {
        Optional<CandidateHarvesterSetElement> result = elements.stream().filter(element -> element.harvesterEquals(harvester)).findFirst();
        if (!result.isPresent()) {
            elements.add(new CandidateHarvesterSetElement(harvester));
            return true;
        }
        return false;
    }

    /**
     * Gathers candidate addresses for a specific Component. CandidateHarvesterSet delegates to the CandidateHarvesters which are its Set elements.
     *
     * @param component the Component to gather candidate addresses for
     * @see CandidateHarvester#harvest(Component)
     */
    public void harvest(Component component) {
        harvest(Arrays.asList(component), null);
    }

    /**
     * Gathers candidate addresses for a specific Component. CandidateHarvesterSet delegates to the CandidateHarvesters which are its Set elements.
     *
     * @param components the Component to gather candidate addresses for
     * @see CandidateHarvester#harvest(Component)
     * @param trickleCallback the {@link TrickleCallback} that we will be feeding candidates to, or null in case the application doesn't
     * want us trickling any candidates
     */
    public void harvest(final List<Component> components, TrickleCallback trickleCallback) {
        harvest(elements.iterator(), components, threadPool, trickleCallback);
    }

    /**
     * Gathers candidate addresses for a specific Component using specific CandidateHarvesters.
     *
     * @param harvesters the CandidateHarvesters to gather candidate addresses for the specified Component
     * @param components the Components to gather candidate addresses for
     * @param executorService the ExecutorService to schedule the execution of the gathering of candidate addresses performed by the
     * specified harvesters
     * @param trickleCallback the {@link TrickleCallback} that we will be feeding candidates to, or null in case the application doesn't
     * want us trickling any candidates
     */
    private void harvest(final Iterator<CandidateHarvesterSetElement> harvesters, final List<Component> components, ExecutorService executorService, final TrickleCallback trickleCallback) {
        // Start asynchronously executing the CandidateHarvester#harvest(Component) method of the harvesters.
        Map<CandidateHarvesterSetTask, Future<?>> tasks = new HashMap<>();
        while (true) {
            // Find the next CandidateHarvester which is to start gathering candidates.
            CandidateHarvesterSetElement harvester;
            synchronized (harvesters) {
                if (harvesters.hasNext()) {
                    harvester = harvesters.next();
                } else {
                    break;
                }
            }
            if (!harvester.isEnabled()) {
                continue;
            }
            List<Component> componentsCopy;
            synchronized (components) {
                componentsCopy = new ArrayList<>(components);
            }
            // Asynchronously start gathering candidates using the harvester.
            CandidateHarvesterSetTask task = new CandidateHarvesterSetTask(harvester, componentsCopy, trickleCallback);
            tasks.put(task, executorService.submit(task));
        }
        // Wait for all harvesters to be given a chance to execute their CandidateHarvester#harvest(Component) method.
        Iterator<Map.Entry<CandidateHarvesterSetTask, Future<?>>> taskIter = tasks.entrySet().iterator();
        while (taskIter.hasNext()) {
            Map.Entry<CandidateHarvesterSetTask, Future<?>> task = taskIter.next();
            Future<?> future = task.getValue();
            do {
                try {
                    future.get(StackProperties.getInt(StackProperties.HARVESTING_TIMEOUT, 15), TimeUnit.SECONDS);
                    break;
                } catch (TimeoutException te) {
                    CandidateHarvesterSetElement harvester = task.getKey().getHarvester();
                    if (harvester != null) {
                        harvester.setEnabled(false);
                    }
                    logger.warn("Timed out while harvesting from {}", harvester);
                    break;
                } catch (CancellationException ce) {
                    logger.warn("Harvester cancelled", ce);
                    // It got cancelled so we cannot say that the fault is with its current harvester.
                    break;
                } catch (ExecutionException ee) {
                    CandidateHarvesterSetElement harvester = task.getKey().getHarvester();
                    // A problem appeared during the execution of the task. CandidateHarvesterSetTask clears its harvester property for the
                    // purpose of determining whether the problem has appeared while working with a harvester.
                    logger.warn("Disabling harvester {}", harvester.getHarvester(), ee);
                    if (harvester != null) {
                        harvester.setEnabled(false);
                    }
                    break;
                } catch (InterruptedException ie) {
                }
            } while (true);
            taskIter.remove();
        }
    }

    /**
     * Returns an Iterator over the CandidateHarvesters which are elements in this CandidateHarvesterSet. The elements are
     * returned in no particular order.
     *
     * @return an Iterator over the CandidateHarvesters which are elements in this CandidateHarvesterSet
     * @see Set#iterator()
     */
    public Iterator<CandidateHarvester> iterator() {
        final Iterator<CandidateHarvesterSetElement> elementIter = elements.iterator();

        return new Iterator<CandidateHarvester>() {
            /**
             * Determines whether this iteration has more elements.
             *
             * @return true if this iteration has more elements; otherwise, false
             * @see Iterator#hasNext()
             */
            public boolean hasNext() {
                return elementIter.hasNext();
            }

            /**
             * Returns the next element in this iteration.
             *
             * @return the next element in this iteration
             * @throws NoSuchElementException if this iteration has no more elements
             * @see Iterator#next()
             */
            public CandidateHarvester next() throws NoSuchElementException {
                return elementIter.next().getHarvester();
            }

            /**
             * Removes from the underlying CandidateHarvesterSet the last CandidateHarvester (element) returned by
             * this Iterator. CandidateHarvestSet does not implement the remove operation at the time of this
             * writing i.e. it always throws UnsupportedOperationException.
             *
             * @throws IllegalStateException if the next method has not yet been called, or the remove method has
             * already been called after the last call to the next method
             * @throws UnsupportedOperationException if the remove operation is not supported by this Iterator
             * @see Iterator#remove()
             */
            public void remove() throws IllegalStateException, UnsupportedOperationException {
                throw new UnsupportedOperationException("remove");
            }
        };
    }

    /**
     * Returns the number of CandidateHarvesters which are elements in this CandidateHarvesterSet.
     *
     * @return the number of CandidateHarvesters which are elements in this CandidateHarvesterSet
     * @see Set#size()
     */
    public int size() {
        return elements.size();
    }
}
