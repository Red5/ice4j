package org.ice4j.socket;

import java.util.Collection;
import java.util.concurrent.LinkedTransferQueue;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Extension of the LinkedTransferQueue so that removals may be tracked when performed by outside callers.
 * 
 * @param <E>
 */
public class SizeTrackedLinkedTransferQueue<E> extends LinkedTransferQueue<E> {

    private static final long serialVersionUID = -2455379209835774055L;

    private final static Logger logger = LoggerFactory.getLogger(SizeTrackedLinkedTransferQueue.class);

    private final static boolean isDebug = logger.isDebugEnabled();

    @SuppressWarnings("rawtypes")
    private final static AtomicIntegerFieldUpdater<SizeTrackedLinkedTransferQueue> AtomicQueueSizeUpdater = AtomicIntegerFieldUpdater.newUpdater(SizeTrackedLinkedTransferQueue.class, "queueSize");

    private volatile int queueSize;

    @Override
    public boolean offer(E message) {
        // while the queue type is unbounded, this will always return true
        boolean added = super.offer(message);
        if (added) {
            int size = AtomicQueueSizeUpdater.addAndGet(this, 1);
            if (isDebug) {
                logger.debug("Message queued, current size: {}", size);
            }
        }
        return added;
    }

    @Override
    public E poll() {
        E message = super.poll();
        if (message != null) {
            int size = AtomicQueueSizeUpdater.decrementAndGet(this);
            if (isDebug) {
                logger.debug("Message removed, current size: {}", size);
            }
        }
        return message;
    }

    @Override
    public int drainTo(Collection<? super E> messages) {
        int removed = super.drainTo(messages);
        int size = AtomicQueueSizeUpdater.updateAndGet(this, s -> s - removed);
        if (isDebug) {
            logger.debug("Message drained by: {}, current size: {}", removed, size);
        }
        return removed;
    }

    @Override
    public boolean isEmpty() {
        return queueSize == 0;
    }

    @Override
    public int size() {
        return queueSize;
    }

}