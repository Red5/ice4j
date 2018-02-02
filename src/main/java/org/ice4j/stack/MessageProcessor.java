/* See LICENSE.md for license information */
package org.ice4j.stack;

import java.util.Queue;
import java.util.concurrent.Future;

import org.ice4j.StunException;
import org.ice4j.StunMessageEvent;
import org.ice4j.message.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The class is used to parse and dispatch incoming messages in a multi-thread manner.
 *
 * @author Emil Ivov
 */
class MessageProcessor implements Runnable {
 
    private static final Logger logger = LoggerFactory.getLogger(MessageProcessor.class);

    /**
     * The queue where we store incoming messages until they are collected.
     */
    private final Queue<RawMessage> messageQueue;

    /**
     * The listener that will be retrieving MessageEvents
     */
    private final MessageEventHandler messageEventHandler;

    /**
     * A reference to the future that we use to execute ourselves.
     */
    private Future<?> future;

    /**
     * Creates a Message processor.
     *
     * @param netAccessManager the NetAccessManager which is creating the new instance
     * @param messageQueue incoming message queue
     * @throws IllegalArgumentException if any of the mentioned properties of
     * netAccessManager are null
     */
    MessageProcessor(NetAccessManager netAccessManager, Queue<RawMessage> messageQueue) throws IllegalArgumentException {
        if (netAccessManager == null) {
            throw new IllegalArgumentException("NetAccessManager may not be null");
        }
        if (messageQueue == null) {
            throw new IllegalArgumentException("Message queue may not be null");
        }
        this.messageQueue = messageQueue;
        this.messageEventHandler = (MessageEventHandler) netAccessManager.getStunStack();
    }

    /**
     * Does the message parsing.
     */
    public void run() {
        Thread.currentThread().setName("MessageProcessor@" + System.currentTimeMillis());
        // add an extra try/catch block that handles uncaught errors and helps avoid having dead threads in our pools.
        try {
            while (true) {
                RawMessage rawMessage = messageQueue.poll();
                // anything to parse?
                if (rawMessage != null) {
                    Message stunMessage = null;
                    try {
                        stunMessage = Message.decode(rawMessage.getBytes(), 0, rawMessage.getMessageLength());
                    } catch (StunException ex) {
                        logger.warn("Failed to decode a stun message!", ex);
                        continue; //let this one go and for better luck next time.
                    }
                    logger.trace("Dispatching a StunMessageEvent");
                    StunMessageEvent stunMessageEvent = new StunMessageEvent((StunStack) messageEventHandler, rawMessage, stunMessage);
                    messageEventHandler.handleMessageEvent(stunMessageEvent);
                }
                Thread.sleep(10L);
            }
        } catch (Throwable err) {
            // notify and bail
            logger.warn("Unexpected Error!", err);
        }
    }

    /**
     * Shut down the message processor.
     */
    void stop() {
        future.cancel(true);
    }

    /**
     * Sets a local reference to the future which owns this instance.
     * 
     * @param future
     */
    public void setFutureRef(Future<?> future) {
        this.future = future;
    }

}
