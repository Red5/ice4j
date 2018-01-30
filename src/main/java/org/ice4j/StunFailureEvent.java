/* See LICENSE.md for license information */
package org.ice4j;

import org.ice4j.message.Message;
import org.ice4j.stack.StunStack;

/**
 * The class is used to dispatch events that occur when a STUN transaction
 * fails asynchronously for reasons like a port unreachable exception for
 * example.
 *
 * @author Emil Ivov
 */
public class StunFailureEvent extends BaseStunMessageEvent {
    /**
     * Serial version UID for this Serializable class.
     */
    private static final long serialVersionUID = 41232541L;

    /**
     * The Exception that caused this failure.
     */
    private final Throwable cause;

    /**
     * Constructs a StunFailureEvent according to the specified
     * message.
     * 
     * @param stunStack the StunStack to be associated with the new
     * instance
     * @param message the message itself
     * @param localAddress the local address that the message was sent from.
     * @param cause the Exception that caused this failure or
     * null if there's no Exception associated with this
     * failure
     */
    public StunFailureEvent(StunStack stunStack, Message message, TransportAddress localAddress, Throwable cause) {
        super(stunStack, localAddress, message);

        this.cause = cause;
    }

    /**
     * Returns the TransportAddress that the message was supposed to
     * leave from.
     *
     * @return the TransportAddress that the message was supposed to
     * leave from.
     */
    public TransportAddress getLocalAddress() {
        return getSourceAddress();
    }

    /**
     * Returns the Exception that cause this failure or null
     * if the failure is not related to an Exception.
     *
     * @return the Exception that cause this failure or null
     * if the failure is not related to an Exception.
     */
    public Throwable getCause() {
        return cause;
    }

    /**
     * Returns a String representation of this event, containing the
     * corresponding message, and local address.
     *
     * @return a String representation of this event, containing the
     * corresponding message, and local address.
     */
    @Override
    public String toString() {
        StringBuilder buff = new StringBuilder("StunFailureEvent:\n\tMessage=");
        buff.append(getMessage());
        buff.append(" localAddr=").append(getLocalAddress());
        return buff.toString();
    }
}
