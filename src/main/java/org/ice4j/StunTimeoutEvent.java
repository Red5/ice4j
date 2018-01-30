/* See LICENSE.md for license information */
package org.ice4j;

import org.ice4j.message.Message;
import org.ice4j.stack.StunStack;
import org.ice4j.stack.TransactionID;

/**
 * The class is used to dispatch events that occur when a STUN transaction
 * expires.
 *
 * @author Emil Ivov
 */
public class StunTimeoutEvent extends BaseStunMessageEvent {
    /**
     * Serial version UID for this Serializable class.
     */
    private static final long serialVersionUID = 41267841L;

    /**
     * Constructs a StunTimeoutEvent according to the specified
     * message.
     *
     * @param stunStack the StunStack to be associated with the new
     * instance
     * @param message the message itself
     * @param localAddress the local address that the message was sent from.
     * @param transactionID the ID of the  associated with this event.
     */
    public StunTimeoutEvent(StunStack stunStack, Message message, TransportAddress localAddress, TransactionID transactionID) {
        super(stunStack, localAddress, message);

        setTransactionID(transactionID);
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
     * Returns a String representation of this event, containing the
     * corresponding message, and local address.
     *
     * @return a String representation of this event, containing the
     * corresponding message, and local address.
     */
    @Override
    public String toString() {
        StringBuilder buff = new StringBuilder("StunTimeoutEvent:\n\tMessage=");
        buff.append(getMessage());
        buff.append(" localAddr=").append(getLocalAddress());
        return buff.toString();
    }
}
