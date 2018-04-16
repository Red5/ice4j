/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal. Copyright @ 2015 Atlassian Pty Ltd Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or
 * agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under the License.
 */
package org.ice4j;

import java.util.EventObject;

import org.ice4j.message.Message;
import org.ice4j.stack.StunStack;
import org.ice4j.stack.TransactionID;

/**
 * Represents an EventObject which notifies of an event associated with
 * a specific STUN Message.
 *
 * @author Lyubomir Marinov
 */
public class BaseStunMessageEvent extends EventObject {

    //private static final Logger logger = LoggerFactory.getLogger(BaseStunMessageEvent.class);

    /**
     * A dummy version UID to suppress warnings.
     */
    private static final long serialVersionUID = 1L;

    /**
     * The STUN Message associated with this event.
     */
    private final Message message;

    /**
     * The StunStack associated with this instance.
     */
    private final StunStack stunStack;

    /**
     * The ID of the transaction related to {@link #message}.
     */
    private TransactionID transactionID;

    /**
     * Initializes a new BaseStunMessageEvent associated with a
     * specific STUN Message.
     *
     * @param stunStack the StunStack to be associated with the new
     * instance
     * @param sourceAddress the TransportAddress which is to be
     * reported as the source of the new event
     * @param message the STUN Message associated with the new event
     */
    public BaseStunMessageEvent(StunStack stunStack, TransportAddress sourceAddress, Message message) {
        super(sourceAddress);

        this.stunStack = stunStack;
        this.message = message;
    }

    /**
     * Gets the STUN Message associated with this event.
     *
     * @return the STUN Message associated with this event
     */
    public Message getMessage() {
        return message;
    }

    /**
     * Gets the TransportAddress which is the source of this event.
     *
     * @return the TransportAddress which is the source of this event
     */
    protected TransportAddress getSourceAddress() {
        return (TransportAddress) getSource();
    }

    /**
     * Gets the StunStack associated with this instance.
     *
     * @return the StunStack associated with this instance
     */
    public StunStack getStunStack() {
        return stunStack;
    }

    /**
     * Gets the ID of the transaction related to the STUN Message associated with this event.
     *
     * @return the ID of the transaction related to the STUN Message associated with this event
     */
    public TransactionID getTransactionID() {
        //logger.debug("getTransactionID: {}", String.valueOf(transactionID));
        if (transactionID == null) {
            transactionID = TransactionID.createTransactionID(getStunStack(), getMessage().getTransactionID());
        }
        return transactionID;
    }

    /**
     * Allows descendants of this class to set the transaction ID so that we don't need to look it up later. This is not mandatory.
     *
     * @param tranID the ID of the transaction associated with this event.
     */
    protected void setTransactionID(TransactionID tranID) {
        //logger.debug("setTransactionID: {}", String.valueOf(tranID));
        this.transactionID = tranID;
    }
}
