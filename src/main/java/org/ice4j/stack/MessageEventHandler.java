/* See LICENSE.md for license information */
package org.ice4j.stack;

import org.ice4j.*;

/**
 * The class is used for collecting incoming STUN messages. This is our way of keeping scalable network and stun layers.
 *
 * @author Emil Ivov
 */
public interface MessageEventHandler {

    /**
     * Called when an incoming message has been received, parsed and is ready for delivery.
     * 
     * @param evt the Event object that encapsulates the newly received message
     */
    public void handleMessageEvent(StunMessageEvent evt);

}
