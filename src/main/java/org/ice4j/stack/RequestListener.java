/* See LICENSE.md for license information */
package org.ice4j.stack;

import org.ice4j.*;
import org.ice4j.message.*;

/**
 * Handles incoming requests.
 *
 * @author Emil Ivov
 */
public interface RequestListener {
    /**
     * Called when delivering incoming STUN requests. Throwing an {@link IllegalArgumentException} from within this method would cause the
     * stack to reply with a 400 Bad Request {@link Response} using the exception's message as a reason phrase for the error response. Any
     * other exception would result in a 500 Server Error {@link Response}.
     *
     * @param evt the event containing the incoming STUN request.
     *
     * @throws IllegalArgumentException if evt contains a malformed {@link Request} and the stack would need to response with a
     * 400 Bad Request {@link Response}.
     */
    public void processRequest(StunMessageEvent evt) throws IllegalArgumentException;
}
