/* See LICENSE.md for license information */
package org.ice4j.stunclient;

import java.io.IOException;
import java.util.Vector;

import org.ice4j.StunException;
import org.ice4j.StunMessageEvent;
import org.ice4j.TransportAddress;
import org.ice4j.ice.nio.IceUdpTransport;
import org.ice4j.message.Response;
import org.ice4j.socket.IceSocketWrapper;
import org.ice4j.socket.IceUdpSocketWrapper;
import org.ice4j.stack.RequestListener;
import org.ice4j.stack.StunStack;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class implements a programmable STUN server that sends predefined
 * sequences of responses. It may be used to test whether a STUN client
 * behaves correctly in different use cases.
 *
 * @author Emil Ivov
 */
public class ResponseSequenceServer implements RequestListener {

    private static final Logger logger = LoggerFactory.getLogger(ResponseSequenceServer.class);

    /**
     * The sequence of responses to send.
     */
    private Vector<Object> messageSequence = new Vector<>();

    /**
     * The StunStack used by this instance for the purposes of STUN communication.
     */
    private final StunStack stunStack;

    private TransportAddress serverAddress = null;

    private IceSocketWrapper localSocket = null;

    /**
     * Initializes a new ResponseSequenceServer instance with a specific StunStack to be used for the purposes of STUN communication.
     *
     * @param stunStack the StunStack to be used by the new instance for the purposes of STUN communication
     * @param bindAddress
     */
    public ResponseSequenceServer(StunStack stunStack, TransportAddress bindAddress) {
        this.stunStack = stunStack;
        this.serverAddress = bindAddress;
    }

    /**
     * Initializes the underlying stack.
     * 
     * @throws StunException if something else fails
     * @throws IOException if we fail to bind a local socket.
     */
    public void start() throws IOException, StunException {
        localSocket = new IceUdpSocketWrapper(serverAddress);
        stunStack.addRequestListener(serverAddress, this);
        IceUdpTransport.getInstance().addBinding(stunStack, localSocket);
    }

    /**
     * Resets the server (deletes the sequence and stops the stack)
     */
    public void shutDown() {
        messageSequence.removeAllElements();
        localSocket.close();
    }

    /**
     * Adds the specified response to this sequence or marks a pause (i.e. do not respond) if response is null.
     * 
     * @param response the response to add or null to mark a pause
     */
    public void addMessage(Response response) {
        if (response == null) {
            // leave a mark to skip a message
            messageSequence.add(false);
        } else {
            messageSequence.add(response);
        }
    }

    /**
     * Completely ignores the event that is passed and just sends the next message from the sequence - or does nothing if there's something
     * different from a Response on the current position.
     * 
     * @param evt the event being dispatched
     */
    public void processRequest(StunMessageEvent evt) {
        if (messageSequence.isEmpty()) {
            return;
        }
        Object obj = messageSequence.remove(0);
        if (!(obj instanceof Response)) {
            return;
        }
        Response res = (Response) obj;
        try {
            stunStack.sendResponse(evt.getMessage().getTransactionID(), res, serverAddress, evt.getRemoteAddress());
        } catch (Exception ex) {
            logger.warn("Failed to send a response", ex);
        }
    }

    /**
     * Returns a string representation of this Server.
     * 
     * @return the ip address and port where this server is bound
     */
    public String toString() {
        return serverAddress == null ? "null" : serverAddress.toString();
    }

}
