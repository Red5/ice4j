/* See LICENSE.md for license information */
package org.ice4j.stack;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.crypto.Mac;

import org.ice4j.ResponseCollector;
import org.ice4j.StackProperties;
import org.ice4j.StunException;
import org.ice4j.StunMessageEvent;
import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.attribute.Attribute;
import org.ice4j.attribute.ErrorCodeAttribute;
import org.ice4j.attribute.MessageIntegrityAttribute;
import org.ice4j.attribute.OptionalAttribute;
import org.ice4j.attribute.UsernameAttribute;
import org.ice4j.ice.nio.NioServer;
import org.ice4j.message.ChannelData;
import org.ice4j.message.Indication;
import org.ice4j.message.Message;
import org.ice4j.message.MessageFactory;
import org.ice4j.message.Request;
import org.ice4j.message.Response;
import org.ice4j.security.CredentialsManager;
import org.ice4j.security.LongTermCredential;
import org.ice4j.socket.IceSocketWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The entry point to the Stun4J stack. The class is used to start, stop and configure the stack.
 *
 * @author Emil Ivov
 * @author Lyubomir Marinov
 * @author Aakash Garg
 * @author Paul Gregoire
 */
public class StunStack implements MessageEventHandler {

    private static final Logger logger = LoggerFactory.getLogger(StunStack.class);

    /**
     * HMAC_SHA1 instance via <pre>Mac.getInstance(MessageIntegrityAttribute.HMAC_SHA1_ALGORITHM)</pre>
     *
     * @see #StunStack()
     */
    @SuppressWarnings("unused")
    private static Mac mac;

    /**
     * Our network gateway.
     */
    private final NetAccessManager netAccessManager;

    /**
     * The {@link CredentialsManager} that we are using for retrieving passwords.
     */
    private final CredentialsManager credentialsManager = new CredentialsManager();

    /**
     * Stores active client transactions mapped against transaction id's.
     */
    private final ConcurrentMap<TransactionID, StunClientTransaction> clientTransactions = new ConcurrentHashMap<>();

    /**
     * The Thread which expires the StunServerTransactions of this StunStack and removes them from {@link #serverTransactions}.
     */
    private Thread serverTransactionExpireThread;

    /**
     * Currently open server transactions. Contains transaction id's for transactions corresponding to all non-answered received requests.
     */
    private final ConcurrentMap<TransactionID, StunServerTransaction> serverTransactions = new ConcurrentHashMap<>();

    /**
     * A dispatcher for incoming requests event;
     */
    private final EventDispatcher eventDispatcher = new EventDispatcher();

    /**
     * The packet logger instance.
     */
    private static PacketLogger packetLogger;

    // https://docs.oracle.com/javase/8/docs/api/java/net/StandardSocketOptions.html#SO_RCVBUF
    private static int receiveBufferSize = StackProperties.getInt("SO_RCVBUF", 1500);

    // https://docs.oracle.com/javase/8/docs/api/java/net/StandardSocketOptions.html#SO_SNDBUF
    private static int sendBufferSize = StackProperties.getInt("SO_SNDBUF", 1500);

    /**
     * Internal NIO server for SocketChannel and DatagramChannel creation and handling.
     */
    private NioServer server;

    static {
        // The Mac instantiation used in MessageIntegrityAttribute could take several hundred milliseconds so we don't want it instantiated only after
        // we get a response because the delay may cause the transaction to fail.
        try {
            mac = Mac.getInstance(MessageIntegrityAttribute.HMAC_SHA1_ALGORITHM);
        } catch (NoSuchAlgorithmException nsaex) {
            nsaex.printStackTrace();
        }
    }

    public StunStack() {
        // create a new network access manager
        netAccessManager = new NetAccessManager(this);
        // get an instance
        server = NioServer.getInstance();
        if (!server.getState().equals(NioServer.State.STARTED)) {
            logger.debug("Starting Nio server");
            // set input and output buffer sizes
            server.setInputBufferSize(receiveBufferSize);
            //logger.info("Initialized recv buf size: {} of requested: {}", server.getInputBufferSize(), receiveBufferSize);
            server.setOutputBufferSize(sendBufferSize);
            //logger.info("Initialized send buf size: {} of requested: {}", server.getOutputBufferSize(), sendBufferSize);
            server.setPriority(StackProperties.getInt("IO_THREAD_PRIORITY", 6));
            server.setSelectorSleepMs((long) StackProperties.getInt("NIO_SELECTOR_SLEEP_MS", 10));
            server.setBlockingIO(StackProperties.getBoolean("IO_BLOCKING", false));
            server.start();
        }
    }

    /**
     * Creates and starts a Network Access Point (Connector) based on the specified socket.
     *
     * @param wrapper The socket that the new access point should represent.
     */
    public void addSocket(IceSocketWrapper wrapper) {
        addSocket(wrapper, wrapper.getRemoteTransportAddress());
    }

    /**
     * Creates and starts a Network Access Point (Connector) based on the specified socket and the specified remote address.
     *
     * @param wrapper The socket that the new access point should represent.
     * @param remoteAddress the remote address of the socket of the Connector to be created if it is a TCP socket, or null if it
     * is UDP.
     */
    public void addSocket(IceSocketWrapper wrapper, TransportAddress remoteAddress) {
        // add a listener for data events
        server.addNioServerListener(wrapper.getServerListener());
        // get the local address
        TransportAddress localAddress = wrapper.getTransportAddress();
        if (localAddress.getTransport() == Transport.UDP) {
            // attempt to add a binding to the server
            server.addUdpBinding(localAddress);
        } else {
            // attempt to add a binding to the server
            server.addTcpBinding(localAddress);
        }
        if (logger.isTraceEnabled()) {
            logger.trace("Binding added: {}", localAddress);
        }
        // add the socket to the net access manager
        netAccessManager.addSocket(wrapper, remoteAddress);
    }

    /**
     * Stops and deletes the connector listening on the specified local address.
     * Note this removes connectors with UDP sockets only, use {@link #removeSocket(org.ice4j.TransportAddress, org.ice4j.TransportAddress)}
     * with the appropriate remote address for TCP.
     *
     * @param localAddr the local address of the socket to remove.
     */
    public void removeSocket(TransportAddress localAddr) {
        removeSocket(localAddr, null);
    }

    /**
     * Stops and deletes the connector listening on the specified local address and remote address.
     *
     * @param localAddr the local address of the socket to remove.
     * @param remoteAddr the remote address of the socket to remove. Use null for UDP.
     */
    public void removeSocket(TransportAddress localAddr, TransportAddress remoteAddr) {
        // clean up server bindings and listener
        server.removeUdpBinding(localAddr);
        // first cancel all transactions using this address
        cancelTransactionsForAddress(localAddr, remoteAddr);
        netAccessManager.removeSocket(localAddr, remoteAddr);
    }

    /**
     * Returns the transaction with the specified transactionID or null if no such transaction exists.
     *
     * @param transactionID the ID of the transaction we are looking for
     * @return the {@link StunClientTransaction} we are looking for
     */
    protected StunClientTransaction getClientTransaction(TransactionID transactionID) {
        StunClientTransaction clientTransaction = clientTransactions.get(transactionID);
        return clientTransaction;
    }

    /**
     * Returns the transaction with the specified transactionID or null if no such transaction exists.
     *
     * @param transactionID the ID of the transaction we are looking for
     * @return the {@link StunServerTransaction} we are looking for
     */
    protected StunServerTransaction getServerTransaction(TransactionID transactionID) {
        StunServerTransaction serverTransaction = serverTransactions.get(transactionID);
        // If a StunServerTransaction is expired, do not return it. It will be removed from serverTransactions soon.
        if (serverTransaction != null && serverTransaction.isExpired()) {
            serverTransaction = null;
        }
        return serverTransaction;
    }

    /**
     * Cancels the {@link StunClientTransaction} with the specified transactionID. Cancellation means that the stack will not
     * retransmit the request, will not treat the lack of response to be a failure, but will wait the duration of the transaction timeout for a
     * response.
     *
     * @param transactionID the {@link TransactionID} of the {@link StunClientTransaction} to cancel
     */
    public void cancelTransaction(TransactionID transactionID) {
        StunClientTransaction clientTransaction = clientTransactions.get(transactionID);
        if (clientTransaction != null) {
            clientTransaction.cancel();
        }
    }

    /**
     * Stops all transactions for the specified localAddr so that they won't send messages through any longer and so that we could remove the
     * associated socket.
     *
     * @param localAddr the TransportAddress that we'd like to remove transactions for.
     * @param remoteAddr the remote TransportAddress that we'd like to remove transactions for. If null, then it will not be taken
     * into account (that is, all transactions with for localAddr will be cancelled).
     */
    private void cancelTransactionsForAddress(TransportAddress localAddr, TransportAddress remoteAddr) {
        for (StunClientTransaction tran : clientTransactions.values()) {
            if (tran.getLocalAddress().equals(localAddr) && (remoteAddr == null || remoteAddr.equals(tran.getRemoteAddress()))) {
                clientTransactions.remove(tran);
                tran.cancel();
            }
        }
        for (StunServerTransaction tran : serverTransactions.values()) {
            TransportAddress listenAddr = tran.getLocalListeningAddress();
            TransportAddress sendingAddr = tran.getSendingAddress();
            if (listenAddr.equals(localAddr) || (sendingAddr != null && sendingAddr.equals(localAddr))) {
                if (remoteAddr == null || remoteAddr.equals(tran.getRequestSourceAddress())) {
                    serverTransactions.remove(tran);
                    tran.expire();
                }
            }
        }
    }

    /**
     * Returns the currently active instance of NetAccessManager.
     * @return NetAccessManager
     */
    NetAccessManager getNetAccessManager() {
        return netAccessManager;
    }

    /**
     * Sends a specific STUN Indication to a specific destination TransportAddress through a socket registered with this
     * StunStack using a specific TransportAddress.
     *
     * @param channelData the STUN Indication to be sent to the specified destination TransportAddress through the socket with
     * the specified TransportAddress
     * @param sendTo the TransportAddress of the destination to which the specified indication is to be sent
     * @param sendThrough the TransportAddress of the socket registered with this StunStack through which the specified
     * indication is to be sent
     * @throws StunException if anything goes wrong while sending the specified indication to the destination sendTo through the socket
     * identified by sendThrough
     */
    public void sendChannelData(ChannelData channelData, TransportAddress sendTo, TransportAddress sendThrough) throws StunException {
        try {
            getNetAccessManager().sendMessage(channelData, sendThrough, sendTo);
        } catch (StunException stex) {
            throw stex;
        } catch (IllegalArgumentException iaex) {
            throw new StunException(StunException.ILLEGAL_ARGUMENT, "Failed to send STUN indication: " + channelData, iaex);
        } catch (IOException ioex) {
            throw new StunException(StunException.NETWORK_ERROR, "Failed to send STUN indication: " + channelData, ioex);
        }
    }

    /**
     * Sends a specific STUN Indication to a specific destination TransportAddress through a socket registered with this
     * StunStack using a specific TransportAddress.
     *
     * @param udpMessage the RawMessage to be sent to the specified destination TransportAddress through the socket with
     * the specified TransportAddress
     * @param sendTo the TransportAddress of the destination to which the specified indication is to be sent
     * @param sendThrough the TransportAddress of the socket registered with this StunStack through which the specified
     * indication is to be sent
     * @throws StunException if anything goes wrong while sending the specified indication to the destination sendTo through the socket
     * identified by sendThrough
     */
    public void sendUdpMessage(RawMessage udpMessage, TransportAddress sendTo, TransportAddress sendThrough) throws StunException {
        try {
            getNetAccessManager().sendMessage(udpMessage.getBytes(), sendThrough, sendTo);
        } catch (IllegalArgumentException iaex) {
            throw new StunException(StunException.ILLEGAL_ARGUMENT, "Failed to send STUN indication: " + udpMessage, iaex);
        } catch (IOException ioex) {
            throw new StunException(StunException.NETWORK_ERROR, "Failed to send STUN indication: " + udpMessage, ioex);
        }
    }

    /**
     * Receives a specific STUN Indication on a specific destination TransportAddress from a socket registered with this
     * StunStack using a specific TransportAddress.
     *
     * @param message the bytes received
     * @param sentTo the TransportAddress of the destination to which the specified indication was sent
     * @param sendFrom the TransportAddress from which the message was received
     * @throws StunException if anything goes wrong
     */
    public void receiveUdpMessage(byte[] message, TransportAddress sentTo, TransportAddress sendFrom) throws StunException {
        try {
            getNetAccessManager().receiveMessage(message, sentTo, sendFrom);
        } catch (IllegalArgumentException iaex) {
            throw new StunException(StunException.ILLEGAL_ARGUMENT, "Failed to receive STUN indication: " + message, iaex);
        } catch (IOException ioex) {
            throw new StunException(StunException.NETWORK_ERROR, "Failed to receive STUN indication: " + message, ioex);
        }
    }

    /**
     * Sends a specific STUN Indication to a specific destination
     * TransportAddress through a socket registered with this
     * StunStack using a specific TransportAddress.
     *
     * @param indication the STUN Indication to be sent to the
     * specified destination TransportAddress through the socket with
     * the specified TransportAddress
     * @param sendTo the TransportAddress of the destination to which
     * the specified indication is to be sent
     * @param sendThrough the TransportAddress of the socket registered
     * with this StunStack through which the specified
     * indication is to be sent
     * @throws StunException if anything goes wrong while sending the specified
     * indication to the destination sendTo through the socket
     * identified by sendThrough
     */
    public void sendIndication(Indication indication, TransportAddress sendTo, TransportAddress sendThrough) throws StunException {
        if (indication.getTransactionID() == null) {
            indication.setTransactionID(TransactionID.createNewTransactionID().getBytes());
        }
        try {
            getNetAccessManager().sendMessage(indication, sendThrough, sendTo);
        } catch (IllegalArgumentException iaex) {
            throw new StunException(StunException.ILLEGAL_ARGUMENT, "Failed to send STUN indication: " + indication, iaex);
        } catch (IOException ioex) {
            throw new StunException(StunException.NETWORK_ERROR, "Failed to send STUN indication: " + indication, ioex);
        }
    }

    /**
     * Sends the specified request through the specified access point, and
     * registers the specified ResponseCollector for later notification.
     * @param  request     the request to send
     * @param  sendTo      the destination address of the request.
     * @param  sendThrough the local address to use when sending the request
     * @param  collector   the instance to notify when a response arrives or the
     *                     the transaction timeouts
     *
     * @return the TransactionID of the StunClientTransaction
     * that we used in order to send the request.
     *
     * @throws IOException  if an error occurs while sending message bytes
     * through the network socket.
     * @throws IllegalArgumentException if the apDescriptor references an
     * access point that had not been installed,
     */
    public TransactionID sendRequest(Request request, TransportAddress sendTo, TransportAddress sendThrough, ResponseCollector collector) throws IOException, IllegalArgumentException {
        return sendRequest(request, sendTo, sendThrough, collector, TransactionID.createNewTransactionID());
    }

    /**
     * Sends the specified request through the specified access point, and
     * registers the specified ResponseCollector for later notification.
     * @param  request     the request to send
     * @param  sendTo      the destination address of the request.
     * @param  sendThrough the local address to use when sending the request
     * @param  collector   the instance to notify when a response arrives or the
     * the transaction timeouts
     * @param transactionID the ID that we'd like the new transaction to use
     * in case the application created it in order to use it for application
     * data correlation.
     *
     * @return the TransactionID of the StunClientTransaction
     * that we used in order to send the request.
     *
     * @throws IllegalArgumentException if the apDescriptor references an
     * access point that had not been installed,
     * @throws IOException  if an error occurs while sending message bytes
     * through the network socket.
     */
    public TransactionID sendRequest(Request request, TransportAddress sendTo, TransportAddress sendThrough, ResponseCollector collector, TransactionID transactionID) throws IllegalArgumentException, IOException {
        return sendRequest(request, sendTo, sendThrough, collector, transactionID, -1, -1, -1);
    }

    /**
     * Sends the specified request through the specified access point, and
     * registers the specified ResponseCollector for later notification.
     * @param  request     the request to send
     * @param  sendTo      the destination address of the request.
     * @param  sendThrough the local address to use when sending the request
     * @param  collector   the instance to notify when a response arrives or the
     * the transaction timeouts
     * @param transactionID the ID that we'd like the new transaction to use
     * in case the application created it in order to use it for application
     * data correlation.
     * @param originalWaitInterval The number of milliseconds to wait before
     * the first retransmission of the request.
     * @param maxWaitInterval The maximum wait interval. Once this interval is
     * reached we should stop doubling its value.
     * @param maxRetransmissions Maximum number of retransmissions. Once this
     * number is reached and if no response is received after maxWaitInterval
     * milliseconds the request is considered unanswered.
     * @return the TransactionID of the StunClientTransaction
     * that we used in order to send the request.
     *
     * @throws IllegalArgumentException if the apDescriptor references an
     * access point that had not been installed,
     * @throws IOException  if an error occurs while sending message bytes
     * through the network socket.
     */
    public TransactionID sendRequest(Request request, TransportAddress sendTo, TransportAddress sendThrough, ResponseCollector collector, TransactionID transactionID, int originalWaitInterval, int maxWaitInterval, int maxRetransmissions) throws IllegalArgumentException, IOException {
        StunClientTransaction clientTransaction = new StunClientTransaction(this, request, sendTo, sendThrough, collector, transactionID);
        if (originalWaitInterval > 0) {
            clientTransaction.originalWaitInterval = originalWaitInterval;
        }
        if (maxWaitInterval > 0) {
            clientTransaction.maxWaitInterval = maxWaitInterval;
        }
        if (maxRetransmissions >= 0) {
            clientTransaction.maxRetransmissions = maxRetransmissions;
        }
        clientTransactions.put(clientTransaction.getTransactionID(), clientTransaction);
        clientTransaction.sendRequest();
        return clientTransaction.getTransactionID();
    }

    /**
     * Sends the specified request through the specified access point, and
     * registers the specified ResponseCollector for later notification.
     * @param  request     the request to send
     * @param  sendTo      the destination address of the request.
     * @param  sendThrough the socket that we should send the request through.
     * @param  collector   the instance to notify when a response arrives or the
     *                     the transaction timeouts
     *
     * @return the TransactionID of the StunClientTransaction
     * that we used in order to send the request.
     *
     * @throws IOException  if an error occurs while sending message bytes
     * through the network socket.
     * @throws IllegalArgumentException if the apDescriptor references an
     * access point that had not been installed,
     */
    public TransactionID sendRequest(Request request, TransportAddress sendTo, DatagramSocket sendThrough, ResponseCollector collector) throws IOException, IllegalArgumentException {
        TransportAddress sendThroughAddr = new TransportAddress(sendThrough.getLocalAddress(), sendThrough.getLocalPort(), Transport.UDP);
        return sendRequest(request, sendTo, sendThroughAddr, collector);
    }

    /**
     * Sends the specified response message through the specified access point.
     *
     * @param transactionID the id of the transaction to use when sending the
     * response. Actually we are getting kind of redundant here as we already
     * have the id in the response object, but I am bringing out as an extra
     * parameter as the user might otherwise forget to explicitly set it.
     * @param response      the message to send.
     * @param sendThrough   the local address to use when sending the message.
     * @param sendTo        the destination of the message.
     *
     * @throws IOException  if an error occurs while sending message bytes
     * through the network socket.
     * @throws IllegalArgumentException if the apDescriptor references an
     * access point that had not been installed,
     * @throws StunException if message encoding fails
     */
    public void sendResponse(byte[] transactionID, Response response, TransportAddress sendThrough, TransportAddress sendTo) throws StunException, IOException, IllegalArgumentException {
        TransactionID tid = TransactionID.createTransactionID(this, transactionID);
        StunServerTransaction sTran = getServerTransaction(tid);
        if (sTran == null) {
            throw new StunException(StunException.TRANSACTION_DOES_NOT_EXIST, "The transaction specified in the response (tid=" + tid.toString() + ") object does not exist.");
        } else if (sTran.isRetransmitting()) {
            throw new StunException(StunException.TRANSACTION_ALREADY_ANSWERED, "The transaction specified in the response (tid=" + tid.toString() + ") has already seen a previous response. Response was:\n" + sTran.getResponse());
        } else {
            sTran.sendResponse(response, sendThrough, sendTo);
        }
    }

    /**
     * Adds a new MessageEventHandler which is to be notified about
     * STUN indications received at a specific local TransportAddress.
     *
     * @param localAddr the TransportAddress of the local socket for
     * which received STUN indications are to be reported to the specified
     * MessageEventHandler
     * @param indicationListener the MessageEventHandler which is to be
     * registered for notifications about STUN indications received at the
     * specified local TransportAddress
     */
    public void addIndicationListener(TransportAddress localAddr, MessageEventHandler indicationListener) {
        eventDispatcher.addIndicationListener(localAddr, indicationListener);
    }

    /**
     * Adds a new MessageEventHandler which is to be notified about
     * old indications received at a specific local TransportAddress.
     *
     * @param localAddr the TransportAddress of the local socket for
     * which received STUN indications are to be reported to the specified
     * MessageEventHandler
     * @param indicationListener the MessageEventHandler which is to be
     * registered for notifications about old indications received at the
     * specified local TransportAddress
     */
    public void addOldIndicationListener(TransportAddress localAddr, MessageEventHandler indicationListener) {
        eventDispatcher.addOldIndicationListener(localAddr, indicationListener);
    }

    /**
     * Sets the listener that should be notified when a new Request is received.
     * @param requestListener the listener interested in incoming requests.
     */
    public void addRequestListener(RequestListener requestListener) {
        eventDispatcher.addRequestListener(requestListener);
    }

    /**
     * Removes an existing MessageEventHandler to no longer be notified
     * about STUN indications received at a specific local
     * TransportAddress.
     *
     * @param localAddr the TransportAddress of the local socket for
     * which received STUN indications are to no longer be reported to the
     * specified MessageEventHandler
     * @param indicationListener the MessageEventHandler which is to be
     * unregistered for notifications about STUN indications received at the
     * specified local TransportAddress
     */
    public void removeIndicationListener(TransportAddress localAddr, MessageEventHandler indicationListener) {
    }

    /**
     * Removes the specified listener from the local listener list. (If any
     * instances of this listener have been registered for a particular
     * access point, they will not be removed).
     * @param listener the RequestListener listener to unregister
     */
    public void removeRequestListener(RequestListener listener) {
        eventDispatcher.removeRequestListener(listener);
    }

    /**
     * Add a RequestListener for requests coming from a specific NetAccessPoint.
     * The listener will be invoked only when a request event is received on
     * that specific property.
     *
     * @param localAddress The local TransportAddress that we would
     * like to listen on.
     * @param listener The ConfigurationChangeListener to be added
     */
    public void addRequestListener(TransportAddress localAddress, RequestListener listener) {
        eventDispatcher.addRequestListener(localAddress, listener);
    }

    /**
     * Removes a client transaction from this providers client transactions
     * list. The method is used by StunClientTransactions themselves
     * when a timeout occurs.
     *
     * @param tran the transaction to remove.
     */
    void removeClientTransaction(StunClientTransaction tran) {
        clientTransactions.remove(tran.getTransactionID());
    }

    /**
     * Removes a server transaction from this provider's server transactions
     * list.
     * Method is used by StunServerTransaction-s themselves when they expire.
     * @param tran the transaction to remove.
     */
    void removeServerTransaction(StunServerTransaction tran) {
        serverTransactions.remove(tran.getTransactionID());
    }

    /**
     * Called to notify this provider for an incoming message.
     *
     * @param ev the event object that contains the new message.
     */
    @Override
    public void handleMessageEvent(StunMessageEvent ev) {
        Message msg = ev.getMessage();
        if (logger.isTraceEnabled()) {
            logger.trace("Received a message on {} of type: {}", ev.getLocalAddress(), msg.getName());
        }
        //request
        if (msg instanceof Request) {
            logger.trace("parsing request");
            // skip badly sized requests
            UsernameAttribute ua = (UsernameAttribute) msg.getAttribute(Attribute.Type.USERNAME);
            if (ua != null) {
                logger.debug("Username length: {} data length: {}", ua.getUsername().length, ua.getDataLength());
                if (ua.getUsername().length != ua.getDataLength()) {
                    logger.warn("Invalid username size, rejecting request");
                    return;
                }
                logger.debug("Username: {}", ua.getUsername());
            } else {
                logger.debug("Username was null");
            }
            TransactionID serverTid = ev.getTransactionID();
            logger.debug("Event server transaction id: {} rfc3489: {}", serverTid.toString(), serverTid.isRFC3489Compatible());
            StunServerTransaction sTran = getServerTransaction(serverTid);
            if (sTran != null) {
                //logger.warn("Stored server transaction id: {}", sTran.getTransactionID().toString());
                //requests from this transaction have already been seen retransmit the response if there was any
                logger.trace("found an existing transaction");
                try {
                    sTran.retransmitResponse();
                    logger.trace("Response retransmitted");
                } catch (Exception ex) {
                    //we couldn't really do anything here .. apart from logging
                    logger.warn("Failed to retransmit a stun response", ex);
                }
                if (!StackProperties.getBoolean(StackProperties.PROPAGATE_RECEIVED_RETRANSMISSIONS, false)) {
                    return;
                }
            } else {
                logger.trace("existing transaction not found");
                sTran = new StunServerTransaction(this, serverTid, ev.getLocalAddress(), ev.getRemoteAddress());
                // if there is an OOM error here, it will lead to NetAccessManager.handleFatalError that will stop the
                // MessageProcessor thread and restart it that will lead again to an OOM error and so on... So stop here right now
                try {
                    sTran.start();
                } catch (OutOfMemoryError t) {
                    logger.warn("STUN transaction thread start failed", t);
                    return;
                }
                serverTransactions.put(serverTid, sTran);
                maybeStartServerTransactionExpireThread();
            }
            // validate attributes that need validation.
            try {
                validateRequestAttributes(ev);
            } catch (Exception exc) {
                // validation failed. log get lost.
                logger.warn("Failed to validate msg: {}", ev, exc);
                // remove failed transaction to account for Edge
                removeServerTransaction(sTran);
                return;
            }
            try {
                eventDispatcher.fireMessageEvent(ev);
            } catch (Throwable t) {
                logger.warn("Received an invalid request", t);
                Throwable cause = t.getCause();
                if (((t instanceof StunException) && ((StunException) t).getID() == StunException.TRANSACTION_ALREADY_ANSWERED) || ((cause instanceof StunException) && ((StunException) cause).getID() == StunException.TRANSACTION_ALREADY_ANSWERED)) {
                    // do not try to send an error response since we will
                    // get another TRANSACTION_ALREADY_ANSWERED
                    return;
                }
                Response error;
                if (t instanceof IllegalArgumentException) {
                    error = createCorrespondingErrorResponse(msg.getMessageType(), ErrorCodeAttribute.BAD_REQUEST, t.getMessage());
                } else {
                    error = createCorrespondingErrorResponse(msg.getMessageType(), ErrorCodeAttribute.SERVER_ERROR, "Oops! Something went wrong on our side :(");
                }
                try {
                    sendResponse(serverTid.getBytes(), error, ev.getLocalAddress(), ev.getRemoteAddress());
                } catch (Exception exc) {
                    logger.warn("Couldn't send a server error response", exc);
                }
            }
        }
        //response
        else if (msg instanceof Response) {
            logger.trace("parsing response");
            TransactionID tid = ev.getTransactionID();
            // skip badly sized requests
            UsernameAttribute ua = (UsernameAttribute) msg.getAttribute(Attribute.Type.USERNAME);
            if (ua != null) {
                logger.debug("Username: {}", ua.getUsername());
            }
            StunClientTransaction tran = clientTransactions.remove(tid);
            if (tran != null) {
                tran.handleResponse(ev);
            } else {
                //do nothing - just drop the phantom response.
                logger.debug("Dropped response - no matching client tran found for tid " + tid + "\nall tids in stock were " + clientTransactions.keySet());
            }
        }
        // indication
        else if (msg instanceof Indication) {
            eventDispatcher.fireMessageEvent(ev);
        }
    }

    /**
     * Returns the {@link CredentialsManager} that this stack is using for
     * verification of {@link MessageIntegrityAttribute}s.
     *
     * @return the {@link CredentialsManager} that this stack is using for
     * verification of {@link MessageIntegrityAttribute}s.
     */
    public CredentialsManager getCredentialsManager() {
        return credentialsManager;
    }

    /**
     * Cancels all running transactions and prepares for garbage collection
     */
    public void shutDown() {
        // remove all listeners
        eventDispatcher.removeAllListeners();
        // clientTransactions
        for (StunClientTransaction tran : clientTransactions.values()) {
            tran.cancel();
        }
        clientTransactions.clear();
        // serverTransactions
        for (StunServerTransaction tran : serverTransactions.values()) {
            tran.expire();
        }
        serverTransactions.clear();
        netAccessManager.stop();
        // don't stop the NIO server unless we are NOT in shared mode
        if (!NioServer.isShared()) {
            // stop the NIO server
            server.stop();
        }
    }

    /**
     * Executes actions related specific attributes like asserting proper
     * checksums or verifying the validity of user names.
     *
     * @param evt the {@link StunMessageEvent} that contains the {@link
     * Request} that we need to validate.
     *
     * @throws IllegalArgumentException if there's something in the
     * attribute that caused us to discard the whole message (e.g. an
     * invalid checksum
     * or username)
     * @throws StunException if we fail while sending an error response.
     * @throws IOException if we fail while sending an error response.
     */
    private void validateRequestAttributes(StunMessageEvent evt) throws IllegalArgumentException, StunException, IOException {
        Message request = evt.getMessage();

        //assert valid username
        UsernameAttribute unameAttr = (UsernameAttribute) request.getAttribute(Attribute.Type.USERNAME);
        String username = null;

        if (unameAttr != null) {
            username = LongTermCredential.toString(unameAttr.getUsername());
            if (!validateUsername(username)) {
                Response error = createCorrespondingErrorResponse(request.getMessageType(), ErrorCodeAttribute.UNAUTHORIZED, "unknown user " + username);

                sendResponse(request.getTransactionID(), error, evt.getLocalAddress(), evt.getRemoteAddress());

                throw new IllegalArgumentException("Non-recognized username: " + username);
            }
        }
        boolean messageIntegrityRequired = StackProperties.getBoolean(StackProperties.REQUIRE_MESSAGE_INTEGRITY, false);
        //assert Message Integrity
        MessageIntegrityAttribute msgIntAttr = (MessageIntegrityAttribute) request.getAttribute(Attribute.Type.MESSAGE_INTEGRITY);

        if (msgIntAttr != null) {
            //we should complain if we have msg integrity and no username.
            if (unameAttr == null) {
                Response error = createCorrespondingErrorResponse(request.getMessageType(), ErrorCodeAttribute.BAD_REQUEST, "missing username");

                sendResponse(request.getTransactionID(), error, evt.getLocalAddress(), evt.getRemoteAddress());

                throw new IllegalArgumentException("Missing USERNAME in the presence of MESSAGE-INTEGRITY: ");
            }
            if (!validateMessageIntegrity(msgIntAttr, username, true, evt.getRawMessage())) {
                Response error = createCorrespondingErrorResponse(request.getMessageType(), ErrorCodeAttribute.UNAUTHORIZED, "Wrong MESSAGE-INTEGRITY value");

                sendResponse(request.getTransactionID(), error, evt.getLocalAddress(), evt.getRemoteAddress());

                throw new IllegalArgumentException("Wrong MESSAGE-INTEGRITY value.");
            }
        } else if (messageIntegrityRequired) {
            // no message integrity
            Response error = createCorrespondingErrorResponse(request.getMessageType(), ErrorCodeAttribute.UNAUTHORIZED, "Missing MESSAGE-INTEGRITY.");

            sendResponse(request.getTransactionID(), error, evt.getLocalAddress(), evt.getRemoteAddress());
            throw new IllegalArgumentException("Missing MESSAGE-INTEGRITY.");
        }

        //look for unknown attributes.
        List<Attribute> allAttributes = request.getAttributes();
        StringBuilder sBuff = new StringBuilder();
        for (Attribute attr : allAttributes) {
            if (attr instanceof OptionalAttribute && attr.getAttributeType().getType() < Attribute.Type.UNKNOWN_OPTIONAL_ATTRIBUTE.getType())
                sBuff.append(attr.getAttributeType());
        }

        if (sBuff.length() > 0) {
            Response error = createCorrespondingErrorResponse(request.getMessageType(), ErrorCodeAttribute.UNKNOWN_ATTRIBUTE, "unknown attribute ", sBuff.toString().toCharArray());

            sendResponse(request.getTransactionID(), error, evt.getLocalAddress(), evt.getRemoteAddress());

            throw new IllegalArgumentException("Unknown attribute(s).");
        }
    }

    /**
     * Recalculates the HMAC-SHA1 signature of the message array so that we could compare it with the value brought by the
     * {@link MessageIntegrityAttribute}.
     *
     * @param msgInt the attribute that we need to validate.
     * @param username the user name that the message integrity checksum is supposed to have been built for.
     * @param shortTermCredentialMechanism true if msgInt is to be validated as part of the STUN short-term credential mechanism or
     * false for the STUN long-term credential mechanism
     * @param message the message whose SHA1 checksum we'd need to recalculate.
     * @return true if msgInt contains a valid SHA1 value and false otherwise.
     */
    public boolean validateMessageIntegrity(MessageIntegrityAttribute msgInt, String username, boolean shortTermCredentialMechanism, RawMessage message) {
        if (logger.isDebugEnabled()) {
            logger.debug("validateMessageIntegrity username: {} short term: {}\nMI attr data length: {} hmac content: {}", username, shortTermCredentialMechanism, msgInt.getDataLength(), toHexString(msgInt.getHmacSha1Content()));
            logger.debug("RawMessage: {}\n{}", message.getMessageLength(), toHexString(message.getBytes()));
        }
        if ((username == null) || (username.length() < 1) || (shortTermCredentialMechanism && !username.contains(":"))) {
            logger.debug("Received a message with an improperly formatted username");
            return false;
        }
        String[] usernameParts = username.split(":");
        if (shortTermCredentialMechanism) {
            username = usernameParts[0]; // lfrag
        }

        byte[] key = getCredentialsManager().getLocalKey(username);
        if (key == null) {
            logger.warn("Local key was not found for {}", username);
            return false;
        }
        logger.debug("Local key: {} remote key: {}", toHexString(key), toHexString(getCredentialsManager().getRemoteKey(usernameParts[1], "media-0")));

        /*
         * Now check whether the SHA1 matches. Using MessageIntegrityAttribute.calculateHmacSha1 on the bytes of the RawMessage will be incorrect if there are other Attributes
         * after the MessageIntegrityAttribute because the value of the MessageIntegrityAttribute is calculated on a STUN "Message Length" up to and including the MESSAGE-INTEGRITY
         * and excluding any Attributes after it.
         */
        byte[] binMsg = new byte[msgInt.getLocationInMessage()];

        System.arraycopy(message.getBytes(), 0, binMsg, 0, binMsg.length);

        int messageLength = (binMsg.length + Attribute.HEADER_LENGTH + msgInt.getDataLength() - Message.HEADER_LENGTH);

        binMsg[2] = (byte) (messageLength >> 8);
        binMsg[3] = (byte) (messageLength & 0xFF);

        byte[] expectedMsgIntHmacSha1Content;
        try {
            expectedMsgIntHmacSha1Content = MessageIntegrityAttribute.calculateHmacSha1(binMsg, 0, binMsg.length, key);
        } catch (IllegalArgumentException iaex) {
            expectedMsgIntHmacSha1Content = null;
        }

        byte[] msgIntHmacSha1Content = msgInt.getHmacSha1Content();

        if (!Arrays.equals(expectedMsgIntHmacSha1Content, msgIntHmacSha1Content)) {
            logger.warn("Received a message with a wrong MESSAGE-INTEGRITY signature expected:\n{}\nreceived:\n{}", toHexString(expectedMsgIntHmacSha1Content), toHexString(msgIntHmacSha1Content));
            return false;
        }
        logger.trace("Successfully verified msg integrity");
        return true;
    }

    /**
     * Returns a String representation of a specific byte array as an unsigned integer in base 16.
     *
     * @param bytes the byte to get the String representation of as an unsigned integer in base 16
     * @return a String representation of the specified byte array as an unsigned integer in base 16
     */
    public static String toHexString(byte[] bytes) {
        if (bytes == null) {
            return null;
        } else {
            StringBuilder hexStringBuilder = new StringBuilder(2 * bytes.length);
            char[] hexes = new char[] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
            for (int i = 0; i < bytes.length; i++) {
                byte b = bytes[i];
                hexStringBuilder.append(hexes[(b & 0xF0) >> 4]);
                hexStringBuilder.append(hexes[b & 0x0F]);
            }
            return hexStringBuilder.toString();
        }
    }

    /**
     * Asserts the validity of a specific username (e.g. which we've received in a USERNAME attribute).
     *
     * @param username the username to be validated
     * @return true if username contains a valid username; false, otherwise
     */
    private boolean validateUsername(String username) {
        int colon = username.indexOf(":");
        if ((username.length() < 1) || (colon < 1)) {
            if (logger.isDebugEnabled()) {
                logger.debug("Received a message with an improperly formatted username");
            }
            return false;
        }
        String lfrag = username.substring(0, colon);
        return getCredentialsManager().checkLocalUserName(lfrag);
    }

    /**
     * Returns the currently set packet logger.
     * @return the currently available packet logger.
     */
    public static PacketLogger getPacketLogger() {
        return packetLogger;
    }

    /**
     * Setting a packet logger for the stack.
     * @param packetLogger the packet logger to use.
     */
    public static void setPacketLogger(PacketLogger packetLogger) {
        StunStack.packetLogger = packetLogger;
    }

    /**
     * Checks whether packet logger is set and enabled.
     * @return true if we have a packet logger instance and it is enabled.
     */
    public static boolean isPacketLoggerEnabled() {
        return packetLogger != null && packetLogger.isEnabled();
    }

    /**
     * Initializes and starts {@link #serverTransactionExpireThread} if necessary.
     */
    private void maybeStartServerTransactionExpireThread() {
        if (!serverTransactions.isEmpty() && serverTransactionExpireThread == null) {
            Thread t = new Thread() {
                @Override
                public void run() {
                    runInServerTransactionExpireThread();
                }
            };
            t.setDaemon(true);
            t.setName(getClass().getName() + ".serverTransactionExpireThread");
            boolean started = false;
            serverTransactionExpireThread = t;
            try {
                t.start();
                started = true;
            } finally {
                if (!started && (serverTransactionExpireThread == t)) {
                    serverTransactionExpireThread = null;
                }
            }
        }
    }

    /**
     * Runs in {@link #serverTransactionExpireThread} and expires the
     * StunServerTransactions of this StunStack and removes
     * them from {@link #serverTransactions}.
     */
    private void runInServerTransactionExpireThread() {
        try {
            long idleStartTime = -1;
            do {
                try {
                    Thread.sleep(StunServerTransaction.LIFETIME);
                } catch (InterruptedException ie) {
                }
                // Is the current Thread still designated to expire the StunServerTransactions of this StunStack?
                if (Thread.currentThread() != serverTransactionExpireThread) {
                    break;
                }
                long now = System.currentTimeMillis();
                // Has the current Thread been idle long enough to merit disposing of it?
                if (serverTransactions.isEmpty()) {
                    if (idleStartTime == -1) {
                        idleStartTime = now;
                    } else if (now - idleStartTime > 60 * 1000) {
                        break;
                    }
                } else {
                    // Expire the StunServerTransactions of this StunStack.
                    idleStartTime = -1;
                    for (Iterator<StunServerTransaction> i = serverTransactions.values().iterator(); i.hasNext();) {
                        StunServerTransaction serverTransaction = i.next();
                        if (serverTransaction == null) {
                            i.remove();
                        } else if (serverTransaction.isExpired(now)) {
                            i.remove();
                            serverTransaction.expire();
                        }
                    }
                }
            } while (true);
        } finally {
            if (serverTransactionExpireThread == Thread.currentThread()) {
                serverTransactionExpireThread = null;
            }
            // If serverTransactionExpireThread dies unexpectedly and yet it is still necessary, resurrect it.
            if (serverTransactionExpireThread == null) {
                maybeStartServerTransactionExpireThread();
            }
        }
    }

    /**
     * Returns the Error Response object with specified errorCode and reasonPhrase corresponding to input type.
     * 
     * @param requestType the message type of Request
     * @param errorCode the errorCode for Error Response object
     * @param reasonPhrase the reasonPhrase for the Error Response object
     * @param unknownAttributes char[] array containing the ids of one or more attributes that had not been recognized
     * @return corresponding Error Response object
     */
    public Response createCorrespondingErrorResponse(char requestType, char errorCode, String reasonPhrase, char... unknownAttributes) {
        if (requestType == Message.BINDING_REQUEST) {
            if (unknownAttributes != null) {
                return MessageFactory.createBindingErrorResponse(errorCode, reasonPhrase, unknownAttributes);
            } else {
                return MessageFactory.createBindingErrorResponse(errorCode, reasonPhrase);
            }
        } else {
            return null;
        }
    }

    /**
     * Logs a specific DatagramPacket using the packet logger of the StunStack.
     *
     * @param p The DatagramPacket to log
     * @param isSent true if the packet is sent, or false if the packet is received
     * @param interfaceAddress The InetAddress to use as source (if the packet was sent) or destination (if the packet was received)
     * @param interfacePort The port to use as source (if the packet was sent) or destination (if the packet was received)
     */
    public static void logPacketToPcap(DatagramPacket p, boolean isSent, InetAddress interfaceAddress, int interfacePort) {
        if (interfaceAddress != null && isPacketLoggerEnabled()) {
            InetAddress[] addr = { interfaceAddress, p.getAddress() };
            int[] port = { interfacePort, p.getPort() };
            int fromIndex = isSent ? 0 : 1;
            int toIndex = isSent ? 1 : 0;
            getPacketLogger().logPacket(addr[fromIndex].getAddress(), port[fromIndex], addr[toIndex].getAddress(), port[toIndex], p.getData(), isSent);
        }
    }

    /**
     * Returns the internal NioServer reference for this StunStack instance.
     * 
     * @return
     */
    NioServer getNioServer() {
        return server;
    }

}
