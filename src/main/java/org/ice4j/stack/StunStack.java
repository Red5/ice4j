/* See LICENSE.md for license information */
package org.ice4j.stack;

import java.io.IOException;
import java.lang.Thread.UncaughtExceptionHandler;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

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
import org.ice4j.ice.nio.IceTcpTransport;
import org.ice4j.ice.nio.IceTransport;
import org.ice4j.ice.nio.IceUdpTransport;
import org.ice4j.message.Indication;
import org.ice4j.message.Message;
import org.ice4j.message.MessageFactory;
import org.ice4j.message.Request;
import org.ice4j.message.Response;
import org.ice4j.security.CredentialsManager;
import org.ice4j.security.LongTermCredential;
import org.ice4j.socket.IceSocketWrapper;
import org.ice4j.socket.IceUdpSocketWrapper;
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
     * The Future which expires the StunServerTransactions of this StunStack and removes them from {@link #serverTransactions}.
     */
    private Future<?> serverTransactionExpireFuture;

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

    /**
     * Executor for all threads and tasks needed in this agent.
     */
    private ExecutorService executor = Executors.newCachedThreadPool(new ThreadFactory() {
        public Thread newThread(Runnable r) {
            Thread t = new Thread(r);
            t.setDaemon(true);
            t.setUncaughtExceptionHandler(new UncaughtExceptionHandler() {

                @Override
                public void uncaughtException(Thread t, Throwable e) {
                    logger.warn("Uncaught exception on {}", t.getName(), e);
                }

            });
            return t;
        }
    });

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
        logger.debug("ctor: {}", this);
        // create a new network access manager
        netAccessManager = new NetAccessManager(this);
    }

    /**
     * Creates and starts a Network Access Point (Connector) based on the specified socket and the specified remote address.
     *
     * @param iceSocket the socket wrapper that the new access point should represent
     * @param remoteAddress of the Connector to be created if it is a TCP socket or null if it is UDP
     * @param doBind perform bind on the wrappers local address if true and not if false
     */
    public void addSocket(IceSocketWrapper iceSocket, TransportAddress remoteAddress, boolean doBind) {
        logger.debug("addSocket: {} remote address: {} bind? {}", iceSocket, remoteAddress, doBind);
        // add the wrapper for binding
        if (iceSocket instanceof IceUdpSocketWrapper) {
            IceUdpTransport transport = IceUdpTransport.getInstance(iceSocket.getId());
            if (doBind) {
                transport.registerStackAndSocket(this, iceSocket);
            } else {
                // add directly to the ice handler to prevent any unwanted binding
                IceTransport.getIceHandler().registerStackAndSocket(this, iceSocket);
            }
            // add the socket to the net access manager
            netAccessManager.addSocket(iceSocket, null);
        } else {
            IceTcpTransport transport = IceTcpTransport.getInstance(iceSocket.getId());
            if (doBind) {
                transport.registerStackAndSocket(this, iceSocket);
            } else {
                // add directly to the ice handler to prevent any unwanted binding
                IceTransport.getIceHandler().registerStackAndSocket(this, iceSocket);
            }
            // add the socket to the net access manager
            netAccessManager.addSocket(iceSocket, remoteAddress);
        }
    }

    /**
     * Stops and deletes the connector listening on the specified local address.
     * Note this removes connectors with UDP sockets only, use {@link #removeSocket(org.ice4j.TransportAddress, org.ice4j.TransportAddress)}
     * with the appropriate remote address for TCP.
     *
     * @param id transport / acceptor identifier
     * @param localAddr the local address of the socket to remove
     */
    public void removeSocket(String id, TransportAddress localAddr) {
        logger.debug("removeSocket: {}", localAddr);
        removeSocket(id, localAddr, null);
    }

    /**
     * Stops and deletes the connector listening on the specified local address and remote address.
     *
     * @param id transport / acceptor identifier
     * @param localAddr the local address of the socket to remove
     * @param remoteAddr the remote address of the socket to remove; use null for UDP
     */
    public void removeSocket(String id, TransportAddress localAddr, TransportAddress remoteAddr) {
        logger.debug("removeSocket: {} remote address: {}", localAddr, remoteAddr);
        // clean up server bindings and listener
        IceTransport transport = IceTransport.getInstance(remoteAddr == null ? Transport.UDP : Transport.TCP, id);
        if (transport != null) {
            transport.removeBinding(localAddr);
        }
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
    public NetAccessManager getNetAccessManager() {
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
    //    public void sendChannelData(ChannelData channelData, TransportAddress sendTo, TransportAddress sendThrough) throws StunException {
    //        try {
    //            getNetAccessManager().sendMessage(channelData, sendThrough, sendTo);
    //        } catch (StunException stex) {
    //            throw stex;
    //        } catch (IllegalArgumentException iaex) {
    //            throw new StunException(StunException.ILLEGAL_ARGUMENT, "Failed to send STUN indication: " + channelData, iaex);
    //        } catch (IOException ioex) {
    //            throw new StunException(StunException.NETWORK_ERROR, "Failed to send STUN indication: " + channelData, ioex);
    //        }
    //    }

    /**
     * Sends a specific STUN Indication to a specific destination TransportAddress through a socket registered with this
     * StunStack using a specific TransportAddress.
     *
     * @param indication the STUN Indication to be sent to the specified destination TransportAddress through the socket with
     * the specified TransportAddress
     * @param sendTo the TransportAddress of the destination to which the specified indication is to be sent
     * @param sendThrough the TransportAddress of the socket registered with this StunStack through which the specified
     * indication is to be sent
     * @throws StunException if anything goes wrong while sending the specified indication to the destination sendTo through the socket
     * identified by sendThrough
     */
    public void sendIndication(Indication indication, TransportAddress sendTo, TransportAddress sendThrough) throws StunException {
        logger.debug("sendIndication {} sendTo: {} sendThrough: {}", indication, sendTo, sendThrough);
        if (indication.getTransactionID() == null) {
            indication.setTransactionID(TransactionID.createNewTransactionID().getBytes());
        }
        if (logger.isDebugEnabled()) {
            indication.getAttributes().forEach(attr -> {
                logger.debug("Attribute: {}", attr);
            });
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
     * Sends the specified request through the specified access point, and registers the specified ResponseCollector for later notification.
     * @param  request     the request to send
     * @param  sendTo      the destination address of the request
     * @param  sendThrough the local address to use when sending the request
     * @param  collector   the instance to notify when a response arrives or the transaction timeouts
     * @return the TransactionID of the StunClientTransaction that we used in order to send the request
     * @throws IOException  if an error occurs while sending message bytes through the network socket
     * @throws IllegalArgumentException if the apDescriptor references an access point that had not been installed
     */
    public TransactionID sendRequest(Request request, TransportAddress sendTo, TransportAddress sendThrough, ResponseCollector collector) throws IOException, IllegalArgumentException {
        return sendRequest(request, sendTo, sendThrough, collector, TransactionID.createNewTransactionID());
    }

    /**
     * Sends the specified request through the specified access point, and registers the specified ResponseCollector for later notification.
     * @param  request     the request to send
     * @param  sendTo      the destination address of the request
     * @param  sendThrough the local address to use when sending the request
     * @param  collector   the instance to notify when a response arrives or the transaction timeouts
     * @param transactionID the ID that we'd like the new transaction to use in case the application created it in order to use it for application
     * data correlation
     * @return the TransactionID of the StunClientTransactionthat we used in order to send the request
     * @throws IllegalArgumentException if the apDescriptor references an access point that had not been installed
     * @throws IOException  if an error occurs while sending message bytes through the network socket
     */
    public TransactionID sendRequest(Request request, TransportAddress sendTo, TransportAddress sendThrough, ResponseCollector collector, TransactionID transactionID) throws IllegalArgumentException, IOException {
        return sendRequest(request, sendTo, sendThrough, collector, transactionID, -1, -1, -1);
    }

    /**
     * Sends the specified request through the specified access point, and registers the specified ResponseCollector for later notification.
     * 
     * @param  request     the request to send
     * @param  sendTo      the destination address of the request
     * @param  sendThrough the local address to use when sending the request
     * @param  collector   the instance to notify when a response arrives or the transaction timeouts
     * @param transactionID the ID that we'd like the new transaction to use in case the application created it in order to use it for application
     * data correlation
     * @param originalWaitInterval The number of milliseconds to wait before the first retransmission of the request
     * @param maxWaitInterval The maximum wait interval. Once this interval is reached we should stop doubling its value
     * @param maxRetransmissions Maximum number of retransmissions. Once this number is reached and if no response is received after maxWaitInterval
     * milliseconds the request is considered unanswered
     * @return the TransactionID of the StunClientTransaction that we used in order to send the request
     * @throws IllegalArgumentException if the apDescriptor references an access point that had not been installed
     * @throws IOException  if an error occurs while sending message bytes through the network socket
     */
    public TransactionID sendRequest(Request request, TransportAddress sendTo, TransportAddress sendThrough, ResponseCollector collector, TransactionID transactionID, int originalWaitInterval, int maxWaitInterval, int maxRetransmissions) throws IllegalArgumentException, IOException {
        logger.debug("sendRequest: {} to: {} thru: {}", request, sendTo, sendThrough);
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
     * Sends the specified response message through the specified access point.
     *
     * @param transactionID the id of the transaction to use when sending the response. Actually we are getting kind of redundant here as we already
     * have the id in the response object, but I am bringing out as an extra parameter as the user might otherwise forget to explicitly set it.
     * @param response      the message to send
     * @param sendThrough   the local address to use when sending the message
     * @param sendTo        the destination of the message
     * @throws IOException  if an error occurs while sending message bytes through the network socket.
     * @throws IllegalArgumentException if the apDescriptor references an access point that had not been installed,
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
     * Adds a new MessageEventHandler which is to be notified about STUN indications received at a specific local TransportAddress.
     *
     * @param localAddr the TransportAddress of the local socket for which received STUN indications are to be reported to the specified
     * MessageEventHandler
     * @param indicationListener the MessageEventHandler which is to be registered for notifications about STUN indications received at the
     * specified local TransportAddress
     */
    public void addIndicationListener(TransportAddress localAddr, MessageEventHandler indicationListener) {
        logger.info("addIndicationListener - {} listener: {}", localAddr, indicationListener);
        eventDispatcher.addIndicationListener(localAddr, indicationListener);
    }

    /**
     * Adds a new MessageEventHandler which is to be notified about old indications received at a specific local TransportAddress.
     *
     * @param localAddr the TransportAddress of the local socket for which received STUN indications are to be reported to the specified
     * MessageEventHandler
     * @param indicationListener the MessageEventHandler which is to be registered for notifications about old indications received at the
     * specified local TransportAddress
     */
    public void addOldIndicationListener(TransportAddress localAddr, MessageEventHandler indicationListener) {
        logger.info("addOldIndicationListener - {} listener: {}", localAddr, indicationListener);
        eventDispatcher.addOldIndicationListener(localAddr, indicationListener);
    }

    /**
     * Sets the listener that should be notified when a new Request is received.
     * 
     * @param requestListener the listener interested in incoming requests
     */
    public void addRequestListener(RequestListener requestListener) {
        eventDispatcher.addRequestListener(requestListener);
    }

    /**
     * Removes an existing MessageEventHandler to no longer be notified about STUN indications received at a specific local TransportAddress.
     *
     * @param localAddr the TransportAddress of the local socket for which received STUN indications are to no longer be reported to the
     * specified MessageEventHandler
     * @param indicationListener the MessageEventHandler which is to be unregistered for notifications about STUN indications received at the
     * specified local TransportAddress
     */
    public void removeIndicationListener(TransportAddress localAddr, MessageEventHandler indicationListener) {
        logger.info("removeIndicationListener - {} listener: {}", localAddr, indicationListener);
    }

    /**
     * Removes the specified listener from the local listener list. (If any instances of this listener have been registered for a particular
     * access point, they will not be removed).
     * @param listener the RequestListener listener to unregister
     */
    public void removeRequestListener(RequestListener listener) {
        eventDispatcher.removeRequestListener(listener);
    }

    /**
     * Add a RequestListener for requests coming from a specific NetAccessPoint. The listener will be invoked only when a request event is received on
     * that specific property.
     *
     * @param localAddress The local TransportAddress that we would like to listen on
     * @param listener The ConfigurationChangeListener to be added
     */
    public void addRequestListener(TransportAddress localAddress, RequestListener listener) {
        eventDispatcher.addRequestListener(localAddress, listener);
    }

    /**
     * Removes a client transaction from this providers client transactions list. The method is used by StunClientTransactions themselves
     * when a timeout occurs.
     *
     * @param tran the transaction to remove
     */
    void removeClientTransaction(StunClientTransaction tran) {
        clientTransactions.remove(tran.getTransactionID());
    }

    /**
     * Removes a server transaction from this provider's server transactions list. Method is used by StunServerTransaction-s themselves when they expire.
     * @param tran the transaction to remove
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
        if (msg instanceof Request) {
            logger.trace("Parsing request");
            // skip badly sized requests
            UsernameAttribute ua = (UsernameAttribute) msg.getAttribute(Attribute.Type.USERNAME);
            if (ua != null) {
                if (logger.isTraceEnabled()) {
                    logger.trace("Username: {} length: {} data length: {}", ua.getUsername(), ua.getUsername().length, ua.getDataLength());
                }
                if (ua.getUsername().length != ua.getDataLength()) {
                    logger.warn("Invalid username size, rejecting request");
                    return;
                }
            } else {
                logger.debug("Username was null");
            }
            TransactionID serverTid = ev.getTransactionID();
            logger.debug("Event server transaction id: {}", serverTid.toString());
            StunServerTransaction sTran = getServerTransaction(serverTid);
            if (sTran != null) {
                //logger.warn("Stored server transaction id: {}", sTran.getTransactionID().toString());
                //requests from this transaction have already been seen retransmit the response if there was any
                logger.trace("Found an existing transaction");
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
                logger.trace("Existing transaction not found");
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
            // validate attributes that need validation
            try {
                validateRequestAttributes(ev);
            } catch (Exception exc) {
                // validation failed
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
        } else if (msg instanceof Response) {
            logger.trace("Parsing response");
            TransactionID tid = ev.getTransactionID();
            // skip badly sized requests
            UsernameAttribute ua = (UsernameAttribute) msg.getAttribute(Attribute.Type.USERNAME);
            if (ua != null) {
                if (logger.isTraceEnabled()) {
                    logger.trace("Username: {}", ua.getUsername());
                }
            }
            StunClientTransaction tran = clientTransactions.remove(tid);
            if (tran != null) {
                tran.handleResponse(ev);
            } else {
                //do nothing - just drop the phantom response.
                logger.debug("Dropped response - no matching client tran found for tid {}\nall tids in stock were {}", tid, clientTransactions.keySet());
            }
        } else if (msg instanceof Indication) {
            eventDispatcher.fireMessageEvent(ev);
        }
    }

    /**
     * Returns the {@link CredentialsManager} that this stack is using for verification of {@link MessageIntegrityAttribute}s.
     *
     * @return the CredentialsManager that this stack is using for verification of MessageIntegrityAttributes
     */
    public CredentialsManager getCredentialsManager() {
        return credentialsManager;
    }

    /**
     * Cancels all running transactions and prepares for garbage collection.
     */
    public void shutDown() {
        // remove all listeners
        eventDispatcher.removeAllListeners();
        // clientTransactions
        for (StunClientTransaction tran : clientTransactions.values()) {
            tran.cancel();
        }
        // serverTransactions
        for (StunServerTransaction tran : serverTransactions.values()) {
            tran.expire();
        }
        // cancel the expire job if one exists
        if (serverTransactionExpireFuture != null) {
            serverTransactionExpireFuture.cancel(true);
        }
        // stop the executor
        if (executor != null) {
            try {
                executor.shutdown();
            } catch (Exception e) {
                logger.warn("Exception during shutdown", e);
            } finally {
                executor = null;
            }
        }
        // clear the collections
        clientTransactions.clear();
        serverTransactions.clear();
        netAccessManager.stop();
    }

    /**
     * Executes actions related specific attributes like asserting proper checksums or verifying the validity of user names.
     *
     * @param evt the {@link StunMessageEvent} that contains the {@link Request} that we need to validate.
     *
     * @throws IllegalArgumentException if there's something in the attribute that caused us to discard the whole message (e.g. an
     * invalid checksum or username)
     * @throws StunException if we fail while sending an error response
     * @throws IOException if we fail while sending an error response
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
                throw new IllegalArgumentException("Wrong MESSAGE-INTEGRITY value");
            }
        } else if (messageIntegrityRequired) {
            // no message integrity
            Response error = createCorrespondingErrorResponse(request.getMessageType(), ErrorCodeAttribute.UNAUTHORIZED, "Missing MESSAGE-INTEGRITY.");
            sendResponse(request.getTransactionID(), error, evt.getLocalAddress(), evt.getRemoteAddress());
            throw new IllegalArgumentException("Missing MESSAGE-INTEGRITY");
        }
        //look for unknown attributes.
        List<Attribute> allAttributes = request.getAttributes();
        StringBuilder sBuff = new StringBuilder();
        for (Attribute attr : allAttributes) {
            if (attr instanceof OptionalAttribute && attr.getAttributeType().getType() < Attribute.Type.UNKNOWN_OPTIONAL_ATTRIBUTE.getType()) {
                sBuff.append(attr.getAttributeType());
            }
        }
        if (sBuff.length() > 0) {
            Response error = createCorrespondingErrorResponse(request.getMessageType(), ErrorCodeAttribute.UNKNOWN_ATTRIBUTE, "unknown attribute ", sBuff.toString().toCharArray());
            sendResponse(request.getTransactionID(), error, evt.getLocalAddress(), evt.getRemoteAddress());
            throw new IllegalArgumentException("Unknown attribute(s)");
        }
    }

    /**
     * Recalculates the HMAC-SHA1 signature of the message array so that we could compare it with the value brought by the
     * {@link MessageIntegrityAttribute}.
     *
     * @param msgInt the attribute that we need to validate
     * @param username the user name that the message integrity checksum is supposed to have been built for
     * @param shortTermCredentialMechanism true if msgInt is to be validated as part of the STUN short-term credential mechanism or
     * false for the STUN long-term credential mechanism
     * @param message the message whose SHA1 checksum we'd need to recalculate
     * @return true if msgInt contains a valid SHA1 value and false otherwise
     */
    public boolean validateMessageIntegrity(MessageIntegrityAttribute msgInt, String username, boolean shortTermCredentialMechanism, RawMessage message) {
        if (logger.isTraceEnabled()) {
            logger.trace("validateMessageIntegrity username: {} short term: {}\nMI attr data length: {} hmac content: {}\nRawMessage: {}\n{}", username, shortTermCredentialMechanism, msgInt.getDataLength(), toHexString(msgInt.getHmacSha1Content()), message.getMessageLength(), toHexString(message.getBytes()));
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
        if (logger.isTraceEnabled() && shortTermCredentialMechanism) {
            // no username[1] with long term creds
            logger.trace("Local key: {} remote key: {}", toHexString(key), toHexString(getCredentialsManager().getRemoteKey(usernameParts[1], "media-0")));
        }
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
            char[] hexes = new char[] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
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
        if (executor != null && !serverTransactions.isEmpty() && serverTransactionExpireFuture == null) {
            serverTransactionExpireFuture = submit(new Runnable() {

                // Expires the StunServerTransactions of this StunStack and removes them from {@link #serverTransactions}.
                @Override
                public void run() {
                    Thread.currentThread().setName("StunStack.serverTransactionExpireThread");
                    try {
                        long idleStartTime = -1;
                        do {
                            try {
                                Thread.sleep(StunServerTransaction.LIFETIME);
                            } catch (InterruptedException ie) {
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
                                serverTransactions.values().forEach(serverTransaction -> {
                                    if (serverTransaction == null || serverTransaction.isExpired()) {
                                        serverTransactions.remove(serverTransaction.getTransactionID());
                                    }
                                });
                            }
                        } while (executor != null); // if the executor goes null, the stack has been shutdown
                    } finally {
                        // If serverTransactionExpireThread dies unexpectedly and yet it is still necessary, resurrect it.
                        serverTransactionExpireFuture.cancel(true);
                        try {
                            serverTransactionExpireFuture.get(1L, TimeUnit.SECONDS);
                        } catch (Exception e) {
                            // wait for the future to finish its work
                        } finally {
                            serverTransactionExpireFuture = null;
                            maybeStartServerTransactionExpireThread();
                        }
                    }
                }
            });
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
     * Submit a task to the internal executor.
     * 
     * @param task
     * @return Future
     */
    public Future<?> submit(Runnable task) {
        if (executor != null && !executor.isTerminated()) {
            logger.debug("Submitting task: {}", task);
            return executor.submit(task);
        }
        logger.warn("Submission rejected, executor is terminated");
        return null;
    }

}
