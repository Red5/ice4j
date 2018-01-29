/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal. Copyright @ 2015 Atlassian Pty Ltd Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or
 * agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under the License.
 */
package org.ice4j.stack;

import java.io.IOException;
import java.nio.channels.DatagramChannel;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;

import org.ice4j.StunException;
import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.message.ChannelData;
import org.ice4j.message.Message;
import org.ice4j.socket.IceSocketWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages Connectors and MessageProcessor pooling. This class serves as a layer that masks network primitives and provides equivalent STUN
 * abstractions. Instances that operate with the NetAccessManager are only supposed to understand STUN talk and shouldn't be aware of datagrams sockets, etc.
 * 
 * @author Emil Ivov
 * @author Aakash Garg
 * @author Boris Grozev
 */
class NetAccessManager implements ErrorHandler {
    /**
     * Our class logger
     */
    private static final Logger logger = LoggerFactory.getLogger(NetAccessManager.class);

    /**
     * All Connectors currently in use with UDP. The table maps a local TransportAddress and and a remote TransportAddress to
     * a Connector. We allow a Connector to be added without a specified remote address, under the null key.
     *
     * Due to the final hashCode() method of InetSocketAddress, TransportAddress cannot override and it causes problem to store both UDP and TCP address
     * (i.e. 192.168.0.3:5000/tcp has the same hashcode as 192.168.0.3:5000/udp because InetSocketAddress does not take into account transport).
     */
    private final ConcurrentMap<TransportAddress, Map<TransportAddress, Connector>> udpConnectors = new ConcurrentHashMap<>();

    /**
     * All Connectors currently in use with TCP. The table maps a local TransportAddress and and a remote TransportAddress to
     * a Connector. We allow a Connector to be added without a specified remote address, under the null key.
     *
     * Due to the final hashCode() method of InetSocketAddress, TransportAddress cannot override and it causes problem to store both UDP and TCP address
     * (i.e. 192.168.0.3:5000/tcp has the same hashcode as 192.168.0.3:5000/udp because InetSocketAddress does not take into account transport).
     */
    private final ConcurrentMap<TransportAddress, Map<TransportAddress, Connector>> tcpConnectors = new ConcurrentHashMap<>();

    /**
     * A synchronized FIFO where incoming messages are stocked for processing.
     */
    private final BlockingQueue<RawMessage> messageQueue = new LinkedBlockingQueue<>();

    /**
     * A thread executor for message processors.
     */
    private final ExecutorService executor = Executors.newCachedThreadPool();

    /**
     * The instance that should be notified when an incoming message has been processed and ready for delivery
     */
    private final MessageEventHandler messageEventHandler;

    /**
     * The instance that should be notified when an incoming UDP message has been processed and ready for delivery
     */
    private final PeerUdpMessageEventHandler peerUdpMessageEventHandler;

    /**
     * The instance that should be notified when an incoming ChannelData message has been processed and ready for delivery
     */
    private final ChannelDataEventHandler channelDataEventHandler;

    /**
     * The StunStack which has created this instance, is its owner and is the handler that incoming message requests should be passed to.
     */
    private final StunStack stunStack;

    /**
     * Constructs a NetAccessManager.
     *
     * @param stunStack the StunStack which is creating the new instance, is going to be its owner and is the handler that incoming
     * message requests should be passed to
     */
    NetAccessManager(StunStack stunStack) {
        this(stunStack, null, null);
    }

    /**
     * Constructs a NetAccessManager with given peerUdpMessageEventHandler and channelDataEventHandler.
     * 
     * @param stunStack the StunStack which is creating the new
     *            instance, is going to be its owner and is the handler that
     *            incoming message requests should be passed to
     * @param peerUdpMessageEventHandler the PeerUdpMessageEventHandler
     *            that will handle incoming UDP messages which are not STUN
     *            messages and ChannelData messages.
     * @param channelDataEventHandler the ChannelDataEventHandler that
     *            will handle incoming UDP messages which are ChannelData
     *            messages.
     */
    NetAccessManager(StunStack stunStack, PeerUdpMessageEventHandler peerUdpMessageEventHandler, ChannelDataEventHandler channelDataEventHandler) {
        this.stunStack = stunStack;
        this.messageEventHandler = stunStack;
        this.peerUdpMessageEventHandler = peerUdpMessageEventHandler;
        this.channelDataEventHandler = channelDataEventHandler;
        // start off with 3 message processors
        for (int i = 0; i < 3; i++) {
            executor.submit(new MessageProcessor(this));
        }
    }

    /**
     * Gets the MessageEventHandler of this NetAccessManager
     * which is to be notified when incoming messages have been processed and
     * are ready for delivery.
     *
     * @return the MessageEventHandler of this
     * NetAccessManager which is to be notified when incoming messages
     * have been processed and are ready for delivery
     */
    MessageEventHandler getMessageEventHandler() {
        return messageEventHandler;
    }

    /**
     * Gets the PeerUdpMessageEventHandler of this
     * NetAccessManager which is to be notified when incoming UDP
     * messages have been processed and are ready for delivery.
     * 
     * @return the PeerUdpMessageEventHandler of this
     *         NetAccessManager which is to be notified when incoming
     *         UDP messages have been processed and are ready for delivery
     */
    public PeerUdpMessageEventHandler getUdpMessageEventHandler() {
        return peerUdpMessageEventHandler;
    }

    /**
     * Gets the ChannelDataEventHandler of this
     * NetAccessManager which is to be notified when incoming
     * ChannelData messages have been processed and are ready for delivery.
     * 
     * @return the ChannelDataEventHandler of this
     *         NetAccessManager which is to be notified when incoming
     *         ChannelData messages have been processed and are ready for
     *         delivery
     */
    public ChannelDataEventHandler getChannelDataMessageEventHandler() {
        return channelDataEventHandler;
    }

    /**
     * Gets the BlockingQueue of this NetAccessManager in which
     * incoming messages are stocked for processing.
     *
     * @return the BlockingQueue of this NetAccessManager in
     * which incoming messages are stocked for processing
     */
    BlockingQueue<RawMessage> getMessageQueue() {
        return messageQueue;
    }

    /**
     * Gets the StunStack which has created this instance and is its
     * owner.
     *
     * @return the StunStack which has created this instance and is its
     * owner
     */
    StunStack getStunStack() {
        return stunStack;
    }

    /**
     * A civilized way of not caring!
     * @param message a description of the error
     * @param error   the error that has occurred
     */
    @Override
    public void handleError(String message, Throwable error) {
        /**
         * apart from logging, i am not sure what else we could do here.
         */
        logger.warn("The following error occurred with an incoming message: {}", message, error);
    }

    /**
     * Clears the faulty thread and reports the problem.
     *
     * @param callingThread the thread where the error occurred.
     * @param message       A description of the error
     * @param error         The error itself
     */
    @Override
    public void handleFatalError(Runnable callingThread, String message, Throwable error) {
        if (callingThread instanceof Connector) {
            Connector connector = (Connector) callingThread;
            //make sure nothing's left and notify user
            removeSocket(connector.getListenAddress(), connector.getRemoteAddress());
            if (error != null) {
                logger.warn("Removing connector: {}", connector, error);
            } else if (logger.isDebugEnabled()) {
                logger.debug("Removing connector {}", connector);
            }
        } else if (callingThread instanceof MessageProcessor) {
            MessageProcessor mp = (MessageProcessor) callingThread;
            logger.warn("A message processor has unexpectedly stopped. AP: {}", mp, error);
            //make sure the guy's dead.
            mp.stop();
            // create a new message processor
            mp = new MessageProcessor(this);
            Future<?> future = executor.submit(mp);
            mp.setFutureRef(future);
            logger.debug("A message processor has been relaunched because of an error");
        }
    }

    /**
     * Creates and starts a new access point based on the specified socket.
     * If the specified access point has already been installed the method
     * has no effect.
     *
     * @param  socket   the socket that the access point should use.
     */
    protected void addSocket(IceSocketWrapper socket) {
        //no null check - let it through as a NullPointerException
        // In case of TCP we can extract the remote address from the actual Socket.
        TransportAddress remoteAddress = socket.getTransportAddress();
        addSocket(socket, remoteAddress);
    }

    /**
     * Creates and starts a new access point based on the specified socket.
     * If the specified access point has already been installed the method has no effect.
     *
     * @param  socket   the socket that the access point should use.
     * @param remoteAddress the remote address of the socket of the
     * {@link Connector} to be created if it is a TCP socket, or null if it is UDP.
     * @throws IOException 
     */
    protected void addSocket(IceSocketWrapper socket, TransportAddress remoteAddress) {
        try {
            logger.info("addSocket: {}", ((DatagramChannel) socket.getChannel()).getLocalAddress());
        } catch (IOException e) {
            logger.warn("Exception getting channels local address", e);
        }
        TransportAddress localAddress = socket.getTransportAddress();
        final ConcurrentMap<TransportAddress, Map<TransportAddress, Connector>> connectorsMap = (localAddress.getTransport().equals(Transport.UDP)) ? udpConnectors : tcpConnectors;
        Map<TransportAddress, Connector> connectorsForLocalAddress = connectorsMap.get(localAddress);
        if (connectorsForLocalAddress == null) {
            connectorsForLocalAddress = new HashMap<>();
            connectorsMap.put(localAddress, connectorsForLocalAddress);
            Connector connector = new Connector(socket, remoteAddress, messageQueue, this);
            connectorsForLocalAddress.put(remoteAddress, connector);
            executor.submit(connector);
        } else if (connectorsForLocalAddress.containsKey(remoteAddress)) {
            logger.info("Not creating a new Connector, because we already have one for the given address pair: {} -> {}", localAddress, remoteAddress);
        } else {
            Connector connector = new Connector(socket, remoteAddress, messageQueue, this);
            executor.submit(connectorsForLocalAddress.put(remoteAddress, connector));
        }
        logger.info("Local connectors (add): {}", connectorsForLocalAddress);
    }

    /**
     * Stops and deletes the specified access point.
     *
     * @param localAddress the local address of the connector to remove.
     * @param remoteAddress the remote address of the connector to remote. Use
     * null to match the Connector with no specified remote address.
     */
    protected void removeSocket(TransportAddress localAddress, TransportAddress remoteAddress) {
        final ConcurrentMap<TransportAddress, Map<TransportAddress, Connector>> connectorsMap = (localAddress.getTransport().equals(Transport.UDP)) ? udpConnectors : tcpConnectors;
        Map<TransportAddress, Connector> connectorsForLocalAddress = connectorsMap.get(localAddress);
        if (connectorsForLocalAddress != null) {
            Connector connector = connectorsForLocalAddress.remove(remoteAddress);
            if (connector != null) {
                connector.stop();
            }
            if (connectorsForLocalAddress.isEmpty()) {
                connectorsMap.remove(localAddress);
            }
        }
    }

    /**
     * Stops NetAccessManager and all of its MessageProcessor.
     */
    public void stop() {
        executor.shutdownNow();
        // close all udp
        for (Map<TransportAddress, Connector> map : udpConnectors.values()) {
            for (Connector connector : map.values()) {
                connector.stop();
            }
        }
        // close all tcp
        for (Map<TransportAddress, Connector> map : tcpConnectors.values()) {
            for (Connector connector : map.values()) {
                connector.stop();
            }
        }
    }

    /**
     * Returns the Connector responsible for a particular source address and a particular destination address.
     *
     * @param localAddress the source address.
     * @param remoteAddress the destination address.
     * Returns the Connector responsible for a particular source address and a particular destination address,
     * or null if there's none.
     */
    private Connector getConnector(TransportAddress localAddress, TransportAddress remoteAddress) {
        boolean udp = localAddress.getTransport() == Transport.UDP;
        final ConcurrentMap<TransportAddress, Map<TransportAddress, Connector>> connectorsMap = udp ? udpConnectors : tcpConnectors;
        Connector connector = null;
        Map<TransportAddress, Connector> connectorsForLocalAddress = connectorsMap.get(localAddress);
        logger.info("Local connectors: {}", connectorsForLocalAddress);
        if (connectorsForLocalAddress != null) {
            connector = connectorsForLocalAddress.get(remoteAddress);
            // Fallback to the socket with no specific remote address
            if (udp && connector == null) {
                connector = connectorsForLocalAddress.get(null);
            }
        }
        return connector;
    }

    //--------------- SENDING MESSAGES -----------------------------------------
    /**
     * Sends the specified stun message through the specified access point.
     *
     * @param stunMessage the message to send
     * @param srcAddr the access point to use to send the message
     * @param remoteAddr the destination of the message.
     *
     * @throws IllegalArgumentException if the apDescriptor references an
     * access point that had not been installed,
     * @throws IOException  if an error occurs while sending message bytes
     * through the network socket.
     */
    void sendMessage(Message stunMessage, TransportAddress srcAddr, TransportAddress remoteAddr) throws IllegalArgumentException, IOException {
        sendMessage(stunMessage.encode(stunStack), srcAddr, remoteAddr);
    }

    /**
     * Sends the specified stun message through the specified access point.
     *
     * @param channelData the message to send
     * @param srcAddr the access point to use to send the message
     * @param remoteAddr the destination of the message.
     *
     * @throws IllegalArgumentException if the apDescriptor references an
     * access point that had not been installed,
     * @throws IOException  if an error occurs while sending message bytes
     * through the network socket.
     * @throws StunException 
     */
    void sendMessage(ChannelData channelData, TransportAddress srcAddr, TransportAddress remoteAddr) throws IllegalArgumentException, IOException, StunException {
        boolean pad = srcAddr.getTransport() == Transport.TCP || srcAddr.getTransport() == Transport.TLS;
        sendMessage(channelData.encode(pad), srcAddr, remoteAddr);
    }

    /**
     * Sends the specified bytes through the specified access point.
     *
     * @param bytes the bytes to send.
     * @param srcAddr the access point to use to send the bytes.
     * @param remoteAddr the destination of the message.
     *
     * @throws IllegalArgumentException if the apDescriptor references an
     * access point that had not been installed,
     * @throws IOException  if an error occurs while sending message bytes
     * through the network socket.
     */
    void sendMessage(byte[] bytes, TransportAddress srcAddr, TransportAddress remoteAddr) throws IllegalArgumentException, IOException {
        Connector ap = getConnector(srcAddr, remoteAddr);
        if (ap == null) {
            throw new IllegalArgumentException("No socket found for " + srcAddr + "->" + remoteAddr);
        }
        ap.sendMessage(bytes, remoteAddr);
    }
}
