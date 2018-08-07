/* See LICENSE.md for license information */
package org.ice4j.socket;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.future.ConnectFuture;
import org.apache.mina.core.future.IoFutureListener;
import org.apache.mina.core.service.IoHandlerAdapter;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.transport.socket.DatagramSessionConfig;
import org.apache.mina.transport.socket.SocketSessionConfig;
import org.apache.mina.transport.socket.nio.NioDatagramConnector;
import org.apache.mina.transport.socket.nio.NioSocketConnector;
import org.ice4j.StunException;
import org.ice4j.StunMessageEvent;
import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.attribute.Attribute;
import org.ice4j.attribute.DataAttribute;
import org.ice4j.attribute.XorMappedAddressAttribute;
import org.ice4j.attribute.XorPeerAddressAttribute;
import org.ice4j.ice.ComponentSocket;
import org.ice4j.ice.RelayedCandidate;
import org.ice4j.ice.harvest.TurnCandidateHarvest;
import org.ice4j.ice.nio.IceDecoder;
import org.ice4j.ice.nio.IceTransport;
import org.ice4j.message.Indication;
import org.ice4j.message.Message;
import org.ice4j.message.MessageFactory;
import org.ice4j.message.Request;
import org.ice4j.message.Response;
import org.ice4j.stack.MessageEventHandler;
import org.ice4j.stack.RawMessage;
import org.ice4j.stack.StunStack;
import org.ice4j.stack.TransactionID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents an application-purposed (as opposed to an ICE-specific) DatagramSocket for a RelayedCandidate harvested by a TurnCandidateHarvest
 * (and its associated TurnCandidateHarvester, of course). RelayedCandidateConnection is associated with a successful Allocation on a TURN server
 * and implements sends and receives through it using TURN messages to and from that TURN server.
 *
 * {@link https://tools.ietf.org/html/rfc5766}
 *
 * @author Lyubomir Marinov
 * @author Paul Gregoire
 */
public class RelayedCandidateConnection extends IoHandlerAdapter implements MessageEventHandler {

    private static final Logger logger = LoggerFactory.getLogger(RelayedCandidateConnection.class);

    /**
     * The constant which represents a channel number value signaling that no channel number has been explicitly specified.
     */
    private static final char CHANNEL_NUMBER_NOT_SPECIFIED = 0;

    /**
     * The length in bytes of the Channel Number field of a TURN ChannelData message.
     */
    private static final int CHANNELDATA_CHANNELNUMBER_LENGTH = 2;

    /**
     * The length in bytes of the Length field of a TURN ChannelData message.
     */
    private static final int CHANNELDATA_LENGTH_LENGTH = 2;

    /**
     * The maximum channel number which is valid for TURN ChannelBind Request.
     */
    public static final char MAX_CHANNEL_NUMBER = 0x7FFF;

    /**
     * The minimum channel number which is valid for TURN ChannelBind Requests.
     */
    public static final char MIN_CHANNEL_NUMBER = 0x4000;

    /**
     * The lifetime in milliseconds of a TURN permission created using a CreatePermission request.
     */
    private static final long PERMISSION_LIFETIME = 300 /* seconds */* 1000L;

    /**
     * The time in milliseconds before a TURN permission expires that a RelayedCandidateConnection is to try to reinstall it.
     */
    private static final long PERMISSION_LIFETIME_LEEWAY = 60 /* seconds */* 1000L;

    /**
     * The RelayedCandidate which uses this instance as the value of its socket property.
     */
    private final RelayedCandidate relayedCandidate;

    /**
     * The TurnCandidateHarvest which has harvested {@link #relayedCandidate}.
     */
    private final TurnCandidateHarvest turnCandidateHarvest;

    /**
     * The list of per-peer Channels through which this RelayedCandidateConnections relays data send to it to peer TransportAddresses.
     */
    private final CopyOnWriteArrayList<Channel> channels = new CopyOnWriteArrayList<>();

    /**
     * Whether or not to use ChannelData instead of Indications (Send/Data).
     */
    private boolean useChannelData;

    /**
     * Transaction id for a channel bind request that was last sent.
     */
    private TransactionID channelBindRequest;

    /**
     * The IoSession through which this RelayedCandidateConnection actually sends and receives the data. Since data can be exchanged with a TURN
     * server using STUN messages (i.e. Send and Data indications), RelayedCandidateConnection may send and receive data using the associated
     * StunStack and not channelDataSocket. However, using channelDataSession is supposed to be more efficient than using StunStack.
     */
    private IoSession channelDataSession;

    /**
     * The next free channel number to be returned by {@link #getNextChannelNumber()} and marked as non-free.
     */
    private char nextChannelNumber = MIN_CHANNEL_NUMBER;

    /**
     * Peer address for the local connection. Peer-B transport address in the RFC example (Figure 1 pg. 5).
     */
    private TransportAddress localPeerAddress;

    /**
     * Peer address for the remote connection. Peer-A transport address in the RFC example (Figure 1 pg. 5).
     */
    private TransportAddress remotePeerAddress;

    /**
     * The indicator which determines whether this instance has started executing or has executed its {@link #close()} method.
     */
    private AtomicBoolean closed = new AtomicBoolean(false);

    /**
     * Used to control connection flow.
     */
    protected CountDownLatch connectLatch = new CountDownLatch(1);

    /**
     * Reusable IoFutureListener for connect.
     */
    protected final IoFutureListener<ConnectFuture> connectListener = new IoFutureListener<ConnectFuture>() {

        @Override
        public void operationComplete(ConnectFuture future) {
            if (future.isConnected()) {
                channelDataSession = future.getSession();
            } else {
                logger.warn("Connect failed: {}", relayedCandidate);
            }
            // count down since connect is complete
            connectLatch.countDown();
        }

    };

    /**
     * Initializes a new RelayedCandidateConnection instance which is to be the socket of a specific RelayedCandidate
     * harvested by a specific TurnCandidateHarvest.
     *
     * @param relayedCandidate the RelayedCandidate which is to use the new instance as the value of its socket property
     * @param turnCandidateHarvest the TurnCandidateHarvest which has harvested relayedCandidate
     * @throws SocketException if anything goes wrong while initializing the new RelayedCandidateConnection instance
     */
    public RelayedCandidateConnection(RelayedCandidate relayedCandidate, TurnCandidateHarvest turnCandidateHarvest) throws SocketException {
        this.relayedCandidate = relayedCandidate;
        this.turnCandidateHarvest = turnCandidateHarvest;
        this.turnCandidateHarvest.harvester.getStunStack().addIndicationListener(this.turnCandidateHarvest.hostCandidate.getTransportAddress(), this);
    }

    /**
     * Determines whether a specific DatagramPacket is accepted by {@link #channelDataSocket} (i.e. whether channelDataSocket
     * understands p and p is meant to be received by channelDataSocket).
     *
     * @param p the DatagramPacket which is to be checked whether it is accepted by channelDataSocket
     * @return true if channelDataSocket accepts p (i.e. channelDataSocket understands p and p is meant to be received by channelDataSocket); otherwise, false
     */
    //    private boolean channelDataSocketAccept(DatagramPacket p) {
    //        // Is it from our TURN server?
    //        if (turnCandidateHarvest.harvester.stunServer.equals(p.getSocketAddress())) {
    //            int pLength = p.getLength();
    //            if (pLength >= (CHANNELDATA_CHANNELNUMBER_LENGTH + CHANNELDATA_LENGTH_LENGTH)) {
    //                byte[] pData = p.getData();
    //                int pOffset = p.getOffset();
    //                // The first two bits should be 0b01 because of the current channel number range 0x4000 - 0x7FFE. But 0b10 and 0b11
    //                // which are currently reserved and may be used in the future to extend the range of channel numbers.
    //                if ((pData[pOffset] & 0xC0) != 0) {
    //                    // Technically, we cannot create a DatagramPacket from a ChannelData message with a Channel Number we do not know about. 
    //                    // But determining that we know the value of the Channel Number field may be too much of an unnecessary performance penalty
    //                    // and it may be unnecessary because the message comes from our TURN server and it looks like a ChannelData message already.
    //                    pOffset += CHANNELDATA_CHANNELNUMBER_LENGTH;
    //                    pLength -= CHANNELDATA_CHANNELNUMBER_LENGTH;
    //                    int length = ((pData[pOffset++] << 8) | (pData[pOffset++] & 0xFF));
    //                    int padding = ((length % 4) > 0) ? 4 - (length % 4) : 0;
    //                    // The Length field specifies the length in bytes of the Application Data field. The Length field does not include the
    //                    // padding that is sometimes present in the data of the DatagramPacket.
    //                    return length == pLength - padding - CHANNELDATA_LENGTH_LENGTH || length == pLength - CHANNELDATA_LENGTH_LENGTH;
    //                }
    //            }
    //        }
    //        return false;
    //    }

    /**
     * Closes this datagram socket.
     */
    public void close() {
        if (closed.compareAndSet(false, true)) {
            turnCandidateHarvest.harvester.getStunStack().removeIndicationListener(turnCandidateHarvest.hostCandidate.getTransportAddress(), this);
            turnCandidateHarvest.close(this);
        }
    }

    /**
     * Gets the local address to which the socket is bound. RelayedCandidateConnection returns the address of its localSocketAddress.
     * <p>
     * If there is a security manager, its checkConnect method is first called with the host address and -1 as its arguments to see if
     * the operation is allowed.
     * <br>
     *
     * @return the local address to which the socket is bound, or an InetAddress representing any local address if either the socket
     * is not bound, or the security manager checkConnect method does not allow the operation
     */
    public InetAddress getLocalAddress() {
        return getLocalSocketAddress().getAddress();
    }

    /**
     * Returns the port number on the local host to which this socket is bound. RelayedCandidateConnection returns the port of its localSocketAddress.
     *
     * @return the port number on the local host to which this socket is bound
     */
    public int getLocalPort() {
        return getLocalSocketAddress().getPort();
    }

    /**
     * Returns the address of the endpoint this socket is bound to, or null if it is not bound yet. Since
     * RelayedCandidateConnection represents an application-purposed DatagramSocket relaying data to and from a
     * TURN server, the localSocketAddress is the transportAddress of the respective RelayedCandidate.
     *
     * @return a SocketAddress representing the local endpoint of this socket, or null if it is not bound yet
     */
    public InetSocketAddress getLocalSocketAddress() {
        return getRelayedCandidate().getTransportAddress();
    }

    /**
     * Gets the next free channel number to be allocated to a Channel and marked as non-free.
     *
     * @return the next free channel number to be allocated to a Channel and marked as non-free.
     */
    private char getNextChannelNumber() {
        char nextChannelNumber;
        if (this.nextChannelNumber > MAX_CHANNEL_NUMBER) {
            nextChannelNumber = CHANNEL_NUMBER_NOT_SPECIFIED;
        } else {
            nextChannelNumber = this.nextChannelNumber;
            this.nextChannelNumber++;
        }
        return nextChannelNumber;
    }

    /**
     * Gets the RelayedCandidate which uses this instance as the value of its socket property.
     *
     * @return the RelayedCandidate which uses this instance as the value of its socket property
     */
    public final RelayedCandidate getRelayedCandidate() {
        return relayedCandidate;
    }

    public TurnCandidateHarvest getTurnCandidateHarvest() {
        return turnCandidateHarvest;
    }

    /**
     * Notifies this MessageEventHandler that a specific STUN message has been received, parsed and is ready for delivery.
     * RelayedCandidateConnection handles STUN indications sent from the associated TURN server and received at the associated local
     * TransportAddress.
     *
     * @param event StunMessageEvent which encapsulates the received STUN message
     */
    public void handleMessageEvent(StunMessageEvent event) {
        logger.debug("handleMessageEvent: {}", event);
        SocketAddress localAddr = event.getLocalAddress();
        SocketAddress remoteAddr = event.getRemoteAddress();
        // Is it meant for us? (It should be because RelayedCandidateConnection registers for STUN indications received at the associated local TransportAddress only)
        if (turnCandidateHarvest.hostCandidate.getTransportAddress().equals(event.getLocalAddress())) {
            // Is it from our TURN server?
            if (turnCandidateHarvest.harvester.stunServer.equals(event.getRemoteAddress())) {
                Message stunMessage = event.getMessage();
                // RFC 5766: When the client receives a Data indication, it checks that the Data indication contains both an 
                // XOR-PEER-ADDRESS and a DATA attribute and discards the indication if it does not.
                XorPeerAddressAttribute peerAddressAttribute = (XorPeerAddressAttribute) stunMessage.getAttribute(Attribute.Type.XOR_PEER_ADDRESS);
                DataAttribute dataAttribute = (DataAttribute) stunMessage.getAttribute(Attribute.Type.DATA);
                if (peerAddressAttribute != null && dataAttribute != null) {
                    TransportAddress peerAddress = peerAddressAttribute.getAddress(stunMessage.getTransactionID());
                    if (peerAddress != null) {
                        byte[] data = dataAttribute.getData();
                        if (data != null) {
                            // create a raw message from the data bytes
                            RawMessage message = RawMessage.build(data, remoteAddr, localAddr);
                            // check for stun/turn
                            if (IceDecoder.isStun(data)) {
                                try {
                                    Message turnMessage = Message.decode(message.getBytes(), 0, message.getMessageLength());
                                    logger.debug("Message: {}", turnMessage);
                                    if (logger.isDebugEnabled()) {
                                        turnMessage.getAttributes().forEach(attr -> {
                                            logger.debug("Attribute: {}", attr);
                                        });
                                    }
                                    // send the data-derived message back over to the stack for processing
                                    StunStack stunStack = relayedCandidate.getStunStack();
                                    stunStack.handleMessageEvent(new StunMessageEvent(stunStack, message, turnMessage));
                                    // if we want to bind a channel, send the request (do we send this more than 1x?)
                                    if (useChannelData && channelBindRequest == null) {
                                        TransportAddress localPeerAddr = relayedCandidate.getRelatedAddress();
                                        logger.debug("Channel bind peer address: {}", localPeerAddr);
                                        // create and send a channel bind request
                                        TransactionID transID = TransactionID.createNewTransactionID();
                                        Request channelRequest = MessageFactory.createChannelBindRequest(RelayedCandidateConnection.MIN_CHANNEL_NUMBER, localPeerAddr, transID.getBytes());
                                        turnCandidateHarvest.getLongTermCredentialSession().addAttributes(channelRequest);
                                        // store the transaction id so we can keep track of it being sent
                                        channelBindRequest = TransactionID.build(turnCandidateHarvest.sendRequest(this, channelRequest));
                                    }
                                } catch (Exception ex) {
                                    logger.warn("Failed to decode a stun message!", ex);
                                }
                            } else {
                                relayedCandidate.getCandidateIceSocketWrapper().offerMessage(message);
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * Notifies this RelayedCandidateConnection that a specific Request it has sent has either failed or received a STUN error Response.
     *
     * @param response the Response which responds to request
     * @param request the Request sent by this instance to which response responds
     * @return true if the failure or error condition has been handled and the caller should assume this instance has recovered from it;
     * otherwise, false
     */
    public boolean processErrorOrFailure(Response response, Request request) {
        switch (request.getMessageType()) {
            case Message.CHANNELBIND_REQUEST:
                setChannelNumberIsConfirmed(request, false);
                break;
            case Message.CREATEPERMISSION_REQUEST:
                setChannelBound(request, false);
                break;
        }
        return false;
    }

    /**
     * Notifies this RelayedCandidateConnection that a specific Request it has sent has received a STUN success Response.
     *
     * @param response the Response which responds to request
     * @param request the Request sent by this instance to which response responds
     */
    public void processSuccess(Response response, Request request) {
        logger.debug("processSuccess - {} to {}", request, response);
        //logger.debug("Relayed candidate - mapped: {} relayed: {}", relayedCandidate.getMappedAddress(), relayedCandidate.getRelayedAddress());
        switch (request.getMessageType()) {
            case Message.CHANNELBIND_REQUEST:
                setChannelNumberIsConfirmed(request, true);
                break;
            case Message.CREATEPERMISSION_REQUEST:
                setChannelBound(request, true);
                break;
        }
        switch (response.getMessageType()) {
            case Message.ALLOCATE_RESPONSE:
                XorMappedAddressAttribute mappedAddressAttribute = (XorMappedAddressAttribute) response.getAttribute(Attribute.Type.XOR_MAPPED_ADDRESS);
                localPeerAddress = mappedAddressAttribute.getAddress(response.getTransactionID());
                logger.info("Local peer address: {}", localPeerAddress);
                break;
            case Message.CREATEPERMISSION_RESPONSE:
                XorPeerAddressAttribute peerAddressAttribute = (XorPeerAddressAttribute) request.getAttribute(Attribute.Type.XOR_PEER_ADDRESS);
                remotePeerAddress = peerAddressAttribute.getAddress(request.getTransactionID());
                logger.info("Remote peer address: {}", remotePeerAddress);
                // update the component socket to inform it of the ice socket wrapper to use
                ComponentSocket componentSocket = relayedCandidate.getParentComponent().getComponentSocket();
                // authorize the remote address
                componentSocket.addAuthorizedAddress(remotePeerAddress);
                logger.debug("Component socket: {} relayed socket: {}", componentSocket.getSocket(), relayedCandidate.getCandidateIceSocketWrapper());
                // get the relayed socket
                IceSocketWrapper relayedSocket = relayedCandidate.getCandidateIceSocketWrapper();
                // get currently set socket and close it if its not our relayed ice socket
                IceSocketWrapper currentSocket = componentSocket.getSocket();
                if (relayedSocket.equals(currentSocket)) {
                    logger.debug("Component socket is relay compatible");
                }
                break;
        }
    }

    public void send(IoBuffer buf, SocketAddress destAddress) throws IOException {
        logger.info("send: {} to {}", buf, destAddress);
        if (closed.get()) {
            throw new IOException(RelayedCandidateConnection.class.getSimpleName() + " has been closed");
        } else if (!useChannelData) { // if we're not using channel-data
            // send indication is the next step after creating permission response. RFC-5766 pg. 51
            byte[] data = new byte[buf.remaining()];
            buf.get(data);
            logger.debug("Send indication data length: {}", data.length);
            TransactionID transID = TransactionID.createNewTransactionID(this);
            Indication indication = MessageFactory.createSendIndication(remotePeerAddress, data, transID.getBytes());
            try {
                turnCandidateHarvest.harvester.getStunStack().sendIndication(indication, turnCandidateHarvest.harvester.stunServer, turnCandidateHarvest.hostCandidate.getTransportAddress());
            } catch (StunException sex) {
                logger.warn("Failed to send send-indication", sex);
            }
        } else {
            // Get a channel to the peer which is to receive the packetToSend.
            int channelCount = channels.size();
            TransportAddress peerAddress = new TransportAddress((InetSocketAddress) destAddress, relayedCandidate.getTransport());
            Channel channel = null;
            for (int channelIndex = 0; channelIndex < channelCount; channelIndex++) {
                Channel aChannel = channels.get(channelIndex);
                if (aChannel.peerAddressEquals(peerAddress)) {
                    channel = aChannel;
                    break;
                }
            }
            if (channel == null) {
                channel = new Channel(peerAddress);
                channels.add(channel);
            }
            // RFC 5245 says that "it is RECOMMENDED that the agent defer creation of a TURN channel until ICE completes." RelayedCandidateConnection
            // is not explicitly told from the outside that ICE has completed so it tries to determine it by assuming that connectivity checks send
            // only STUN messages and ICE has completed by the time a non-STUN message is to be sent.
            boolean forceBind = false;
            if (channelDataSession != null && !channel.getChannelDataIsPreferred() && !IceDecoder.isStun(buf.array())) {
                channel.setChannelDataIsPreferred(true);
                forceBind = true;
            }
            logger.debug("Force: {} binding: {} bound: {} for peer: {}", forceBind, channel.isBinding(), channel.isBound(), peerAddress);
            // Either bind the channel or send the packetToSend through it.
            if (!forceBind && channel.isBound()) {
                try {
                    channel.send(buf, peerAddress);
                } catch (StunException sex) {
                    logger.warn("Failed to send through channel", sex);
                }
            } else if (forceBind || !channel.isBinding()) {
                try {
                    channel.bind();
                } catch (StunException sex) {
                    logger.warn("Failed to bind channel", sex);
                }
            }
        }

    }

    /** {@inheritDoc} */
    @Override
    public void sessionCreated(IoSession session) throws Exception {
        if (logger.isTraceEnabled()) {
            logger.trace("Session created (session: {}) local: {} remote: {}", session.getId(), session.getLocalAddress(), session.getRemoteAddress());
        }
        // get the ice socket using the host candidates address
        TransportAddress addr = turnCandidateHarvest.hostCandidate.getTransportAddress();
        IceSocketWrapper iceSocket = IceTransport.getIceHandler().lookupBinding(addr);
        // add the socket to the session
        session.setAttribute(IceTransport.Ice.CONNECTION, iceSocket);
    }

    /**
     * {@inheritDoc} 
     * <br>
     * This should only receive data from the tunneled connection.
     */
    @Override
    public void messageReceived(IoSession session, Object message) throws Exception {
        if (logger.isTraceEnabled()) {
            logger.trace("Message received (session: {}) local: {} remote: {}", session.getId(), session.getLocalAddress(), session.getRemoteAddress());
            logger.trace("Received: {} type: {}", String.valueOf(message), message.getClass().getName());
        }
        // get the transport
        Transport transport = session.getTransportMetadata().isConnectionless() ? Transport.UDP : Transport.TCP;
        // get the local address
        InetSocketAddress inetAddr = (InetSocketAddress) session.getLocalAddress();
        // XXX i assume the port wont match here, we can't use the relay channel's port
        TransportAddress localAddress = new TransportAddress(inetAddr.getAddress(), inetAddr.getPort(), transport);
        // get our associated ice socket
        final IceSocketWrapper iceSocket = (IceSocketWrapper) session.getAttribute(IceTransport.Ice.CONNECTION);
        if (iceSocket != null) {
            if (message instanceof IoBuffer) {
                IoBuffer buf = (IoBuffer) message;
                int channelDataLength = buf.remaining();
                if (channelDataLength >= (CHANNELDATA_CHANNELNUMBER_LENGTH + CHANNELDATA_LENGTH_LENGTH)) {
                    // read the channel number
                    char channelNumber = (char) (buf.get() << 8 | buf.get() & 0xFF);
                    // read the length
                    int length = buf.get() << 8 | buf.get() & 0xFF;
                    byte[] channelData = new byte[length];
                    // pull the bytes from iobuffer into channel data
                    buf.get(channelData);
                    channels.forEach(channel -> {
                        if (channel.channelNumberEquals(channelNumber)) {
                            // create a raw message and pass it to the socket queue for consumers
                            iceSocket.offerMessage(RawMessage.build(channelData, channel.peerAddress, localAddress));
                            return;
                        }
                    });
                } else {
                    logger.debug("Invalid channel data bytes < 4");
                }
            } else if (message instanceof RawMessage) {
                // non-stun message
                iceSocket.offerMessage((RawMessage) message);
            } else {
                logger.debug("Message type: {}", message.getClass().getName());
            }
        } else {
            logger.debug("Ice socket lookups failed");
        }
    }

    /** {@inheritDoc} */
    @Override
    public void messageSent(IoSession session, Object message) throws Exception {
        if (logger.isTraceEnabled()) {
            logger.trace("Message sent (session: {}) local: {} remote: {}\nread: {} write: {}", session.getId(), session.getLocalAddress(), session.getRemoteAddress(), session.getReadBytes(), session.getWrittenBytes());
        }
    }

    /**
     * Sets the bound property of a Channel the installation of which has been attempted by sending a specific Request.
     *
     * @param request the Request which has been attempted in order to install a Channel
     * @param bound true if the bound property of the Channel is to be set to true; otherwise, false
     */
    private void setChannelBound(Request request, boolean bound) {
        logger.debug("setChannelBound: {}", bound);
        XorPeerAddressAttribute peerAddressAttribute = (XorPeerAddressAttribute) request.getAttribute(Attribute.Type.XOR_PEER_ADDRESS);
        byte[] transactionID = request.getTransactionID();
        TransportAddress peerAddress = peerAddressAttribute.getAddress(transactionID);
        channels.forEach(channel -> {
            if (channel.peerAddressEquals(peerAddress)) {
                logger.debug("Channel {} bound, sending channel bind request for {}", channel.channelNumber, peerAddress);
                channel.setBound(bound, transactionID);
                // create and send a channel bind request
                try {
                    Request chanBindRequest = MessageFactory.createChannelBindRequest(channel.channelNumber, peerAddress, TransactionID.createNewTransactionID().getBytes());
                    turnCandidateHarvest.sendRequest(this, chanBindRequest);
                } catch (StunException sex) {
                    logger.warn("Channel bind request failed", sex);
                }
                return;
            }
        });
    }

    /**
     * Sets the channelNumberIsConfirmed property of a Channel which has attempted to allocate a specific channel number by sending a
     * specific ChannelBind Request.
     *
     * @param request the Request which has been sent to allocate a specific channel number for a Channel
     * @param channelNumberIsConfirmed true if the channel number has been successfully allocated; otherwise, false
     */
    private void setChannelNumberIsConfirmed(Request request, boolean channelNumberIsConfirmed) {
        logger.debug("setChannelNumberIsConfirmed: {} channelNumberIsConfirmed: {}", request, channelNumberIsConfirmed);
        XorPeerAddressAttribute peerAddressAttribute = (XorPeerAddressAttribute) request.getAttribute(Attribute.Type.XOR_PEER_ADDRESS);
        byte[] transactionID = request.getTransactionID();
        TransportAddress peerAddress = peerAddressAttribute.getAddress(transactionID);
        logger.debug("Channel number confirmed for {}", peerAddress);
        channels.forEach(channel -> {
            if (channel.peerAddressEquals(peerAddress)) {
                channel.setChannelNumberIsConfirmed(channelNumberIsConfirmed, transactionID);
                return;
            }
        });
    }

    public boolean isUseChannelData() {
        return useChannelData;
    }

    public void setUseChannelData(boolean useChannelData) {
        this.useChannelData = useChannelData;
    }

    // create either UDP or TCP sessions for the channel data to go over
    private void createSession(TransportAddress peerAddress) {
        TransportAddress transportAddress = turnCandidateHarvest.hostCandidate.getTransportAddress();
        logger.debug("createSession: {} {}", transportAddress, peerAddress);
        switch (relayedCandidate.getTransport()) {
            case TCP:
                try {
                    NioSocketConnector connector = new NioSocketConnector();
                    SocketSessionConfig config = connector.getSessionConfig();
                    config.setReuseAddress(true);
                    config.setTcpNoDelay(true);
                    // QoS
                    config.setTrafficClass(IceTransport.trafficClass);
                    // set connection timeout of x milliseconds
                    connector.setConnectTimeoutMillis(3000L);
                    // set the handler on the connector
                    connector.setHandler(this);
                    // connect it
                    ConnectFuture future = connector.connect(peerAddress, transportAddress);
                    future.addListener(connectListener);
                    future.awaitUninterruptibly();
                    logger.debug("Connect future: {}", future.isDone());
                } catch (Throwable t) {
                    logger.warn("Exception creating new TCP connector for {} to {}", transportAddress, peerAddress, t);
                }
                break;
            case UDP:
            default:
                try {
                    NioDatagramConnector connector = new NioDatagramConnector();
                    DatagramSessionConfig config = connector.getSessionConfig();
                    config.setBroadcast(false);
                    config.setReuseAddress(true);
                    config.setCloseOnPortUnreachable(true);
                    // QoS
                    config.setTrafficClass(IceTransport.trafficClass);
                    // set connection timeout of x milliseconds
                    connector.setConnectTimeoutMillis(3000L);
                    // set the handler on the connector
                    connector.setHandler(this);
                    // connect it
                    ConnectFuture future = connector.connect(peerAddress, transportAddress);
                    future.addListener(connectListener);
                    future.awaitUninterruptibly();
                    logger.debug("Connect future: {}", future.isDone());
                } catch (Throwable t) {
                    logger.warn("Exception creating new UDP connector for {} to {}", transportAddress, peerAddress, t);
                }
                break;
        }
    }

    /**
     * Represents a channel which relays data sent through this RelayedCandidateConnection to a specific
     * TransportAddress via the TURN server associated with this RelayedCandidateConnection.
     */
    private class Channel {
        /**
         * The time stamp in milliseconds at which {@link #bindingTransactionID} has been used to bind/install this Channel.
         */
        private long bindingTimeStamp = -1;

        /**
         * The ID of the transaction with which a CreatePermission Request has been sent to bind/install this Channel.
         */
        private byte[] bindingTransactionID;

        /**
         * The indication which determines whether a confirmation has been received that this Channel has been bound.
         */
        private boolean bound;

        /**
         * The indicator which determines whether this Channel is set to prefer sending using TURN ChannelData
         * messages instead of Send indications.
         */
        private boolean channelDataIsPreferred;

        /**
         * The IoBuffer in which this Channel sends TURN ChannelData messages through IoSession.
         */
        private IoBuffer channelDataBuffer;

        /**
         * The TURN channel number of this Channel which is to be or has been allocated using a ChannelBind Request.
         */
        private char channelNumber = CHANNEL_NUMBER_NOT_SPECIFIED;

        /**
         * The indicator which determines whether the associated TURN server has confirmed the allocation of {@link #channelNumber} by us receiving a
         * success Response to our ChannelBind Request.
         */
        private boolean channelNumberIsConfirmed;

        /**
         * The TransportAddress of the peer to which this Channel provides a permission of this RelayedCandidateConnection to send data to.
         */
        public final TransportAddress peerAddress;

        /**
         * Initializes a new Channel instance which is to provide this RelayedCandidateConnection with a permission to send to a specific peer address.
         *
         * @param peerAddress the TransportAddress of the peer
         */
        public Channel(TransportAddress peerAddress) {
            logger.debug("New channel: {}", peerAddress);
            this.peerAddress = peerAddress;
        }

        /**
         * Binds/installs this channel so that it provides this RelayedCandidateConnection with a permission to send data to the TransportAddress
         * associated with this instance.
         *
         * @throws StunException if anything goes wrong while binding/installing this channel
         */
        public void bind() throws StunException {
            logger.debug("bind!");
            byte[] createPermissionTransactionID = TransactionID.createNewTransactionID().getBytes();
            Request createPermissionRequest = MessageFactory.createCreatePermissionRequest(peerAddress, createPermissionTransactionID);
            createPermissionRequest.setTransactionID(createPermissionTransactionID);
            turnCandidateHarvest.sendRequest(RelayedCandidateConnection.this, createPermissionRequest);
            bindingTransactionID = createPermissionTransactionID;
            bindingTimeStamp = System.currentTimeMillis();
            if (channelDataIsPreferred) {
                if (channelNumber == CHANNEL_NUMBER_NOT_SPECIFIED) {
                    channelNumber = getNextChannelNumber();
                    channelNumberIsConfirmed = false;
                }
                if (channelNumber != CHANNEL_NUMBER_NOT_SPECIFIED) {
                    byte[] channelBindTransactionID = TransactionID.createNewTransactionID().getBytes();
                    Request channelBindRequest = MessageFactory.createChannelBindRequest(channelNumber, peerAddress, channelBindTransactionID);
                    channelBindRequest.setTransactionID(channelBindTransactionID);
                    // be prepared to receive ChannelData messages from the TURN server as soon as the ChannelBind request is sent and before
                    // success response is received
                    createSession(peerAddress);
                    // send the bind request
                    turnCandidateHarvest.sendRequest(RelayedCandidateConnection.this, channelBindRequest);
                }
            }
        }

        /**
         * Determines whether the channel number of this Channel is value equal to a specific channel number.
         *
         * @param channelNumber the channel number to be compared to the channel number of this Channel for value equality
         * @return true if the specified channelNumber is equal to the channel number of this Channel
         */
        public boolean channelNumberEquals(char channelNumber) {
            return (this.channelNumber == channelNumber);
        }

        /**
         * Gets the indicator which determines whether this Channel is set to prefer sending DatagramPackets using TURN ChannelData
         * messages instead of Send indications.
         *
         * @return the indicator which determines preference of TURN ChannelData messages instead of Send indications
         */
        public boolean getChannelDataIsPreferred() {
            return channelDataIsPreferred;
        }

        /**
         * Gets the indicator which determines whether this instance has started binding/installing itself and has not received a confirmation that it
         * has succeeded in doing so yet.
         *
         * @return true if this instance has started binding/installing itself and has not received a confirmation that it has succeeded in
         * doing so yet; otherwise, false
         */
        public boolean isBinding() {
            return (bindingTransactionID != null);
        }

        /**
         * Gets the indication which determines whether this instance is currently considered bound/installed.
         *
         * @return true if this instance is currently considered bound/installed; otherwise, false
         */
        public boolean isBound() {
            if (bindingTimeStamp == -1 || (bindingTimeStamp + PERMISSION_LIFETIME - PERMISSION_LIFETIME_LEEWAY) < System.currentTimeMillis()) {
                return false;
            }
            return (bindingTransactionID == null) && bound;
        }

        /**
         * Determines whether the peerAddress property of this instance is considered by this Channel to be equal to a specific TransportAddress.
         *
         * @param peerAddress the TransportAddress which is to be checked for equality (as defined by this Channel and not
         * necessarily by the TransportAddress class)
         * @return true if the specified TransportAddress is considered by this Channel to be equal to its peerAddress property; otherwise, false
         */
        public boolean peerAddressEquals(TransportAddress peerAddress) {
            // CreatePermission installs a permission for the IP address and the port is ignored. But ChannelBind creates a channel for the peerAddress only. So if there is a
            // chance that ChannelBind will be used, have a Channel instance per peerAddress and CreatePermission more often than really necessary (as a side effect).
            if (channelDataSession != null) {
                return this.peerAddress.equals(peerAddress);
            } else {
                return this.peerAddress.getAddress().equals(peerAddress.getAddress());
            }
        }

        /**
         * Sends a specific data through this Channel to a specific peer TransportAddress.
         *
         * @param data the data to be sent
         * @param peerAddress the TransportAddress of the peer to which the data is to be sent
         * @throws StunException if anything goes wrong while sending the specified data to the specified peer address
         */
        public void send(IoBuffer data, TransportAddress peerAddress) throws StunException {
            logger.debug("send: {} to {}", data, peerAddress);
            if (channelDataIsPreferred && (channelNumber != CHANNEL_NUMBER_NOT_SPECIFIED) && channelNumberIsConfirmed) {
                int length = data.limit();
                int channelDataLength = CHANNELDATA_CHANNELNUMBER_LENGTH + CHANNELDATA_LENGTH_LENGTH + length;
                if (channelDataBuffer == null) {
                    channelDataBuffer = IoBuffer.allocate(channelDataLength);
                } else if (channelDataLength > channelDataBuffer.limit()) {
                    channelDataBuffer.capacity(channelDataLength);
                }
                // Channel Number
                channelDataBuffer.put((byte) (channelNumber >> 8));
                channelDataBuffer.put((byte) (channelNumber & 0xFF));
                // Length
                channelDataBuffer.put((byte) (length >> 8));
                channelDataBuffer.put((byte) (length & 0xFF));
                // Application Data
                channelDataBuffer.put(data);
                // flip it so we can send it
                channelDataBuffer.flip();
                // send it out
                if (Transport.UDP.equals(peerAddress.getTransport())) {
                    channelDataSession.write(channelDataBuffer, peerAddress);
                } else {
                    channelDataSession.write(channelDataBuffer);
                }
            } else {
                byte[] transactionID = TransactionID.createNewTransactionID().getBytes();
                // data array won't contain the channel number + length
                Indication sendIndication = MessageFactory.createSendIndication(peerAddress, data.array(), transactionID);
                sendIndication.setTransactionID(transactionID);
                turnCandidateHarvest.harvester.getStunStack().sendIndication(sendIndication, turnCandidateHarvest.harvester.stunServer, turnCandidateHarvest.hostCandidate.getTransportAddress());
            }
        }

        /**
         * Sets the indicator which determines whether this Channel is bound/installed.
         *
         * @param bound true if this Channel is to be marked as bound/installed; otherwise, false
         * @param boundTransactionID an array of bytes which represents the ID of the transaction with which the confirmation about the
         * binding/installing has arrived
         */
        public void setBound(boolean bound, byte[] boundTransactionID) {
            logger.debug("setBound: {} transaction id: {}", bound, TransactionID.toString(boundTransactionID));
            if (bindingTransactionID != null) {
                bindingTransactionID = null;
                this.bound = bound;
            }
        }

        /**
         * Sets the indicator which determines whether this Channel is set to prefer sending DatagramPackets using TURN ChannelData
         * messages instead of Send indications.
         *
         * @param channelDataIsPreferred true if this Channel is to be set to prefer sending DatagramPackets using TURN
         * ChannelData messages instead of Send indications
         */
        public void setChannelDataIsPreferred(boolean channelDataIsPreferred) {
            this.channelDataIsPreferred = channelDataIsPreferred;
        }

        /**
         * Sets the indicator which determines whether the associated TURN server has confirmed the allocation of the channelNumber of
         * this Channel by us receiving a success Response to our ChannelBind Request.
         *
         * @param channelNumberIsConfirmed true if allocation of the channel number has been confirmed by a success Response to
         * our ChannelBind Request
         * @param channelNumberIsConfirmedTransactionID an array of bytes which represents the ID of the transaction with which
         * the confirmation about the allocation of the channel number has arrived
         */
        public void setChannelNumberIsConfirmed(boolean channelNumberIsConfirmed, byte[] channelNumberIsConfirmedTransactionID) {
            logger.debug("setChannelNumberIsConfirmed: {} {}", channelNumberIsConfirmed, channelNumberIsConfirmedTransactionID);
            this.channelNumberIsConfirmed = channelNumberIsConfirmed;
        }

    }

}
