/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal. Copyright @ 2015 Atlassian Pty Ltd Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or
 * agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under the License.
 */
package org.ice4j.socket;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.ice4j.StunException;
import org.ice4j.StunMessageEvent;
import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.attribute.Attribute;
import org.ice4j.attribute.DataAttribute;
import org.ice4j.attribute.XorPeerAddressAttribute;
import org.ice4j.ice.RelayedCandidate;
import org.ice4j.ice.harvest.TurnCandidateHarvest;
import org.ice4j.message.Indication;
import org.ice4j.message.Message;
import org.ice4j.message.MessageFactory;
import org.ice4j.message.Request;
import org.ice4j.message.Response;
import org.ice4j.socket.filter.DatagramPacketFilter;
import org.ice4j.socket.filter.StunDatagramPacketFilter;
import org.ice4j.stack.MessageEventHandler;
import org.ice4j.stack.TransactionID;
import org.ice4j.util.DatagramUtil;

/**
 * Represents an application-purposed (as opposed to an ICE-specific) DatagramSocket for a RelayedCandidate harvested by a
 * TurnCandidateHarvest (and its associated TurnCandidateHarvester, of course).
 * RelayedCandidateDatagramSocket is associated with a successful Allocation on a TURN server and implements sends and receives through it
 * using TURN messages to and from that TURN server.
 *
 * @author Lyubomir Marinov
 */
public class RelayedCandidateDatagramSocket extends DatagramSocket implements MessageEventHandler {

    /**
     * The Logger used by the RelayedCandidateDatagramSocket
     * class and its instances for logging output.
     */
    private static final Logger logger = Logger.getLogger(RelayedCandidateDatagramSocket.class.getName());

    /**
     * The constant which represents a channel number value signaling that no
     * channel number has been explicitly specified.
     */
    private static final char CHANNEL_NUMBER_NOT_SPECIFIED = 0;

    /**
     * The length in bytes of the Channel Number field of a TURN ChannelData
     * message.
     */
    private static final int CHANNELDATA_CHANNELNUMBER_LENGTH = 2;

    /**
     * The length in bytes of the Length field of a TURN ChannelData message.
     */
    private static final int CHANNELDATA_LENGTH_LENGTH = 2;

    /**
     * The maximum channel number which is valid for TURN ChannelBind
     * Request.
     */
    private static final char MAX_CHANNEL_NUMBER = 0x7FFF;

    /**
     * The minimum channel number which is valid for TURN ChannelBind
     * Requests.
     */
    private static final char MIN_CHANNEL_NUMBER = 0x4000;

    /**
     * The lifetime in milliseconds of a TURN permission created using a
     * CreatePermission request.
     */
    private static final long PERMISSION_LIFETIME = 300 /* seconds */* 1000L;

    /**
     * The time in milliseconds before a TURN permission expires that a
     * RelayedCandidateDatagramSocket is to try to reinstall it.
     */
    private static final long PERMISSION_LIFETIME_LEEWAY = 60 /* seconds */* 1000L;

    /**
     * The DatagramSocket through which this
     * RelayedCandidateDatagramSocket actually sends and receives the
     * data it has been asked to {@link #send(DatagramPacket)} and
     * {@link #receive(DatagramPacket)}. Since data can be exchanged with a TURN
     * server using STUN messages (i.e. Send and Data indications),
     * RelayedCandidateDatagramSocket may send and receive data using
     * the associated StunStack and not channelDataSocket.
     * However, using channelDataSocket is supposed to be more
     * efficient than using StunStack.
     */
    private final DatagramSocket channelDataSocket;

    /**
     * The list of per-peer Channels through which this
     * RelayedCandidateDatagramSockets relays data send to it to
     * peer TransportAddresses.
     */
    private final List<Channel> channels = new LinkedList<>();

    /**
     * The indicator which determines whether this instance has started executing or has executed its {@link #close()} method.
     */
    private boolean closed;

    /**
     * The DatagramPacketFilter which is able to determine whether a specific DatagramPacket sent through a
     * RelayedCandidateDatagramSocket is part of the ICE connectivity checks. The recognizing is necessary because RFC 5245 says that "it is
     * RECOMMENDED that the agent defer creation of a TURN channel until ICE completes."
     */
    private static final DatagramPacketFilter connectivityCheckRecognizer = new StunDatagramPacketFilter();

    /**
     * The next free channel number to be returned by {@link #getNextChannelNumber()} and marked as non-free.
     */
    private char nextChannelNumber = MIN_CHANNEL_NUMBER;

    /**
     * The DatagramPackets which are to be received through this DatagramSocket upon calls to its
     * {@link #receive(DatagramPacket)} method. They have been received from the TURN server in the form of Data indications.
     */
    private final List<DatagramPacket> packetsToReceive = new LinkedList<>();

    /**
     * The DatagramSockets which have been sent through this DatagramSocket using its {@link #send(DatagramPacket)} method
     * and which are to be relayed through its associated TURN server in the form of Send indications.
     */
    private final List<DatagramPacket> packetsToSend = new LinkedList<>();

    /**
     * The Thread which receives DatagramPackets from {@link #channelDataSocket} and queues them in {@link #packetsToReceive}.
     */
    private Thread receiveChannelDataThread;

    /**
     * The RelayedCandidate which uses this instance as the value of its socket property.
     */
    private final RelayedCandidate relayedCandidate;

    /**
     * The Thread which is to send the {@link #packetsToSend} to the associated TURN server.
     */
    private Thread sendThread;

    /**
     * The TurnCandidateHarvest which has harvested {@link #relayedCandidate}.
     */
    private final TurnCandidateHarvest turnCandidateHarvest;

    /**
     * Initializes a new RelayedCandidateDatagramSocket instance which is to be the socket of a specific RelayedCandidate
     * harvested by a specific TurnCandidateHarvest.
     *
     * @param relayedCandidate the RelayedCandidate which is to use the new instance as the value of its socket property
     * @param turnCandidateHarvest the TurnCandidateHarvest which has harvested relayedCandidate
     * @throws SocketException if anything goes wrong while initializing the new RelayedCandidateDatagramSocket instance
     */
    public RelayedCandidateDatagramSocket(RelayedCandidate relayedCandidate, TurnCandidateHarvest turnCandidateHarvest) throws SocketException {
        super(/* bindaddr */(SocketAddress) null);
        this.relayedCandidate = relayedCandidate;
        this.turnCandidateHarvest = turnCandidateHarvest;
        this.turnCandidateHarvest.harvester.getStunStack().addIndicationListener(this.turnCandidateHarvest.hostCandidate.getTransportAddress(), this);
        /* XXX check back on this when we do TURN
        IceSocketWrapper hostSocket = this.turnCandidateHarvest.hostCandidate.getCandidateIceSocketWrapper();
        if (hostSocket instanceof MultiplexingDatagramSocket) {
            channelDataSocket = ((MultiplexingDatagramSocket) hostSocket).getSocket(new TurnDatagramPacketFilter(this.turnCandidateHarvest.harvester.stunServer) {
                @Override
                public boolean accept(DatagramPacket p) {
                    return channelDataSocketAccept(p);
                }

                @Override
                protected boolean acceptMethod(char method) {
                    return channelDataSocketAcceptMethod(method);
                }
            });
        } else {
            channelDataSocket = null;
        }
        */
        channelDataSocket = null;
    }

    /**
     * Determines whether a specific DatagramPacket is accepted by {@link #channelDataSocket} (i.e. whether channelDataSocket
     * understands p and p is meant to be received by channelDataSocket).
     *
     * @param p the DatagramPacket which is to be checked whether it is accepted by channelDataSocket
     * @return true if channelDataSocket accepts p (i.e. channelDataSocket understands p and p is
     * meant to be received by channelDataSocket); otherwise, false
     */
    @SuppressWarnings("unused")
    private boolean channelDataSocketAccept(DatagramPacket p) {
        // Is it from our TURN server?
        if (turnCandidateHarvest.harvester.stunServer.equals(p.getSocketAddress())) {
            int pLength = p.getLength();

            if (pLength >= (CHANNELDATA_CHANNELNUMBER_LENGTH + CHANNELDATA_LENGTH_LENGTH)) {
                byte[] pData = p.getData();
                int pOffset = p.getOffset();

                /*
                 * The first two bits should be 0b01 because of the current channel number range 0x4000 - 0x7FFE. But 0b10 and 0b11 which are currently reserved and may be used in
                 * the future to extend the range of channel numbers.
                 */
                if ((pData[pOffset] & 0xC0) != 0) {
                    /*
                     * Technically, we cannot create a DatagramPacket from a ChannelData message with a Channel Number we do not know about. But determining that we know the value
                     * of the Channel Number field may be too much of an unnecessary performance penalty and it may be unnecessary because the message comes from our TURN server
                     * and it looks like a ChannelData message already.
                     */
                    pOffset += CHANNELDATA_CHANNELNUMBER_LENGTH;
                    pLength -= CHANNELDATA_CHANNELNUMBER_LENGTH;

                    int length = ((pData[pOffset++] << 8) | (pData[pOffset++] & 0xFF));

                    int padding = ((length % 4) > 0) ? 4 - (length % 4) : 0;

                    /*
                     * The Length field specifies the length in bytes of the Application Data field. The Length field does not include the padding that is sometimes present in the
                     * data of the DatagramPacket.
                     */
                    return length == pLength - padding - CHANNELDATA_LENGTH_LENGTH || length == pLength - CHANNELDATA_LENGTH_LENGTH;
                }
            }
        }
        return false;
    }

    /**
     * Determines whether {@link #channelDataSocket} accepts DatagramPackets which represent STUN messages with a specific
     * method.
     *
     * @param method the method of the STUN messages represented in DatagramPackets which is accepted by channelDataSocket
     * @return true if channelDataSocket accepts DatagramPackets which represent STUN messages with the specified
     * method; otherwise, false
     */
    @SuppressWarnings("unused")
    private boolean channelDataSocketAcceptMethod(char method) {
        // Accept only ChannelData messages for now. ChannelData messages are not STUN messages so they do not have a method associated with them.
        return false;
    }

    /**
     * Closes this datagram socket.
     *
     * @see DatagramSocket#close()
     */
    @Override
    public void close() {
        synchronized (this) {
            if (this.closed)
                return;
            else
                this.closed = true;
        }
        synchronized (packetsToReceive) {
            packetsToReceive.notifyAll();
        }
        synchronized (packetsToSend) {
            packetsToSend.notifyAll();
        }
        turnCandidateHarvest.harvester.getStunStack().removeIndicationListener(turnCandidateHarvest.hostCandidate.getTransportAddress(), this);
        turnCandidateHarvest.close(this);
        super.close();
    }

    /**
     * Creates {@link #receiveChannelDataThread} which is to receive DatagramPackets from {@link #channelDataSocket} and queue them
     * in {@link #packetsToReceive}.
     */
    private void createReceiveChannelDataThread() {
        receiveChannelDataThread = new Thread() {
            @Override
            public void run() {
                boolean done = false;

                try {
                    runInReceiveChannelDataThread();
                    done = true;
                } catch (SocketException sex) {
                    done = true;
                } finally {
                    // If receiveChannelDataThread is dying and this RelayedCandidateDatagramSocket is not closed, then spawn a new 
                    // receiveChannelDataThread.
                    synchronized (packetsToReceive) {
                        if (receiveChannelDataThread == Thread.currentThread())
                            receiveChannelDataThread = null;
                        if ((receiveChannelDataThread == null) && !closed && !done)
                            createReceiveChannelDataThread();
                    }
                }
            }
        };
        receiveChannelDataThread.start();
    }

    /**
     * Creates {@link #sendThread} which is to send {@link #packetsToSend} to the associated TURN server.
     */
    private void createSendThread() {
        sendThread = new Thread() {
            @Override
            public void run() {
                try {
                    runInSendThread();
                } finally {
                    /*
                     * If sendThread is dying and there are packetsToSend, then spawn a new sendThread.
                     */
                    synchronized (packetsToSend) {
                        if (sendThread == Thread.currentThread())
                            sendThread = null;
                        if ((sendThread == null) && !closed && !packetsToSend.isEmpty())
                            createSendThread();
                    }
                }
            }
        };
        sendThread.start();
    }

    /**
     * Gets the local address to which the socket is bound.
     * RelayedCandidateDatagramSocket returns the address of
     * its localSocketAddress.
     * <p>
     * If there is a security manager, its checkConnect method is first
     * called with the host address and -1 as its arguments to see if
     * the operation is allowed.
     * <br>
     *
     * @return the local address to which the socket is bound, or an
     * InetAddress representing any local address if either the socket
     * is not bound, or the security manager checkConnect method does
     * not allow the operation
     * @see #getLocalSocketAddress()
     * @see DatagramSocket#getLocalAddress()
     */
    @Override
    public InetAddress getLocalAddress() {
        return getLocalSocketAddress().getAddress();
    }

    /**
     * Returns the port number on the local host to which this socket is bound.
     * RelayedCandidateDatagramSocket returns the port of its
     * localSocketAddress.
     *
     * @return the port number on the local host to which this socket is bound
     * @see #getLocalSocketAddress()
     * @see DatagramSocket#getLocalPort()
     */
    @Override
    public int getLocalPort() {
        return getLocalSocketAddress().getPort();
    }

    /**
     * Returns the address of the endpoint this socket is bound to, or
     * null if it is not bound yet. Since
     * RelayedCandidateDatagramSocket represents an
     * application-purposed DatagramSocket relaying data to and from a
     * TURN server, the localSocketAddress is the
     * transportAddress of the respective RelayedCandidate.
     *
     * @return a SocketAddress representing the local endpoint of this
     * socket, or null if it is not bound yet
     * @see DatagramSocket#getLocalSocketAddress()
     */
    @Override
    public InetSocketAddress getLocalSocketAddress() {
        return getRelayedCandidate().getTransportAddress();
    }

    /**
     * Gets the next free channel number to be allocated to a Channel
     * and marked as non-free.
     *
     * @return the next free channel number to be allocated to a
     * Channel and marked as non-free.
     */
    private char getNextChannelNumber() {
        char nextChannelNumber;

        if (this.nextChannelNumber > MAX_CHANNEL_NUMBER)
            nextChannelNumber = CHANNEL_NUMBER_NOT_SPECIFIED;
        else {
            nextChannelNumber = this.nextChannelNumber;
            this.nextChannelNumber++;
        }
        return nextChannelNumber;
    }

    /**
     * Gets the RelayedCandidate which uses this instance as the value
     * of its socket property.
     *
     * @return the RelayedCandidate which uses this instance as the
     * value of its socket property
     */
    public final RelayedCandidate getRelayedCandidate() {
        return relayedCandidate;
    }

    /**
     * Notifies this MessageEventHandler that a specific STUN message
     * has been received, parsed and is ready for delivery.
     * RelayedCandidateDatagramSocket handles STUN indications sent
     * from the associated TURN server and received at the associated local
     * TransportAddress.
     *
     * @param e a StunMessageEvent which encapsulates the received STUN
     * message
     */
    public void handleMessageEvent(StunMessageEvent e) {
        /*
         * Is it meant for us? (It should be because RelayedCandidateDatagramSocket registers for STUN indications received at the associated local TransportAddress only.)
         */
        if (!turnCandidateHarvest.hostCandidate.getTransportAddress().equals(e.getLocalAddress()))
            return;
        // Is it from our TURN server?
        if (!turnCandidateHarvest.harvester.stunServer.equals(e.getRemoteAddress()))
            return;

        Message message = e.getMessage();
        char messageType = message.getMessageType();

        if (messageType != Message.DATA_INDICATION)
            return;

        /*
         * RFC 5766: When the client receives a Data indication, it checks that the Data indication contains both an XOR-PEER-ADDRESS and a DATA attribute, and discards the
         * indication if it does not.
         */
        XorPeerAddressAttribute peerAddressAttribute = (XorPeerAddressAttribute) message.getAttribute(Attribute.Type.XOR_PEER_ADDRESS);

        if (peerAddressAttribute == null)
            return;

        DataAttribute dataAttribute = (DataAttribute) message.getAttribute(Attribute.Type.DATA);

        if (dataAttribute == null)
            return;

        TransportAddress peerAddress = peerAddressAttribute.getAddress(message.getTransactionID());

        if (peerAddress == null)
            return;

        byte[] data = dataAttribute.getData();

        if (data == null)
            return;

        DatagramPacket packetToReceive;

        try {
            packetToReceive = new DatagramPacket(data, 0, data.length, peerAddress);
        } catch (Throwable t) {
            /*
             * The signature of the DatagramPacket constructor was changed in JDK 8 to not declare that it may throw a SocketException.
             */
            if (t instanceof SocketException) {
                packetToReceive = null;
            } else if (t instanceof Error) {
                throw (Error) t;
            } else if (t instanceof RuntimeException) {
                throw (RuntimeException) t;
            } else {
                /*
                 * Unfortunately, we cannot re-throw it. Anyway, it was unlikely to occur on JDK 7.
                 */
                if (t instanceof InterruptedException) {
                    Thread.currentThread().interrupt();
                }
                packetToReceive = null;
            }
        }
        if (packetToReceive != null) {
            synchronized (packetsToReceive) {
                packetsToReceive.add(packetToReceive);
                packetsToReceive.notifyAll();
            }
        }
    }

    /**
     * Notifies this RelayedCandidateDatagramSocket that a specific
     * Request it has sent has either failed or received a STUN error
     * Response.
     *
     * @param response the Response which responds to request
     * @param request the Request sent by this instance to which
     * response responds
     * @return true if the failure or error condition has been handled
     * and the caller should assume this instance has recovered from it;
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
            default:
                break;
        }
        return false;
    }

    /**
     * Notifies this RelayedCandidateDatagramSocket that a specific
     * Request it has sent has received a STUN success
     * Response.
     *
     * @param response the Response which responds to request
     * @param request the Request sent by this instance to which
     * response responds
     */
    public void processSuccess(Response response, Request request) {
        switch (request.getMessageType()) {
            case Message.CHANNELBIND_REQUEST:
                setChannelNumberIsConfirmed(request, true);
                break;
            case Message.CREATEPERMISSION_REQUEST:
                setChannelBound(request, true);
                break;
            default:
                break;
        }
    }

    /**
     * Receives a datagram packet from this socket. When this method returns, the DatagramPacket's buffer is filled with the data received.
     * The datagram packet also contains the sender's IP address, and the port number on the sender's machine.
     *
     * @param p the DatagramPacket into which to place the incoming data
     * @throws IOException if an I/O error occurs
     * @see DatagramSocket#receive(DatagramPacket)
     */
    @Override
    public void receive(DatagramPacket p) throws IOException {
        synchronized (packetsToReceive) {
            do {
                // According to the javadoc of DatagramSocket#close(), any thread currently blocked in #receive(DatagramPacket) upon this socket will throw a SocketException
                if (closed) {
                    throw new SocketException(RelayedCandidateDatagramSocket.class.getSimpleName() + " has been closed.");
                } else if (packetsToReceive.isEmpty()) {
                    try {
                        packetsToReceive.wait();
                    } catch (InterruptedException iex) {
                    }
                } else {
                    DatagramPacket packetToReceive = packetsToReceive.remove(0);
                    DatagramUtil.copy(packetToReceive, p);
                    packetsToReceive.notifyAll();
                    break;
                }
            } while (true);
        }
    }

    /**
     * Runs in {@link #receiveChannelDataThread} to receive
     * DatagramPackets from {@link #channelDataSocket} and queue them
     * in {@link #packetsToReceive}.
     *
     * @throws SocketException if anything goes wrong while receiving
     * DatagramPackets from {@link #channelDataSocket} and
     * {@link #receiveChannelDataThread} is to no longer exist
     */
    private void runInReceiveChannelDataThread() throws SocketException {
        DatagramPacket p = null;

        while (!closed) {
            // read one datagram a time
            int receiveBufferSize = 1500;

            if (p == null) {
                p = new DatagramPacket(new byte[receiveBufferSize], receiveBufferSize);
            } else {
                byte[] pData = p.getData();

                if ((pData == null) || (pData.length < receiveBufferSize))
                    p.setData(new byte[receiveBufferSize]);
                else
                    p.setLength(receiveBufferSize);
            }

            try {
                channelDataSocket.receive(p);
            } catch (Throwable t) {
                if (t instanceof ThreadDeath) {
                    // Death is the end of life no matter what.
                    throw (ThreadDeath) t;
                } else if (t instanceof SocketException) {
                    // If the channelDataSocket has gone unusable, put an end to receiving from it.
                    throw (SocketException) t;
                } else {
                    if (logger.isLoggable(Level.WARNING)) {
                        logger.log(Level.WARNING, "Ignoring error while receiving from" + " ChannelData socket", t);
                    }
                    continue;
                }
            }

            /*
             * We've been waiting in #receive so make sure we're still to continue just in case.
             */
            if (closed)
                break;

            int channelDataLength = p.getLength();

            if (channelDataLength < (CHANNELDATA_CHANNELNUMBER_LENGTH + CHANNELDATA_LENGTH_LENGTH))
                continue;

            byte[] channelData = p.getData();
            int channelDataOffset = p.getOffset();
            char channelNumber = (char) ((channelData[channelDataOffset++] << 8) | (channelData[channelDataOffset++] & 0xFF));

            channelDataLength -= CHANNELDATA_CHANNELNUMBER_LENGTH;

            char length = (char) ((channelData[channelDataOffset++] << 8) | (channelData[channelDataOffset++] & 0xFF));

            channelDataLength -= CHANNELDATA_LENGTH_LENGTH;
            if (length > channelDataLength)
                continue;

            TransportAddress peerAddress = null;

            synchronized (packetsToSend) {
                int channelCount = channels.size();

                for (int channelIndex = 0; channelIndex < channelCount; channelIndex++) {
                    Channel channel = channels.get(channelIndex);

                    if (channel.channelNumberEquals(channelNumber)) {
                        peerAddress = channel.peerAddress;
                        break;
                    }
                }
            }
            if (peerAddress == null)
                continue;

            byte[] data = new byte[length];

            System.arraycopy(channelData, channelDataOffset, data, 0, length);

            DatagramPacket packetToReceive = new DatagramPacket(data, 0, length, peerAddress);

            synchronized (packetsToReceive) {
                packetsToReceive.add(packetToReceive);
                packetsToReceive.notifyAll();
            }
        }
    }

    /**
     * Runs in {@link #sendThread} to send {@link #packetsToSend} to the
     * associated TURN server.
     */
    private void runInSendThread() {
        synchronized (packetsToSend) {
            while (!closed) {
                if (packetsToSend.isEmpty()) {
                    try {
                        packetsToSend.wait();
                    } catch (InterruptedException iex) {
                    }
                    continue;
                }

                int packetToSendCount = packetsToSend.size();

                for (int packetToSendIndex = 0; packetToSendIndex < packetToSendCount; packetToSendIndex++) {
                    DatagramPacket packetToSend = packetsToSend.get(packetToSendIndex);

                    /*
                     * Get a channel to the peer which is to receive the packetToSend.
                     */
                    int channelCount = channels.size();
                    TransportAddress peerAddress = new TransportAddress(packetToSend.getAddress(), packetToSend.getPort(), Transport.UDP);
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

                    /*
                     * RFC 5245 says that "it is RECOMMENDED that the agent defer creation of a TURN channel until ICE completes." RelayedCandidateDatagramSocket is not explicitly
                     * told from the outside that ICE has completed so it tries to determine it by assuming that connectivity checks send only STUN messages and ICE has completed
                     * by the time a non-STUN message is to be sent.
                     */
                    boolean forceBind = false;

                    if ((channelDataSocket != null) && !channel.getChannelDataIsPreferred() && !connectivityCheckRecognizer.accept(packetToSend)) {
                        channel.setChannelDataIsPreferred(true);
                        forceBind = true;
                    }

                    /*
                     * Either bind the channel or send the packetToSend through it.
                     */
                    if (!forceBind && channel.isBound()) {
                        packetsToSend.remove(packetToSendIndex);
                        try {
                            channel.send(packetToSend, peerAddress);
                        } catch (StunException sex) {
                            if (logger.isLoggable(Level.INFO)) {
                                logger.log(Level.INFO, "Failed to send through " + RelayedCandidateDatagramSocket.class.getSimpleName() + " channel.", sex);
                            }
                        }
                        break;
                    } else if (forceBind || !channel.isBinding()) {
                        try {
                            channel.bind();
                        } catch (StunException sex) {
                            if (logger.isLoggable(Level.INFO)) {
                                logger.log(Level.INFO, "Failed to bind " + RelayedCandidateDatagramSocket.class.getSimpleName() + " channel.", sex);
                            }
                            /*
                             * Well, it may not be the fault of the packetToSend but it happened while we were trying to send it and we don't have a way to report an error so just
                             * drop packetToSend in order to change something and not just go again trying the same thing.
                             */
                            packetsToSend.remove(packetToSendIndex);
                            break;
                        }
                        /*
                         * If the Channel was bound but #bind() was forced on it, we cannot continue with the next packetToSend because it may be for the same Channel and then
                         * #bind() will not be forced and the Channel will be bound already so the send order of the packetsToSend will be disrupted.
                         */
                        if (forceBind)
                            break;
                    }
                }

                /*
                 * If no packetToSend has been sent by the current iteration, then we must be waiting for some condition to change in order to be able to send.
                 */
                if (packetsToSend.size() == packetToSendCount) {
                    try {
                        packetsToSend.wait();
                    } catch (InterruptedException iex) {
                    }
                }
            }
        }
    }

    /**
     * Sends a datagram packet from this socket. The DatagramPacket
     * includes information indicating the data to be sent, its length, the IP
     * address of the remote host, and the port number on the remote host.
     *
     * @param p the DatagramPacket to be sent
     * @throws IOException if an I/O error occurs
     * @see DatagramSocket#send(DatagramPacket)
     */
    @Override
    public void send(DatagramPacket p) throws IOException {
        synchronized (packetsToSend) {
            if (closed) {
                throw new IOException(RelayedCandidateDatagramSocket.class.getSimpleName() + " has been closed.");
            } else {
                packetsToSend.add(DatagramUtil.clone(p, true));
                if (sendThread == null)
                    createSendThread();
                else
                    packetsToSend.notifyAll();
            }
        }
    }

    /**
     * Sets the bound property of a Channel the installation
     * of which has been attempted by sending a specific Request.
     *
     * @param request the Request which has been attempted in order to
     * install a Channel
     * @param bound true if the bound property of the
     * Channel is to be set to true; otherwise, false
     */
    private void setChannelBound(Request request, boolean bound) {
        XorPeerAddressAttribute peerAddressAttribute = (XorPeerAddressAttribute) request.getAttribute(Attribute.Type.XOR_PEER_ADDRESS);
        byte[] transactionID = request.getTransactionID();
        TransportAddress peerAddress = peerAddressAttribute.getAddress(transactionID);

        synchronized (packetsToSend) {
            int channelCount = channels.size();

            for (int channelIndex = 0; channelIndex < channelCount; channelIndex++) {
                Channel channel = channels.get(channelIndex);

                if (channel.peerAddressEquals(peerAddress)) {
                    channel.setBound(bound, transactionID);
                    packetsToSend.notifyAll();
                    break;
                }
            }
        }
    }

    /**
     * Sets the channelNumberIsConfirmed property of a Channel
     * which has attempted to allocate a specific channel number by sending a
     * specific ChannelBind Request.
     *
     * @param request the Request which has been sent to allocate a
     * specific channel number for a Channel
     * @param channelNumberIsConfirmed true if the channel number has
     * been successfully allocated; otherwise, false
     */
    private void setChannelNumberIsConfirmed(Request request, boolean channelNumberIsConfirmed) {
        XorPeerAddressAttribute peerAddressAttribute = (XorPeerAddressAttribute) request.getAttribute(Attribute.Type.XOR_PEER_ADDRESS);
        byte[] transactionID = request.getTransactionID();
        TransportAddress peerAddress = peerAddressAttribute.getAddress(transactionID);

        synchronized (packetsToSend) {
            int channelCount = channels.size();

            for (int channelIndex = 0; channelIndex < channelCount; channelIndex++) {
                Channel channel = channels.get(channelIndex);

                if (channel.peerAddressEquals(peerAddress)) {
                    channel.setChannelNumberIsConfirmed(channelNumberIsConfirmed, transactionID);
                    packetsToSend.notifyAll();
                    break;
                }
            }
        }
    }

    /**
     * Represents a channel which relays data sent through this
     * RelayedCandidateDatagramSocket to a specific
     * TransportAddress via the TURN server associated with this
     * RelayedCandidateDatagramSocket.
     */
    private class Channel {
        /**
         * The time stamp in milliseconds at which {@link #bindingTransactionID}
         * has been used to bind/install this Channel.
         */
        private long bindingTimeStamp = -1;

        /**
         * The ID of the transaction with which a CreatePermission
         * Request has been sent to bind/install this Channel.
         */
        private byte[] bindingTransactionID;

        /**
         * The indication which determines whether a confirmation has been
         * received that this Channel has been bound.
         */
        private boolean bound = false;

        /**
         * The value of the data property of
         * {@link #channelDataPacket}.
         */
        private byte[] channelData;

        /**
         * The indicator which determines whether this Channel is set
         * to prefer sending DatagramPackets using TURN ChannelData
         * messages instead of Send indications.
         */
        private boolean channelDataIsPreferred = false;

        /**
         * The DatagramPacket in which this Channel sends TURN
         * ChannelData messages through
         * {@link RelayedCandidateDatagramSocket#channelDataSocket}.
         */
        private DatagramPacket channelDataPacket;

        /**
         * The TURN channel number of this Channel which is to be or
         * has been allocated using a ChannelBind Request.
         */
        private char channelNumber = CHANNEL_NUMBER_NOT_SPECIFIED;

        /**
         * The indicator which determines whether the associated TURN server has
         * confirmed the allocation of {@link #channelNumber} by us receiving a
         * success Response to our ChannelBind Request.
         */
        private boolean channelNumberIsConfirmed;

        /**
         * The TransportAddress of the peer to which this
         * Channel provides a permission of this
         * RelayedCandidateDatagramSocket to send data to.
         */
        public final TransportAddress peerAddress;

        /**
         * Initializes a new Channel instance which is to provide this
         * RelayedCandidateDatagramSocket with a permission to send
         * to a specific peer TransportAddress.
         *
         * @param peerAddress the TransportAddress of the peer to which
         * the new instance is to provide a permission of this
         * RelayedCandidateDatagramSocket to send data to
         */
        public Channel(TransportAddress peerAddress) {
            this.peerAddress = peerAddress;
        }

        /**
         * Binds/installs this channel so that it provides this
         * RelayedCandidateDatagramSocket with a permission to send
         * data to the TransportAddress associated with this instance.
         *
         * @throws StunException if anything goes wrong while binding/installing
         * this channel
         */
        public void bind() throws StunException {
            byte[] createPermissionTransactionID = TransactionID.createNewTransactionID().getBytes();
            Request createPermissionRequest = MessageFactory.createCreatePermissionRequest(peerAddress, createPermissionTransactionID);

            createPermissionRequest.setTransactionID(createPermissionTransactionID);
            turnCandidateHarvest.sendRequest(RelayedCandidateDatagramSocket.this, createPermissionRequest);

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

                    /*
                     * We have to be prepared to receive ChannelData messages from the TURN server as soon as we've sent the ChannelBind request and before we've received a success
                     * response to it.
                     */
                    synchronized (packetsToReceive) {
                        if (!closed && (receiveChannelDataThread == null))
                            createReceiveChannelDataThread();
                    }

                    turnCandidateHarvest.sendRequest(RelayedCandidateDatagramSocket.this, channelBindRequest);
                }
            }
        }

        /**
         * Determines whether the channel number of this Channel is
         * value equal to a specific channel number.
         *
         * @param channelNumber the channel number to be compared to the channel
         * number of this Channel for value equality
         * @return true if the specified channelNumber is
         * equal to the channel number of this Channel
         */
        public boolean channelNumberEquals(char channelNumber) {
            return (this.channelNumber == channelNumber);
        }

        /**
         * Gets the indicator which determines whether this Channel is
         * set to prefer sending DatagramPackets using TURN ChannelData
         * messages instead of Send indications.
         *
         * @return the indicator which determines whether this Channel
         * is set to prefer sending DatagramPackets using TURN
         * ChannelData messages instead of Send indications
         */
        public boolean getChannelDataIsPreferred() {
            return channelDataIsPreferred;
        }

        /**
         * Gets the indicator which determines whether this instance has started
         * binding/installing itself and has not received a confirmation that it
         * has succeeded in doing so yet.
         *
         * @return true if this instance has started binding/installing
         * itself and has not received a confirmation that it has succeeded in
         * doing so yet; otherwise, false
         */
        public boolean isBinding() {
            return (bindingTransactionID != null);
        }

        /**
         * Gets the indication which determines whether this instance is
         * currently considered bound/installed.
         *
         * @return true if this instance is currently considered
         * bound/installed; otherwise, false
         */
        public boolean isBound() {
            if ((bindingTimeStamp == -1) || (bindingTimeStamp + PERMISSION_LIFETIME - PERMISSION_LIFETIME_LEEWAY) < System.currentTimeMillis())
                return false;
            return (bindingTransactionID == null) && bound;
        }

        /**
         * Determines whether the peerAddress property of this instance
         * is considered by this Channel to be equal to a specific
         * TransportAddress.
         *
         * @param peerAddress the TransportAddress which is to be
         * checked for equality (as defined by this Channel and not
         * necessarily by the TransportAddress class)
         * @return true if the specified TransportAddress is
         * considered by this Channel to be equal to its
         * peerAddress property; otherwise, false
         */
        public boolean peerAddressEquals(TransportAddress peerAddress) {
            /*
             * CreatePermission installs a permission for the IP address and the port is ignored. But ChannelBind creates a channel for the peerAddress only. So if there is a
             * chance that ChannelBind will be used, have a Channel instance per peerAddress and CreatePermission more often than really necessary (as a side effect).
             */
            if (channelDataSocket != null)
                return this.peerAddress.equals(peerAddress);
            else {
                return this.peerAddress.getAddress().equals(peerAddress.getAddress());
            }
        }

        /**
         * Sends a specific DatagramPacket through this
         * Channel to a specific peer TransportAddress.
         *
         * @param p the DatagramPacket to be sent
         * @param peerAddress the TransportAddress of the peer to which
         * the DatagramPacket is to be sent
         * @throws StunException if anything goes wrong while sending the
         * specified DatagramPacket to the specified peer
         * TransportAddress
         */
        public void send(DatagramPacket p, TransportAddress peerAddress) throws StunException {
            byte[] pData = p.getData();
            int pOffset = p.getOffset();
            int pLength = p.getLength();
            byte[] data;

            if ((pOffset == 0) && (pLength == pData.length))
                data = pData;
            else {
                data = new byte[pLength];
                System.arraycopy(pData, pOffset, data, 0, pLength);
            }

            if (channelDataIsPreferred && (channelNumber != CHANNEL_NUMBER_NOT_SPECIFIED) && channelNumberIsConfirmed) {
                char length = (char) data.length;
                int channelDataLength = CHANNELDATA_CHANNELNUMBER_LENGTH + CHANNELDATA_LENGTH_LENGTH + length;

                if ((channelData == null) || (channelData.length < channelDataLength)) {
                    channelData = new byte[channelDataLength];
                    if (channelDataPacket != null)
                        channelDataPacket.setData(channelData);
                }

                // Channel Number
                channelData[0] = (byte) (channelNumber >> 8);
                channelData[1] = (byte) (channelNumber & 0xFF);
                // Length
                channelData[2] = (byte) (length >> 8);
                channelData[3] = (byte) (length & 0xFF);
                // Application Data
                System.arraycopy(data, 0, channelData, CHANNELDATA_CHANNELNUMBER_LENGTH + CHANNELDATA_LENGTH_LENGTH, length);

                try {
                    if (channelDataPacket == null) {
                        channelDataPacket = new DatagramPacket(channelData, 0, channelDataLength, turnCandidateHarvest.harvester.stunServer);
                    } else
                        channelDataPacket.setData(channelData, 0, channelDataLength);

                    channelDataSocket.send(channelDataPacket);
                } catch (IOException ioex) {
                    throw new StunException(StunException.NETWORK_ERROR, "Failed to send TURN ChannelData message", ioex);
                }
            } else {
                byte[] transactionID = TransactionID.createNewTransactionID().getBytes();
                Indication sendIndication = MessageFactory.createSendIndication(peerAddress, data, transactionID);

                sendIndication.setTransactionID(transactionID);
                turnCandidateHarvest.harvester.getStunStack().sendIndication(sendIndication, turnCandidateHarvest.harvester.stunServer, turnCandidateHarvest.hostCandidate.getTransportAddress());
            }
        }

        /**
         * Sets the indicator which determines whether this Channel is
         * bound/installed.
         *
         * @param bound true if this Channel is to be marked
         * as bound/installed; otherwise, false
         * @param boundTransactionID an array of bytes which represents
         * the ID of the transaction with which the confirmation about the
         * binding/installing has arrived
         */
        public void setBound(boolean bound, byte[] boundTransactionID) {
            if (bindingTransactionID != null) {
                bindingTransactionID = null;
                this.bound = bound;
            }
        }

        /**
         * Sets the indicator which determines whether this Channel is
         * set to prefer sending DatagramPackets using TURN ChannelData
         * messages instead of Send indications.
         *
         * @param channelDataIsPreferred true if this Channel
         * is to be set to prefer sending DatagramPackets using TURN
         * ChannelData messages instead of Send indications
         */
        public void setChannelDataIsPreferred(boolean channelDataIsPreferred) {
            this.channelDataIsPreferred = channelDataIsPreferred;
        }

        /**
         * Sets the indicator which determines whether the associated TURN
         * server has confirmed the allocation of the channelNumber of
         * this Channel by us receiving a success Response to
         * our ChannelBind Request.
         *
         * @param channelNumberIsConfirmed true if allocation of the
         * channel number has been confirmed by a success Response to
         * our ChannelBind Request
         * @param channelNumberIsConfirmedTransactionID an array of
         * bytes which represents the ID of the transaction with which
         * the confirmation about the allocation of the channel number has
         * arrived
         */
        public void setChannelNumberIsConfirmed(boolean channelNumberIsConfirmed, byte[] channelNumberIsConfirmedTransactionID) {
            this.channelNumberIsConfirmed = channelNumberIsConfirmed;
        }
    }
}
