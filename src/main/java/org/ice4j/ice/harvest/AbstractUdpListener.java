/* See LICENSE.md for license information */
package org.ice4j.ice.harvest;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;

import org.ice4j.StackProperties;
import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.attribute.Attribute;
import org.ice4j.attribute.UsernameAttribute;
import org.ice4j.ice.nio.NioServer;
import org.ice4j.ice.nio.NioServer.Event;
import org.ice4j.message.Message;
import org.ice4j.stack.StunStack;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A class which holds a {@link DatagramSocket} and runs a thread ({@link #thread}) which perpetually reads from it.
 *
 * When a datagram from an unknown source is received, it is parsed as a STUN Binding Request, and if it has a USERNAME attribute, its ufrag is extracted.
 * At this point, an implementing class may choose to create a mapping for the remote address of the datagram, which will be used for further packets
 * from this address.
 *
 * @author Boris Grozev
 * @author Paul Gregoire
 */
public abstract class AbstractUdpListener {

    private static final Logger logger = LoggerFactory.getLogger(AbstractUdpListener.class);

    /**
     * Returns the list of {@link TransportAddress}es, one for each allowed IP address found on each allowed network interface, with the given port.
     *
     * @param port the UDP port number.
     * @return the list of allowed transport addresses.
     */
    public static List<TransportAddress> getAllowedAddresses(int port) {
        List<TransportAddress> addresses = new LinkedList<>();
        for (InetAddress address : HostCandidateHarvester.getAllAllowedAddresses()) {
            addresses.add(new TransportAddress(address, port, Transport.UDP));
        }
        return addresses;
    }

    /**
     * Tries to parse the bytes in buf at offset off (and length len) as a STUN Binding Request message. If successful,
     * looks for a USERNAME attribute and returns the local username fragment part (see RFC5245 Section 7.1.2.3).
     * In case of any failure returns null.
     *
     * @param buf the bytes.
     * @param off the offset.
     * @param len the length.
     * @return the local ufrag from the USERNAME attribute of the STUN message contained in buf, or null.
     */
    static String getUfrag(byte[] buf, int off, int len) {
        // RFC5389, Section 6: All STUN messages MUST start with a 20-byte header followed by zero or more Attributes.
        if (buf == null || buf.length < off + len || len < 20) {
            return null;
        }
        // RFC5389, Section 6: The magic cookie field MUST contain the fixed value 0x2112A442 in network byte order.
        if (((buf[off + 4] & 0xFF) == 0x21 && (buf[off + 5] & 0xFF) == 0x12 && (buf[off + 6] & 0xFF) == 0xA4 && (buf[off + 7] & 0xFF) == 0x42)) {
            try {
                Message stunMessage = Message.decode(buf, off, len);
                if (stunMessage.getMessageType() == Message.BINDING_REQUEST) {
                    UsernameAttribute usernameAttribute = (UsernameAttribute) stunMessage.getAttribute(Attribute.Type.USERNAME);
                    if (logger.isTraceEnabled()) {
                        logger.trace("usernameAttribute: {}", usernameAttribute);
                    }
                    if (usernameAttribute != null) {
                        String usernameString = new String(usernameAttribute.getUsername());
                        return usernameString.split(":")[0];
                    }
                }
            } catch (Exception e) {
                // Catch everything. We are going to log, and then drop the packet anyway.
                if (logger.isDebugEnabled()) {
                    logger.warn("Failed to extract local ufrag", e);
                }
            }
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug("Not a STUN packet, magic cookie not found.");
            }
        }
        return null;
    }

    /**
     * The map which keeps the known remote addresses and their associated candidateSockets.
     * {@link #thread} is the only thread which adds new entries, while other threads remove entries when candidates are freed.
     */
    protected final Map<SocketAddress, UdpChannel> sockets = new ConcurrentHashMap<>();

    /**
     * The local address that this harvester is bound to.
     */
    protected final TransportAddress localAddress;

    /**
     * Internal NIO server.
     */
    private NioServer server;

    /**
     * Initializes a new SinglePortUdpHarvester instance which is to bind on the specified local address.
     * 
     * @param localAddress the address to bind to.
     * @throws IOException if initialization fails.
     */
    protected AbstractUdpListener(TransportAddress localAddress) throws IOException {
        boolean bindWildcard = !StackProperties.getBoolean(StackProperties.BIND_WILDCARD, false);
        if (bindWildcard) {
            this.localAddress = new TransportAddress((InetAddress) null, localAddress.getPort(), localAddress.getTransport());
        } else {
            this.localAddress = localAddress;
        }
        // create a stunstack
        final StunStack stunStack = new StunStack();
        // instance a new NIO server
        server = NioServer.getInstance(stunStack);
        // add a listener for data events
        server.addNioServerListener(localAddress, new NioServer.Adapter(null) {

            @Override
            public boolean udpDataReceived(Event evt) {
                if (logger.isDebugEnabled()) {
                    logger.debug("udpDataReceived: {}", evt);
                }
                //get the data
                ByteBuffer recvBuf = evt.getInputBuffer();
                byte[] buf = new byte[recvBuf.remaining()];
                recvBuf.get(buf);
                // get the remote address
                InetSocketAddress remoteAddress = (InetSocketAddress) evt.getRemoteSocketAddress();
                // channel wrapper is created when binding request is received in maybeAcceptNewSession
                UdpChannel channel = sockets.get(remoteAddress);
                if (channel != null) {
                    // make 'pkt' available for reading through destinationSocket
                    channel.addBuffer(buf);
                } else {
                    // Packet from an unknown source. Is it a STUN Binding Request?
                    String ufrag = getUfrag(buf, 0, buf.length);
                    if (ufrag != null) {
                        // grab the datagram channel from the event and add to the UdpChannel
                        maybeAcceptNewSession((DatagramChannel) evt.getKey().channel(), buf, remoteAddress, ufrag);
                    } else {
                        // Not a STUN Binding Request or doesn't have a valid USERNAME attribute, drop it.
                    }
                }
                return true;
            }

            @Override
            public boolean connectionClosed(Event evt) {
                if (logger.isDebugEnabled()) {
                    logger.debug("connectionClosed: {}", evt);
                }
                UdpChannel destinationSocket = sockets.remove(evt.getRemoteSocketAddress());
                if (destinationSocket != null) {
                    destinationSocket.close();
                }
                stunStack.shutDown();
                return true;
            }

        });
        // add the local binding
        server.addUdpBinding(localAddress);
        // start it up!
        server.start();
    }

    /**
     * Handles the reception of a STUN Binding Request with a valid USERNAME attribute, from a "new" remote address (one which is not in
     * {@link #sockets}). Implementations may choose to e.g. create a socket and pass it to their ICE stack.
     *
     * Note that this is meant to only be executed by {@link AbstractUdpListener}'s read thread, and should not be called from
     * implementing classes.
     *
     * @param channel DatagramChannel datagram was received on
     * @param buf the UDP payload of the first datagram received
     * @param remoteAddress the remote address from which the datagram was received
     * @param ufrag the local ICE username fragment of the received STUN Binding Request
     */
    protected abstract void maybeAcceptNewSession(DatagramChannel channel, byte[] buf, InetSocketAddress remoteAddress, String ufrag);

    /**
     * Wraps a DatagramChannel for the purposes of a specific MyCandidate.
     *
     * It is not bound to a specific port, but shares the same local address as the bound socket held by the harvester.
     */
    protected class UdpChannel {

        /**
         * The FIFO which acts as a buffer for this socket.
         */
        private final ArrayBlockingQueue<byte[]> queue = new ArrayBlockingQueue<>(64);

        /**
         * DatagramChannel.
         */
        private final DatagramChannel datagramChannel;

        /**
         * The remote address that is associated with this channel.
         */
        private InetSocketAddress remoteAddress;

        /**
         * The flag which indicates that this channel has been closed.
         */
        private boolean closed;

        /**
         * Wraps the given DatagramChannel.
         * 
         * @param channel DatagramChannel for wrapping
         */
        UdpChannel(DatagramChannel channel) {
            datagramChannel = channel;
        }

        /**
         * Constructor to use before a DatagramChannel exists.
         * 
         * @param channel DatagramChannel for wrapping
         * @param remoteAddress the remote address to be associated with this instance.
         */
        UdpChannel(DatagramChannel channel, InetSocketAddress remoteAddress) {
            datagramChannel = channel;
            this.remoteAddress = remoteAddress;
            if (!channel.isConnected()) {
                try {
                    channel.connect(remoteAddress);
                } catch (IOException e) {
                    logger.warn("Connection failure", e);
                }
            }
        }

        /**
         * Adds pkt to this socket. If the queue is full, drops a packet. Does not block.
         */
        public void addBuffer(byte[] buf) {
            // Drop the first rather than the current packet, so that receivers can notice the loss earlier.
            if (queue.offer(buf)) {
                logger.trace("Packet accepted by the queue");
            } else {
                logger.info("Dropping a packet because the queue is full.");
                // remove head
                queue.poll();
                // try once more to add the buf
                if (queue.offer(buf)) {
                    logger.trace("Packet accepted by the to queue");
                }
            }
        }

        /**
         * Reads the data from the first element of {@link #queue} into p. Blocks until {@link #queue} has an element.
         * @param p
         * @throws IOException
         */
        public void receive(DatagramPacket p) throws IOException {
            logger.debug("receive: {}", p);
            byte[] buf = null;
            while (buf == null) {
                if (closed) {
                    throw new SocketException("Socket closed");
                }
                try {
                    // take will block until there's a buffer
                    buf = queue.take();
                } catch (InterruptedException e) {
                }
            }
            byte[] pData = p.getData();
            // XXX Should we use p.setData() here with a buffer of our own?
            if (pData == null || pData.length < buf.length) {
                throw new IOException("packet buffer not available");
            }
            System.arraycopy(buf, 0, pData, 0, buf.length);
            p.setLength(buf.length);
            p.setSocketAddress(remoteAddress);
        }

        /**
         * Delegates to the DatagramChannel.
         */
        public void send(DatagramPacket p) throws IOException {
            logger.debug("send: {}", p);
            if (datagramChannel != null) {
                datagramChannel.send(ByteBuffer.wrap(p.getData()), p.getSocketAddress());
            } else {
                logger.warn("No datagram channel exists for sending");
            }
        }

        /**
         * Removes the association of the remote address with this socket from the harvester's map.
         */
        public void close() {
            closed = true;
            queue.clear();
            // We could be called by the super-class constructor, in which case this.removeAddress is not initialized yet.
            if (remoteAddress != null) {
                AbstractUdpListener.this.sockets.remove(remoteAddress);
            }
            try {
                datagramChannel.close();
            } catch (IOException e) {
                logger.warn("Exception closing datagram channel", e);
            }
            // XXX should probably clean-up the nio server here since the listener/harvester dont stop or close
            if (sockets.isEmpty()) {
                server.stop();
            }
        }

        public DatagramChannel getDatagramChannel() {
            return datagramChannel;
        }

        /**
         * Returns the local TransportAddress for the harvester.
         * 
         * @return localAddress
         */
        public TransportAddress getLocalTransportAddress() {
            return localAddress;
        }

        /**
         * Delegates to the actual socket of the harvester.
         */
        public InetAddress getLocalAddress() {
            return localAddress.getAddress();
        }

        /**
         * Delegates to the actual socket of the harvester.
         */
        public int getLocalPort() {
            return localAddress.getPort();
        }

        /**
         * Delegates to the actual socket of the harvester.
         */
        public SocketAddress getLocalSocketAddress() {
            return localAddress;
        }

        /**
         * @param remoteAddress the remote address to be associated with this instance.
         */
        public void setRemoteSocketAddress(InetSocketAddress remoteAddress) {
            this.remoteAddress = remoteAddress;
        }

        /**
         * This {@link DatagramSocket} will only allow packets from the remote address that it has, so we consider it connected to this address.
         */
        public SocketAddress getRemoteSocketAddress() {
            return remoteAddress;
        }

        /**
         * This {@link DatagramSocket} will only allow packets from the remote address that it has, so we consider it connected to this address.
         */
        public InetAddress getInetAddress() {
            return remoteAddress.getAddress();
        }

        /**
         * This {@link DatagramSocket} will only allow packets from the remote address that it has, so we consider it connected to this address.
         */
        public int getPort() {
            return remoteAddress.getPort();
        }

    }

}
