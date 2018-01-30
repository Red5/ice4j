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
     * The size for newly allocated Buffer instances. This limits the maximum size of datagrams we can receive.
     *
     * XXX should we increase this in case of other MTUs, or set it dynamically according to the available network interfaces?
     */
    //private static final int BUFFER_SIZE = /* assumed MTU */1500 - /* IPv4 header */20 - /* UDP header */8;

    /**
     * The name of the property which controls the size of the receive buffer for the sockets created.
     */
    private static final String SO_RCVBUF_PNAME = AbstractUdpListener.class.getName() + ".SO_RCVBUF";

    /**
     * The name of the property which controls the size of the send buffer for the sockets created.
     */
    private static final String SO_SNDBUF_PNAME = AbstractUdpListener.class.getName() + ".SO_SNDBUF";

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
        if (!((buf[off + 4] & 0xFF) == 0x21 && (buf[off + 5] & 0xFF) == 0x12 && (buf[off + 6] & 0xFF) == 0xA4 && (buf[off + 7] & 0xFF) == 0x42)) {
            if (logger.isDebugEnabled()) {
                logger.debug("Not a STUN packet, magic cookie not found.");
            }
            return null;
        }
        try {
            Message stunMessage = Message.decode(buf, off, len);
            if (stunMessage.getMessageType() != Message.BINDING_REQUEST) {
                return null;
            }
            UsernameAttribute usernameAttribute = (UsernameAttribute) stunMessage.getAttribute(Attribute.Type.USERNAME);
            //logger.info("usernameAttribute: " + usernameAttribute);
            if (usernameAttribute == null) {
                return null;
            }
            String usernameString = new String(usernameAttribute.getUsername());
            return usernameString.split(":")[0];
        } catch (Exception e) {
            // Catch everything. We are going to log, and then drop the packet anyway.
            if (logger.isDebugEnabled()) {
                logger.warn("Failed to extract local ufrag", e);
            }
        }
        return null;
    }

    /**
     * The map which keeps the known remote addresses and their associated candidateSockets.
     * {@link #thread} is the only thread which adds new entries, while other threads remove entries when candidates are freed.
     */
    private final Map<SocketAddress, MySocket> sockets = new ConcurrentHashMap<>();

    /**
     * The local address that this harvester is bound to.
     */
    protected final TransportAddress localAddress;

    private DatagramChannel channel;

    /**
     * Internal NIO server.
     */
    private NioServer server;

    /**
     * Initializes a new SinglePortUdpHarvester instance which is to bind on the specified local address.
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
        // instance a new NIO server
        server = new NioServer();
        // add the local binding
        server.addUdpBinding(localAddress);
        // https://docs.oracle.com/javase/8/docs/api/java/net/StandardSocketOptions.html#SO_RCVBUF
        int receiveBufferSize = StackProperties.getInt(SO_RCVBUF_PNAME, -1);
        if (receiveBufferSize > 0) {
            server.setInputBufferSize(receiveBufferSize);
        }
        logger.info("Initialized AbstractUdpListener on: {} with recv buf size: {} of requested: {}", localAddress, server.getInputBufferSize(), receiveBufferSize);
        // https://docs.oracle.com/javase/8/docs/api/java/net/StandardSocketOptions.html#SO_SNDBUF
        int sendBufferSize = StackProperties.getInt(SO_SNDBUF_PNAME, -1);
        if (sendBufferSize > 0) {
            server.setOutputBufferSize(sendBufferSize);
        }
        logger.info("Initialized AbstractUdpListener on: {} with send buf size: {} of requested: {}", localAddress, server.getOutputBufferSize(), sendBufferSize);
        // add a listener for data events
        server.addNioServerListener(new NioServer.Adapter() {

            @Override
            public void udpDataReceived(Event evt) {
                // grab the datagram channel from the event
                if (channel == null) {
                    channel = (DatagramChannel) evt.getKey().channel();
                }
                //get the data
                ByteBuffer recvBuf = evt.getInputBuffer();
                byte[] buf = new byte[recvBuf.remaining()];
                recvBuf.get(buf);
                // get the remote address
                InetSocketAddress remoteAddress = (InetSocketAddress) evt.getRemoteSocketAddress();
                MySocket destinationSocket = sockets.get(remoteAddress);
                if (destinationSocket != null) {
                    //make 'pkt' available for reading through destinationSocket
                    destinationSocket.addBuffer(buf);
                } else {
                    // Packet from an unknown source. Is it a STUN Binding Request?
                    String ufrag = getUfrag(buf, 0, buf.length);
                    if (ufrag != null) {
                        maybeAcceptNewSession(buf, remoteAddress, ufrag);
                    } else {
                        // Not a STUN Binding Request or doesn't have a valid USERNAME attribute, drop it.
                    }
                }
            }

            @Override
            public void connectionClosed(Event evt) {
                MySocket destinationSocket = sockets.get(evt.getRemoteSocketAddress());
                if (destinationSocket != null) {
                    destinationSocket.close();
                }
            }

        });
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
     * @param buf the UDP payload of the first datagram received on the newly accepted socket.
     * @param remoteAddress the remote address from which the datagram was received.
     * @param ufrag the local ICE username fragment of the received STUN Binding Request.
     */
    protected abstract void maybeAcceptNewSession(byte[] buf, InetSocketAddress remoteAddress, String ufrag);

    /**
     * Creates a new {@link MySocket} instance and associates it with the given remote address. Returns the created instance.
     *
     * Note that this is meant to only execute in {@link AbstractUdpListener}'s read thread.
     *
     * @param remoteAddress the remote address with which to associate the new socket instance.
     * @return the created socket instance.
     */
    protected MySocket addSocket(InetSocketAddress remoteAddress) throws SocketException {
        MySocket newSocket = new MySocket(remoteAddress);
        sockets.put(remoteAddress, newSocket);
        return newSocket;
    }

    /**
     * Implements a DatagramSocket for the purposes of a specific MyCandidate.
     *
     * It is not bound to a specific port, but shares the same local address as the bound socket held by the harvester.
     */
    protected class MySocket extends DatagramSocket {

        /**
         * The FIFO which acts as a buffer for this socket.
         */
        private final ArrayBlockingQueue<byte[]> queue = new ArrayBlockingQueue<>(64);

        /**
         * The remote address that is associated with this socket.
         */
        private InetSocketAddress remoteAddress;

        /**
         * The flag which indicates that this DatagramSocket has been closed.
         */
        private boolean closed;

        /**
         * Initializes a new MySocket instance with the given remote address.
         * 
         * @param remoteAddress the remote address to be associated with the new instance.
         * @throws SocketException
         */
        MySocket(InetSocketAddress remoteAddress) throws SocketException {
            // unbound
            super((SocketAddress) null);
            this.remoteAddress = remoteAddress;
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
         * {@inheritDoc}
         *
         * Delegates to the actual socket of the harvester.
         */
        @Override
        public InetAddress getLocalAddress() {
            return localAddress.getAddress();
        }

        /**
         * {@inheritDoc}
         *
         * Delegates to the actual socket of the harvester.
         */
        @Override
        public int getLocalPort() {
            return localAddress.getPort();
        }

        /**
         * {@inheritDoc}
         *
         * Delegates to the actual socket of the harvester.
         */
        @Override
        public SocketAddress getLocalSocketAddress() {
            return localAddress;
        }

        /**
         * {@inheritDoc}
        * <br>
         * This {@link DatagramSocket} will only allow packets from the remote address that it has, so we consider it connected to this address.
         */
        @Override
        public SocketAddress getRemoteSocketAddress() {
            return remoteAddress;
        }

        /**
         * {@inheritDoc}
        * <br>
         * This {@link DatagramSocket} will only allow packets from the remote address that it has, so we consider it connected to this address.
         */
        @Override
        public InetAddress getInetAddress() {
            return remoteAddress.getAddress();
        }

        /**
         * {@inheritDoc}
        * <br>
         * This {@link DatagramSocket} will only allow packets from the remote address that it has, so we consider it connected to this address.
         */
        @Override
        public int getPort() {
            return remoteAddress.getPort();
        }

        /**
         * {@inheritDoc}
         *
         * Removes the association of the remote address with this socket from the harvester's map.
         */
        @Override
        public void close() {
            closed = true;
            queue.clear();
            // We could be called by the super-class constructor, in which case this.removeAddress is not initialized yet.
            if (remoteAddress != null) {
                AbstractUdpListener.this.sockets.remove(remoteAddress);
            }
            super.close();
        }

        /**
         * Reads the data from the first element of {@link #queue} into p. Blocks until {@link #queue} has an element.
         * @param p
         * @throws IOException
         */
        @Override
        public void receive(DatagramPacket p) throws IOException {
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
         * {@inheritDoc}
         *
         * Delegates to the actual socket of the harvester.
         */
        @Override
        public void send(DatagramPacket p) throws IOException {
            channel.socket().send(p);
        }
    }

}
