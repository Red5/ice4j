/* See LICENSE.md for license information */
package org.ice4j.ice.harvest;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.Channel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.ice4j.StackProperties;
import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.ice.nio.IceDecoder;
import org.ice4j.message.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An abstract class that binds on a set of sockets and accepts sessions that start with a STUN Binding Request (preceded by an optional fake SSL
 * handshake). The handling of the accepted sessions (e.g. handling in ICE) is left to the implementations.
 *
 * This instance runs two threads: {@link #acceptThread} and {@link #readThread}. The 'accept' thread just accepts new Sockets
 * and passes them over to the 'read' thread. The 'read' thread reads a STUN message from an accepted socket and, based on the STUN username, passes it
 * to the appropriate session.
 *
 * @author Boris Grozev
 * @author Lyubomir Marinov
 */
public abstract class AbstractTcpListener {

    private static final Logger logger = LoggerFactory.getLogger(AbstractTcpListener.class);

    /**
     * The maximum number of milliseconds to wait for an accepted {@code SocketChannel} to provide incoming/readable data before it is
     * considered abandoned by the client.
     */
    public static final int SOCKET_CHANNEL_READ_TIMEOUT = 15 * 1000;

    /**
     * Closes a {@code Channel} and swallows any {@link IOException}.
     *
     * @param channel the {@code Channel} to close
     */
    static void closeNoExceptions(Channel channel) {
        try {
            channel.close();
        } catch (IOException ioe) {
            // close a Channel without caring about any possible IOException
        }
    }

    /**
     * Returns the list of {@link TransportAddress}es, one for each allowed IP address found on each allowed network interface, with the given port.
     *
     * @param port the TCP port number.
     * @return the list of allowed transport addresses.
     */
    public static List<TransportAddress> getAllowedAddresses(int port) {
        List<TransportAddress> addresses = new LinkedList<>();
        for (InetAddress address : HostCandidateHarvester.getAllAllowedAddresses()) {
            addresses.add(new TransportAddress(address, port, Transport.TCP));
        }
        return addresses;
    }

    /**
     * Determines whether a specific {@link DatagramPacket} is the first expected (i.e. supported) to be received from an accepted
     * {@link SocketChannel} by this {@link AbstractTcpListener}. This is true if it is contains the hard-coded SSL client handshake (
     * {@link GoogleTurnSSLCandidateHarvester#SSL_CLIENT_HANDSHAKE}), or a STUN Binding Request.
     *
     * @param p the {@code DatagramPacket} to examine
     * @return {@code true} if {@code p} looks like the first {@code DatagramPacket} expected to be received from an accepted
     * {@code SocketChannel} by this {@code TcpHarvester}; otherwise, {@code false}
     */
    @SuppressWarnings("unused")
    private static boolean isFirstDatagramPacket(DatagramPacket p) {
        int len = p.getLength();
        boolean b = false;
        if (len > 0) {
            byte[] buf = p.getData();
            int off = p.getOffset();
            // Check for Google TURN SSLTCP
            final byte[] googleTurnSslTcp = TurnCandidateHarvester.SSL_CLIENT_HANDSHAKE;
            if (len >= googleTurnSslTcp.length) {
                b = true;
                for (int i = 0, iEnd = googleTurnSslTcp.length, j = off; i < iEnd; i++, j++) {
                    if (googleTurnSslTcp[i] != buf[j]) {
                        b = false;
                        break;
                    }
                }
            }
            // nothing found, lets check for stun binding requests
            if (!b) {
                // 2 bytes    uint16 length
                // STUN Binding request:
                //   2 bits   00
                //   14 bits  STUN Messsage Type
                //   2 bytes  Message Length
                //   4 bytes  Magic Cookie
                // RFC 5389: For example, a Binding request has class=0b00 (request) and method=0b000000000001 (Binding)
                // and is encoded into the first 16 bits as 0x0001.
                if (len >= 10 && buf[off + 2] == 0 && buf[off + 3] == 1) {
                    final byte[] magicCookie = Message.MAGIC_COOKIE;
                    b = true;
                    for (int i = 0, iEnd = magicCookie.length, j = off + 6; i < iEnd; i++, j++) {
                        if (magicCookie[i] != buf[j]) {
                            b = false;
                            break;
                        }
                    }
                }
            }
        }
        return b;
    }

    /**
     * The thread which accepts TCP connections from the sockets in {@link #serverSocketChannels}.
     */
    private AcceptThread acceptThread;

    /**
     * Triggers the termination of the threads of this instance.
     */
    private boolean close;

    /**
     * The list of transport addresses which we have found to be listening on, and which may be, for example, advertises as ICE candidates.
     */
    protected final List<TransportAddress> localAddresses = new LinkedList<>();

    /**
     * Channels pending to be added to the list that {@link #readThread} reads from.
     */
    private final List<SocketChannel> newChannels = new LinkedList<>();

    /**
     * The Selector used by {@link #readThread}.
     */
    private final Selector readSelector = Selector.open();

    /**
     * The thread which reads from the already accepted sockets.
     */
    private ReadThread readThread;

    /**
     * The list of ServerSocketChannels that we will accept
     * on.
     */
    private final List<ServerSocketChannel> serverSocketChannels = new LinkedList<>();

    /**
     * The object used to synchronize access to the collection of sessions that the implementation of this class uses.
     */
    protected final Object sessionsSyncRoot = new Object();

    /**
     * Initializes a new TcpHarvester, which is to listen on port number port on all IP addresses on all available interfaces.
     *
     * @param port the port to listen on.
     * @throws IOException when {@link StackProperties#ALLOWED_ADDRESSES} or {@link StackProperties#BLOCKED_ADDRESSES} contains invalid values, or
     * if an I/O error occurs.
     */
    public AbstractTcpListener(int port) throws IOException {
        this(getAllowedAddresses(port));
    }

    /**
     * Initializes a new TcpHarvester, which is to listen on the specified list of TransportAddresses.
     *
     * @param transportAddresses the transport addresses to listen on.
     * @throws IOException when {@link StackProperties#ALLOWED_ADDRESSES} or {@link StackProperties#BLOCKED_ADDRESSES} contains invalid values, or
     * if an I/O error occurs.
     */
    public AbstractTcpListener(List<TransportAddress> transportAddresses) throws IOException {
        addLocalAddresses(transportAddresses);
        init();
    }

    public AbstractTcpListener(int port, List<NetworkInterface> interfaces) throws IOException {
        List<TransportAddress> transportAddresses = new LinkedList<>();
        for (NetworkInterface iface : interfaces) {
            Enumeration<InetAddress> addresses = iface.getInetAddresses();
            while (addresses.hasMoreElements()) {
                InetAddress address = addresses.nextElement();
                transportAddresses.add(new TransportAddress(address, port, Transport.TCP));
            }
        }
        addLocalAddresses(transportAddresses);
        init();
    }

    /**
     * Adds to {@link #localAddresses} those addresses from transportAddresses which are found suitable for candidate allocation.
     *
     * @param transportAddresses the list of addresses to add.
     * @throws IOException when {@link StackProperties#ALLOWED_ADDRESSES} or {@link StackProperties#BLOCKED_ADDRESSES} contains invalid values.
     */
    protected void addLocalAddresses(List<TransportAddress> transportAddresses) throws IOException {
        boolean useIPv6 = !StackProperties.getBoolean(StackProperties.DISABLE_IPv6, true);
        boolean useIPv6LinkLocal = !StackProperties.getBoolean(StackProperties.DISABLE_LINK_LOCAL_ADDRESSES, false);
        // White list from the configuration
        String[] allowedAddressesStr = StackProperties.getStringArray(StackProperties.ALLOWED_ADDRESSES, ";");
        InetAddress[] allowedAddresses = null;
        if (allowedAddressesStr != null) {
            allowedAddresses = new InetAddress[allowedAddressesStr.length];
            for (int i = 0; i < allowedAddressesStr.length; i++) {
                allowedAddresses[i] = InetAddress.getByName(allowedAddressesStr[i]);
            }
        }
        // Black list from the configuration
        String[] blockedAddressesStr = StackProperties.getStringArray(StackProperties.BLOCKED_ADDRESSES, ";");
        InetAddress[] blockedAddresses = null;
        if (blockedAddressesStr != null) {
            blockedAddresses = new InetAddress[blockedAddressesStr.length];
            for (int i = 0; i < blockedAddressesStr.length; i++) {
                blockedAddresses[i] = InetAddress.getByName(blockedAddressesStr[i]);
            }
        }
        for (TransportAddress transportAddress : transportAddresses) {
            InetAddress address = transportAddress.getAddress();
            if (address.isLoopbackAddress()) {
                //loopback again
                continue;
            }
            if (!useIPv6 && (address instanceof Inet6Address)) {
                continue;
            }
            if (!useIPv6LinkLocal && (address instanceof Inet6Address) && address.isLinkLocalAddress()) {
                logger.debug("Not using link-local address {} for TCP candidates", address);
                continue;
            }
            if (allowedAddresses != null) {
                boolean found = false;
                for (InetAddress allowedAddress : allowedAddresses) {
                    if (allowedAddress.equals(address)) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    logger.debug("Not using {} for TCP candidates, because it is not in the allowed list", address);
                    continue;
                }
            }
            if (blockedAddresses != null) {
                boolean found = false;
                for (InetAddress blockedAddress : blockedAddresses) {
                    if (blockedAddress.equals(address)) {
                        found = true;
                        break;
                    }
                }
                if (found) {
                    logger.debug("Not using {} for TCP candidates, because it is in the blocked list", address);
                    continue;
                }
            }
            // Passed all checks
            localAddresses.add(transportAddress);
        }
    }

    /**
     * Triggers the termination of the threads of this MultiplexingTcpHarvester.
     */
    public void close() {
        close = true;
    }

    /**
     * Initializes {@link #serverSocketChannels}, creates and starts the threads used by this instance.
     * @throws IOException if an I/O error occurs
     */
    protected void init() throws IOException {
        boolean bindWildcard = !StackProperties.getBoolean(StackProperties.BIND_WILDCARD, false);
        // Use a set to filter out any duplicates.
        Set<InetSocketAddress> addressesToBind = new HashSet<>();
        for (TransportAddress transportAddress : localAddresses) {
            addressesToBind.add(new InetSocketAddress(bindWildcard ? null : transportAddress.getAddress(), transportAddress.getPort()));
        }
        for (InetSocketAddress addressToBind : addressesToBind) {
            addSocketChannel(addressToBind);
        }
        acceptThread = new AcceptThread();
        acceptThread.start();
        readThread = new ReadThread();
        readThread.start();
    }

    /**
     * Initializes one of the channels in {@link #serverSocketChannels},
     * @throws IOException if an I/O error occurs
     */
    private void addSocketChannel(InetSocketAddress address) throws IOException {
        ServerSocketChannel channel = ServerSocketChannel.open();
        channel.bind(address, 0);
        // XXX if we need to add a datagram filter
        /*
         * new DatagramPacketFilter() {
         * @Override public boolean accept(DatagramPacket p) { return isFirstDatagramPacket(p); } };
         */
        serverSocketChannels.add(channel);
    }

    /**
     * Accepts a session.
     * @param socket the {@link Socket} for the session.
     * @param ufrag the local username fragment for the session.
     * @param pushback the first "datagram" (RFC4571-framed), already read from the socket's stream.
     * @throws IllegalStateException
     * @throws IOException
     */
    protected abstract void acceptSession(Socket socket, String ufrag, DatagramPacket pushback) throws IOException, IllegalStateException;

    /**
     * A Thread which will accept new SocketChannels from all
     * ServerSocketChannels in {@link #serverSocketChannels}.
     */
    private class AcceptThread extends Thread {
        /**
         * The Selector used to select a specific
         * ServerSocketChannel which is ready to accept.
         */
        private final Selector selector;

        /**
         * Initializes a new AcceptThread.
         */
        public AcceptThread() throws IOException {
            setName("TcpHarvester AcceptThread");
            setDaemon(true);
            selector = Selector.open();
            for (ServerSocketChannel channel : serverSocketChannels) {
                channel.configureBlocking(false);
                channel.register(selector, SelectionKey.OP_ACCEPT);
            }
        }

        /**
         * Notifies {@link #readThread} that new channels have been added.
         */
        private void notifyReadThread() {
            readSelector.wakeup();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void run() {
            do {
                if (close) {
                    break;
                }
                IOException exception = null;
                List<SocketChannel> channelsToAdd = new LinkedList<>();
                // Allow to go on, so we can quit if closed.
                long selectTimeout = 3000;
                for (SelectionKey key : selector.keys()) {
                    if (key.isValid()) {
                        SocketChannel channel;
                        boolean acceptable = key.isAcceptable();
                        try {
                            channel = ((ServerSocketChannel) key.channel()).accept();
                        } catch (IOException ioe) {
                            exception = ioe;
                            break;
                        }
                        // Add the accepted channel to newChannels to allow the 'read' thread to it up.
                        if (channel != null) {
                            channelsToAdd.add(channel);
                        } else if (acceptable) {
                            // The SelectionKey reported the channel as acceptable but channel#accept() did not accept a
                            // non-null SocketChannel. Give the channel a little time to get its act together.
                            selectTimeout = 100;
                        }
                    }
                }
                // We accepted from all serverSocketChannels.
                selector.selectedKeys().clear();
                if (!channelsToAdd.isEmpty()) {
                    synchronized (newChannels) {
                        newChannels.addAll(channelsToAdd);
                    }
                    notifyReadThread();
                }
                if (exception != null) {
                    logger.warn("Failed to accept a socket, which should have been ready to accept", exception);
                    break;
                }
                try {
                    // Allow to go on, so we can quit if closed.
                    selector.select(selectTimeout);
                } catch (IOException ioe) {
                    logger.warn("Failed to select an accept-ready socket", ioe);
                    break;
                }
            } while (true);
            //now clean up and exit
            for (ServerSocketChannel serverSocketChannel : serverSocketChannels) {
                closeNoExceptions(serverSocketChannel);
            }
            try {
                selector.close();
            } catch (IOException ioe) {
            }
        }
    }

    /**
     * Contains a SocketChannel that ReadThread is reading from.
     */
    private static class ChannelDesc {
        /**
         * The actual SocketChannel.
         */
        public final SocketChannel channel;

        /**
         * The time the channel was last found to be active.
         */
        long lastActive = System.currentTimeMillis();

        /**
         * The buffer which stores the data so far read from the channel.
         */
        ByteBuffer buffer = null;

        /**
         * Whether we had checked for initial "pseudo" SSL handshake.
         */
        boolean checkedForSSLHandshake = false;

        /**
         * Buffer to use if we had read some data in advance and want to process it after next read, used when we are checking for "pseudo" SSL and
         * we haven't found some, but had read data to check for it.
         */
        byte[] preBuffered;

        /**
         * The value of the RFC4571 "length" field read from the channel, or -1 if it hasn't been read (yet).
         */
        int length = -1;

        /**
         * Initializes a new ChannelDesc with the given channel.
         * 
         * @param channel the channel.
         */
        public ChannelDesc(SocketChannel channel) {
            this.channel = channel;
        }
    }

    private class ReadThread extends Thread {
        /**
         * Initializes a new ReadThread.
         *
         * @throws IOException if the selector to be used fails to open.
         */
        public ReadThread() throws IOException {
            setName("TcpHarvester ReadThread");
            setDaemon(true);
        }

        /**
         * Registers the channels from {@link #newChannels} in {@link #readSelector}.
         */
        private void checkForNewChannels() {
            synchronized (newChannels) {
                for (SocketChannel channel : newChannels) {
                    try {
                        channel.configureBlocking(false);
                        channel.register(readSelector, SelectionKey.OP_READ, new ChannelDesc(channel));
                    } catch (IOException ioe) {
                        logger.warn("Failed to register channel", ioe);
                        closeNoExceptions(channel);
                    }
                }
                newChannels.clear();
            }
        }

        /**
         * Closes any inactive channels registered with {@link #readSelector}.
         * A channel is considered inactive if it hasn't been available for reading for
         * {@link MuxServerSocketChannelFactory#SOCKET_CHANNEL_READ_TIMEOUT} milliseconds.
         */
        private void cleanup() {
            long now = System.currentTimeMillis();
            for (SelectionKey key : readSelector.keys()) {
                // An invalid key specifies that either the channel was closed
                // (in which case we do not have to do anything else to it) or
                // that we no longer control the channel (i.e. we do not want to
                // do anything else to it). 
                if (!key.isValid()) {
                    continue;
                }
                ChannelDesc channelDesc = (ChannelDesc) key.attachment();
                if (channelDesc == null) {
                    continue;
                }
                long lastActive = channelDesc.lastActive;
                if (lastActive != -1 && now - lastActive > SOCKET_CHANNEL_READ_TIMEOUT) {
                    // De-register from the Selector.
                    key.cancel();
                    SocketChannel channel = channelDesc.channel;
                    logger.debug("Read timeout for socket {}", channel.socket());
                    closeNoExceptions(channel);
                }
            }
        }

        /**
         * Tries to read, without blocking, from channel to its buffer. If after reading the buffer is filled, handles the data in
         * the buffer.
         *
         * This works in three stages:
         * 1 (optional): Read a fixed-size message. If it matches the hard-coded pseudo SSL ClientHello, sends the hard-coded ServerHello.
         * 2: Read two bytes as an unsigned int and interpret it as the length to read in the next stage.
         * 3: Read number of bytes indicated in stage2 and try to interpret them as a STUN message.
         *
         * If a datagram is successfully read it is passed on to {@link #processFirstDatagram(byte[], ChannelDesc, SelectionKey)}
         *
         * @param channel the SocketChannel to read from.
         * @param key the SelectionKey associated with channel, which is to be canceled in case no further
         * reading is required from the channel.
         */
        private void readFromChannel(ChannelDesc channel, SelectionKey key) {
            if (channel.buffer == null) {
                // Set up a buffer with a pre-determined size
                if (!channel.checkedForSSLHandshake && channel.length == -1) {
                    channel.buffer = ByteBuffer.allocate(TurnCandidateHarvester.SSL_CLIENT_HANDSHAKE.length);
                } else if (channel.length == -1) {
                    channel.buffer = ByteBuffer.allocate(2);
                } else {
                    channel.buffer = ByteBuffer.allocate(channel.length);
                }
            }

            try {
                int read = channel.channel.read(channel.buffer);

                if (read == -1)
                    throw new IOException("End of stream!");
                else if (read > 0)
                    channel.lastActive = System.currentTimeMillis();

                if (!channel.buffer.hasRemaining()) {
                    // We've filled in the buffer.
                    if (!channel.checkedForSSLHandshake) {
                        byte[] bytesRead = new byte[TurnCandidateHarvester.SSL_CLIENT_HANDSHAKE.length];

                        channel.buffer.flip();
                        channel.buffer.get(bytesRead);

                        // Set to null, so that we re-allocate it for the next stage
                        channel.buffer = null;
                        channel.checkedForSSLHandshake = true;

                        if (Arrays.equals(bytesRead, TurnCandidateHarvester.SSL_CLIENT_HANDSHAKE)) {
                            ByteBuffer byteBuffer = ByteBuffer.wrap(TurnCandidateHarvester.SSL_SERVER_HANDSHAKE);
                            channel.channel.write(byteBuffer);
                        } else {
                            int fb = bytesRead[0];
                            int sb = bytesRead[1];

                            channel.length = (((fb & 0xff) << 8) | (sb & 0xff));

                            byte[] preBuffered = Arrays.copyOfRange(bytesRead, 2, bytesRead.length);

                            // if we had read enough data
                            if (channel.length <= bytesRead.length - 2) {
                                processFirstDatagram(preBuffered, channel, key);
                            } else {
                                // not enough data, store what was read
                                // and continue
                                channel.preBuffered = preBuffered;

                                channel.length -= channel.preBuffered.length;
                            }
                        }
                    } else if (channel.length == -1) {
                        channel.buffer.flip();

                        int fb = channel.buffer.get();
                        int sb = channel.buffer.get();

                        channel.length = (((fb & 0xff) << 8) | (sb & 0xff));

                        // Set to null, so that we re-allocate it for the next stage
                        channel.buffer = null;
                    } else {
                        byte[] bytesRead = new byte[channel.length];

                        channel.buffer.flip();
                        channel.buffer.get(bytesRead);

                        if (channel.preBuffered != null) {
                            // will store preBuffered and currently read data
                            byte[] newBytesRead = new byte[channel.preBuffered.length + bytesRead.length];

                            // copy old data
                            System.arraycopy(channel.preBuffered, 0, newBytesRead, 0, channel.preBuffered.length);
                            // and new data
                            System.arraycopy(bytesRead, 0, newBytesRead, channel.preBuffered.length, bytesRead.length);

                            // use that data for processing
                            bytesRead = newBytesRead;

                            channel.preBuffered = null;
                        }

                        processFirstDatagram(bytesRead, channel, key);
                    }
                }
            } catch (IOException | IllegalStateException e) {
                logger.warn("Failed to handle TCP socket {}", channel.channel.socket(), e);
                key.cancel();
                closeNoExceptions(channel.channel);
            }
        }

        /**
         * Process the first RFC4571-framed datagram read from a socket.
         *
         * If the datagram contains a STUN Binding Request, and it has a USERNAME attribute, the local &quot;ufrag&quot; is extracted from the
         * attribute value, and the socket is passed to {@link #acceptSession(Socket, String, DatagramPacket)}.
         *
         * @param bytesRead bytes to be processed
         * @param channel the SocketChannel to read from.
         * @param key the SelectionKey associated with channel, which is to be canceled in case no further
         * reading is required from the channel.
         * @throws IOException if the datagram does not contain s STUN Binding Request with a USERNAME attribute.
         * @throws IllegalStateException if the session for the extracted username fragment cannot be accepted for implementation reasons
         * (e.g. no ICE Agent with the given local ufrag is found).
         */
        private void processFirstDatagram(byte[] bytesRead, ChannelDesc channelDesc, SelectionKey key) throws IOException, IllegalStateException {
            // Does this look like a STUN binding request? What's the username?
            String ufrag = IceDecoder.getUfrag(bytesRead, 0, bytesRead.length);
            if (ufrag == null) {
                throw new IOException("Cannot extract ufrag");
            }
            // The rest of the stack will read from the socket's InputStream. We cannot change the blocking mode
            // before the channel is removed from the selector (by canceling the key)
            key.cancel();
            channelDesc.channel.configureBlocking(true);
            // Construct a DatagramPacket from the just-read packet which is to be pushed back
            DatagramPacket p = new DatagramPacket(bytesRead, bytesRead.length);
            Socket socket = channelDesc.channel.socket();
            p.setAddress(socket.getInetAddress());
            p.setPort(socket.getPort());
            acceptSession(socket, ufrag, p);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void run() {
            do {
                synchronized (AbstractTcpListener.this) {
                    if (close) {
                        break;
                    }
                }
                // clean up stale channels
                cleanup();
                checkForNewChannels();
                for (SelectionKey key : readSelector.keys()) {
                    if (key.isValid()) {
                        ChannelDesc channelDesc = (ChannelDesc) key.attachment();

                        readFromChannel(channelDesc, key);
                    }
                }
                // We read from all SocketChannels.
                readSelector.selectedKeys().clear();
                try {
                    readSelector.select(SOCKET_CHANNEL_READ_TIMEOUT / 2);
                } catch (IOException ioe) {
                    logger.warn("Failed to select a read-ready channel", ioe);
                }
            } while (true);
            //we are all done, clean up.
            synchronized (newChannels) {
                for (SocketChannel channel : newChannels) {
                    closeNoExceptions(channel);
                }
                newChannels.clear();
            }
            for (SelectionKey key : readSelector.keys()) {
                // An invalid key specifies that either the channel was closed (in which case we do not have to do anything else to it) or
                // that we no longer control the channel (i.e. we do not want to do anything else to it).
                if (key.isValid()) {
                    Channel channel = key.channel();
                    if (channel.isOpen()) {
                        closeNoExceptions(channel);
                    }
                }
            }
            try {
                readSelector.close();
            } catch (IOException ioe) {
            }
        }
    }
}
