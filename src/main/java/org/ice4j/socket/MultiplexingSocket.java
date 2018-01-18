/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal. Copyright @ 2015 Atlassian Pty Ltd Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or
 * agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under the License.
 */
package org.ice4j.socket;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketImpl;
import java.util.List;
import java.util.logging.Logger;

import org.ice4j.socket.filter.DatagramPacketFilter;

/**
 * Represents a Socket which allows filtering DatagramPackets
 * it reads from the network using DatagramPacketFilters so that the
 * DatagramPackets do not get received through it but through
 * associated MultiplexedSockets.
 *
 * @author Sebastien Vincent
 * @author Lyubomir Marinov
 */
public class MultiplexingSocket {
    /**
     * The Logger used by the MultiplexingSocket class and its
     * instances for logging output.
     */
    private static final Logger logger = Logger.getLogger(MultiplexingSocket.class.getName());

    /**
     * Custom InputStream for this Socket.
     */
    private final InputStream inputStream = new TCPInputStream(this);

    /**
     * The {@code MultiplexingXXXSocketSupport} which implements functionality
     * common to TCP and UDP sockets in order to facilitate implementers such as
     * this instance.
     */
    private final MultiplexingXXXSocketSupport<MultiplexedSocket> multiplexingXXXSocketSupport = new MultiplexingXXXSocketSupport<MultiplexedSocket>() {
        /**
         * {@inheritDoc}
         */
        @Override
        protected MultiplexedSocket createSocket(DatagramPacketFilter filter) throws SocketException {
            return new MultiplexedSocket(MultiplexingSocket.this, filter);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        protected void doReceive(DatagramPacket p) throws IOException {
            multiplexingXXXSocketSupportDoReceive(p);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        protected void doSetReceiveBufferSize(int receiveBufferSize) throws SocketException {
            multiplexingXXXSocketSupportDoSetReceiveBufferSize(receiveBufferSize);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        protected List<DatagramPacket> getReceived() {
            return received;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        protected List<DatagramPacket> getReceived(MultiplexedSocket socket) {
            return socket.received;
        }
    };

    /**
     * Custom OutputStream for this Socket.
     */
    private TCPOutputStream outputStream;

    /**
     * The list of DatagramPackets to be received through this
     * Socket i.e. not accepted by the DatagramFilters of
     * {@link #sockets} at the time of the reading from the network.
     */
    private final List<DatagramPacket> received = new SocketReceiveBuffer() {
        private static final long serialVersionUID = 4097024214973676873L;

        @Override
        public int getReceiveBufferSize() throws SocketException {
            return MultiplexingSocket.this.getReceiveBufferSize();
        }
    };

    /**
     * Buffer variable for storing the SO_TIMEOUT value set by the last
     * setSoTimeout() call. Although not strictly needed, getting the
     * locally stored value as opposed to retrieving it from a parent
     * getSoTimeout() call seems to significantly improve efficiency,
     * at least on some platforms.
     */
    private int soTimeout = 0;

    /**
     * Initializes a new MultiplexingSocket instance.
     *
     * @see Socket#Socket()
     */
    public MultiplexingSocket() {
        this((Socket) null);
    }

    /**
     * Initializes a new MultiplexingSocket instance.
     *
     * @param address not used
     * @param port not used
     * @see Socket#Socket(InetAddress, int)
     */
    public MultiplexingSocket(InetAddress address, int port) {
        this((Socket) null);
    }

    /**
     * Initializes a new MultiplexingSocket instance.
     *
     * @param address not used
     * @param port not used
     * @param localAddr not used
     * @param localPort not used
     * @see Socket#Socket(InetAddress, int, InetAddress, int)
     */
    public MultiplexingSocket(InetAddress address, int port, InetAddress localAddr, int localPort) {
        this((Socket) null);
    }

    /**
     * Initializes a new MultiplexingSocket instance.
     *
     * @param proxy not used
     * @see Socket#Socket(Proxy)
     */
    public MultiplexingSocket(Proxy proxy) {
        this((Socket) null);
    }

    /**
     * Initializes a new MultiplexingSocket instance.
     *
     * @param socket delegate socket
     */
    public MultiplexingSocket(Socket socket) {
        super(socket);

        try {
            setTcpNoDelay(true);
        } catch (SocketException ex) {
            logger.info("Cannot SO_TCPNODELAY");
        }
    }

    /**
     * Initializes a new MultiplexingSocket instance.
     *
     * @param impl not used
     * @see Socket#Socket(SocketImpl)
     */
    protected MultiplexingSocket(SocketImpl impl) {
        this((Socket) null);
    }

    /**
     * Initializes a new MultiplexingSocket instance.
     *
     * @param host not used
     * @param port not used
     * @see Socket#Socket(String, int)
     */
    public MultiplexingSocket(String host, int port) {
        this((Socket) null);
    }

    /**
     * Initializes a new MultiplexingSocket instance.
     *
     * @param host not used
     * @param port not used
     * @param localAddr not used
     * @param localPort not used
     * @see Socket#Socket(String, int, InetAddress, int)
     */
    public MultiplexingSocket(String host, int port, InetAddress localAddr, int localPort) {
        this((Socket) null);
    }

    /**
     * Closes a specific MultiplexedSocket which filters
     * DatagramPackets away from this Socket.
     *
     * @param multiplexed the MultiplexedSocket to close
     */
    void close(MultiplexedSocket multiplexed) {
        multiplexingXXXSocketSupport.close(multiplexed);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public InputStream getInputStream() throws IOException {
        return inputStream;
    }

    /**
     * Get original InputStream.
     *
     * @return original InputStream
     * @throws IOException if something goes wrong
     */
    public InputStream getOriginalInputStream() throws IOException {
        return super.getInputStream();
    }

    /**
     * Get original OutputStream.
     *
     * @return original OutputStream
     * @throws IOException if something goes wrong
     */
    public OutputStream getOriginalOutputStream() throws IOException {
        return super.getOutputStream();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public OutputStream getOutputStream() throws IOException {
        if (outputStream == null)
            outputStream = new TCPOutputStream(super.getOutputStream());
        return outputStream;
    }

    /**
     * Gets a MultiplexedDatagramSocket which filters
     * DatagramPackets away from this DatagramSocket using a
     * specific DatagramPacketFilter. If such a
     * MultiplexedDatagramSocket does not exist in this instance, it is
     * created.
     *
     * @param filter the DatagramPacketFilter to get a
     * MultiplexedDatagramSocket for
     * @return a MultiplexedDatagramSocket which filters
     * DatagramPackets away from this DatagramSocket using the
     * specified filter
     * @throws SocketException if creating the
     * MultiplexedDatagramSocket for the specified filter
     * fails
     */
    public MultiplexedSocket getSocket(DatagramPacketFilter filter) throws SocketException {
        return multiplexingXXXSocketSupport.getSocket(filter);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getSoTimeout() {
        return soTimeout;
    }

    /**
     * Implements {@link MultiplexingXXXSocketSupport#doReceive(DatagramPacket)}
     * on behalf of {@link #multiplexingXXXSocketSupport}. Receives a
     * {@code DatagramPacket} from this socket.
     *
     * @param p the {@code DatagramPacket} into which to place the incoming data
     * @throws IOException if an I/O error occurs
     */
    private void multiplexingXXXSocketSupportDoReceive(DatagramPacket p) throws IOException {
        super.receive(p);
    }

    /**
     * Implements
     * {@link MultiplexingXXXSocketSupport#doSetReceiveBufferSize(int)} on
     * behalf of {@link #multiplexingXXXSocketSupport}. Sets the
     * {@code SO_RCVBUF} option to the specified value for this
     * {@code DatagramSocket}. The {@code SO_RCVBUF} option is used by the
     * network implementation as a hint to size the underlying network I/O
     * buffers. The {@code SO_RCVBUF} setting may also be used by the network
     * implementation to determine the maximum size of the packet that can be
     * received on this socket.
     *
     * @param receiveBufferSize the size to which to set the receive buffer size
     * @throws SocketException if there is an error in the underlying protocol,
     * such as a TCP error
     */
    private void multiplexingXXXSocketSupportDoSetReceiveBufferSize(int receiveBufferSize) throws SocketException {
        super.setReceiveBufferSize(receiveBufferSize);
    }

    /**
     * Receives a datagram packet from this socket. The DatagramPackets
     * returned by this method do not match any of the
     * DatagramPacketFilters of the MultiplexedDatagramSockets
     * associated with this instance at the time of their receipt. When this
     * method returns, the DatagramPacket's buffer is filled with the
     * data received. The datagram packet also contains the sender's IP address,
     * and the port number on the sender's machine.
     * <p>
     * This method blocks until a datagram is received. The length
     * field of the datagram packet object contains the length of the received
     * message. If the message is longer than the packet's length, the message
     * is truncated.
     * </p>
     *
     * @param p the DatagramPacket into which to place the incoming
     * data
     * @throws IOException if an I/O error occurs
     * @see DelegatingSocket#receive(DatagramPacket)
     */
    @Override
    public void receive(DatagramPacket p) throws IOException {
        try {
            setOriginalInputStream(super.getInputStream());
        } catch (Exception e) {
        }

        multiplexingXXXSocketSupport.receive(received, p, soTimeout);
    }

    /**
     * Receives a DatagramPacket from this Socket upon
     * request from a specific MultiplexedSocket.
     *
     * @param multiplexed the MultiplexedSocket which requests
     * the receipt of a DatagramPacket from the network
     * @param p the DatagramPacket to receive the data from the network
     * @throws IOException if an I/O error occurs
     */
    void receive(MultiplexedSocket multiplexed, DatagramPacket p) throws IOException {
        try {
            setOriginalInputStream(super.getInputStream());
        } catch (Exception e) {
        }

        multiplexingXXXSocketSupport.receive(multiplexed.received, p, multiplexed.getSoTimeout());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setSoTimeout(int timeout) throws SocketException {
        super.setSoTimeout(timeout);

        soTimeout = timeout;
    }
}
