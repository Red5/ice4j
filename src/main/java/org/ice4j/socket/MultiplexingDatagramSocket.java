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
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.List;

import org.ice4j.socket.filter.DatagramPacketFilter;

/**
 * Represents a DatagramSocket which allows filtering DatagramPackets it reads from the network using
 * DatagramPacketFilters so that the DatagramPackets do not get received through it but through associated
 * MultiplexedDatagramSockets.
 *
 * @author Lyubomir Marinov
 */
public class MultiplexingDatagramSocket extends DelegatingDatagramSocket {
    /**
     * The {@code MultiplexingXXXSocketSupport} which implements functionality
     * common to TCP and UDP sockets in order to facilitate implementers such as
     * this instance.
     */
    private final MultiplexingXXXSocketSupport<MultiplexedDatagramSocket> multiplexingXXXSocketSupport = new MultiplexingXXXSocketSupport<MultiplexedDatagramSocket>() {
        /**
         * {@inheritDoc}
         */
        @Override
        protected MultiplexedDatagramSocket createSocket(DatagramPacketFilter filter) throws SocketException {
            return new MultiplexedDatagramSocket(MultiplexingDatagramSocket.this, filter);
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
        protected List<DatagramPacket> getReceived(MultiplexedDatagramSocket socket) {
            return socket.received;
        }
    };

    /**
     * The list of DatagramPackets to be received through this
     * DatagramSocket i.e. not accepted by the DatagramFilters
     * of {@link #sockets} at the time of the reading from the network.
     */
    private final List<DatagramPacket> received = new SocketReceiveBuffer() {
        private static final long serialVersionUID = 3125772367019091216L;

        @Override
        public int getReceiveBufferSize() throws SocketException {
            return MultiplexingDatagramSocket.this.getReceiveBufferSize();
        }
    };

    /**
     * Buffer variable for storing the SO_TIMEOUT value set by the
     * last setSoTimeout() call. Although not strictly needed,
     * getting the locally stored value as opposed to retrieving it
     * from a parent getSoTimeout() call seems to
     * significantly improve efficiency, at least on some platforms.
     */
    private int soTimeout = 0;

    /**
     * Initializes a new MultiplexingDatagramSocket instance which is
     * to enable DatagramPacket filtering and binds it to any available
     * port on the local host machine. The socket will be bound to the wildcard
     * address, an IP address chosen by the kernel.
     *
     * @throws SocketException if the socket could not be opened, or the socket
     * could not bind to the specified local port
     * @see DatagramSocket#DatagramSocket()
     */
    public MultiplexingDatagramSocket() throws SocketException {
    }

    /**
     * Initializes a new MultiplexingDatagramSocket instance which is
     * to enable DatagramPacket filtering on a specific
     * DatagramSocket.
     *
     * @param delegate the DatagramSocket on which
     * DatagramPacket filtering is to be enabled by the new instance
     * @throws SocketException if anything goes wrong while initializing the new
     * instance
     */
    public MultiplexingDatagramSocket(DatagramSocket delegate) throws SocketException {
        super(delegate);
    }

    /**
     * Initializes a new MultiplexingDatagramSocket instance which is
     * to enable DatagramPacket filtering and binds it to the specified
     * port on the local host machine. The socket will be bound to the wildcard
     * address, an IP address chosen by the kernel.
     *
     * @param port the port to bind the new socket to
     * @throws SocketException if the socket could not be opened, or the socket
     * could not bind to the specified local port
     * @see DatagramSocket#DatagramSocket(int)
     */
    public MultiplexingDatagramSocket(int port) throws SocketException {
        super(port);
    }

    /**
     * Initializes a new MultiplexingDatagramSocket instance which is
     * to enable DatagramPacket filtering, bound to the specified local
     * address. The local port must be between 0 and 65535 inclusive. If the IP
     * address is 0.0.0.0, the socket will be bound to the wildcard address, an
     * IP address chosen by the kernel.
     *
     * @param port the local port to bind the new socket to
     * @param laddr the local address to bind the new socket to
     * @throws SocketException if the socket could not be opened, or the socket
     * could not bind to the specified local port
     * @see DatagramSocket#DatagramSocket(int, InetAddress)
     */
    public MultiplexingDatagramSocket(int port, InetAddress laddr) throws SocketException {
        super(port, laddr);
    }

    /**
     * Initializes a new MultiplexingDatagramSocket instance which is
     * to enable DatagramPacket filtering, bound to the specified local
     * socket address.
     * <p>
     * If the specified local socket address is null, creates an
     * unbound socket.
     * </p>
     *
     * @param bindaddr local socket address to bind, or null for an
     * unbound socket
     * @throws SocketException if the socket could not be opened, or the socket
     * could not bind to the specified local port
     * @see DatagramSocket#DatagramSocket(SocketAddress)
     */
    public MultiplexingDatagramSocket(SocketAddress bindaddr) throws SocketException {
        super(bindaddr);
    }

    /**
     * Closes a specific MultiplexedDatagramSocket which filters
     * DatagramPackets away from this DatagramSocket.
     *
     * @param multiplexed the MultiplexedDatagramSocket to close
     */
    void close(MultiplexedDatagramSocket multiplexed) {
        multiplexingXXXSocketSupport.close(multiplexed);
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
    public MultiplexedDatagramSocket getSocket(DatagramPacketFilter filter) throws SocketException {
        return getSocket(filter, /* create */true);
    }

    /**
     * Gets a MultiplexedDatagramSocket which filters
     * DatagramPackets away from this DatagramSocket using a
     * specific DatagramPacketFilter. If create is true and
     * such a MultiplexedDatagramSocket does not exist in this
     * instance, it is created.
     *
     * @param filter the DatagramPacketFilter to get a
     * MultiplexedDatagramSocket for
     * @param create whether or not to create a
     * MultiplexedDatagramSocket if this instance does not already have
     * a socket for the given filter.
     * @return a MultiplexedDatagramSocket which filters
     * DatagramPackets away from this DatagramSocket using the
     * specified filter
     * @throws SocketException if creating the
     * MultiplexedDatagramSocket for the specified filter
     * fails.
     */
    public MultiplexedDatagramSocket getSocket(DatagramPacketFilter filter, boolean create) throws SocketException {
        return multiplexingXXXSocketSupport.getSocket(filter, create);
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
     * such as a UDP error
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
     * @throws SocketTimeoutException if setSoTimeout(int) was
     * previously called and the timeout has expired
     * @see DatagramSocket#receive(DatagramPacket)
     */
    @Override
    public void receive(DatagramPacket p) throws IOException {
        multiplexingXXXSocketSupport.receive(received, p, soTimeout);
    }

    /**
     * Receives a DatagramPacket from this DatagramSocket upon
     * request from a specific MultiplexedDatagramSocket.
     *
     * @param multiplexed the MultiplexedDatagramSocket which requests
     * the receipt of a DatagramPacket from the network
     * @param p the DatagramPacket to receive the data from the network
     * @throws IOException if an I/O error occurs
     * @throws SocketTimeoutException if setSoTimeout(int) was
     * previously called on multiplexed and the timeout has expired
     */
    void receive(MultiplexedDatagramSocket multiplexed, DatagramPacket p) throws IOException {
        multiplexingXXXSocketSupport.receive(multiplexed.received, p, multiplexed.getSoTimeout());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setReceiveBufferSize(int receiveBufferSize) throws SocketException {
        multiplexingXXXSocketSupport.setReceiveBufferSize(receiveBufferSize);
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
