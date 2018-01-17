/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal. Copyright @ 2015 Atlassian Pty Ltd Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or
 * agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under the License.
 */
package org.ice4j.socket;

import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.Socket;
import java.net.SocketException;
import java.util.List;
import java.util.logging.Logger;

import org.ice4j.socket.filter.DatagramPacketFilter;

/**
 * Represents a Socket which receives DatagramPackets
 * selected by a DatagramPacketFilter from a
 * MultiplexingSocket. The associated MultiplexingSocket is
 * the actual Socket which reads the DatagramPackets from the
 * network. The DatagramPackets received through the
 * MultiplexedSocket will not be received through the
 * associated MultiplexingSocket.
 *
 * @author Sebastien Vincent
 */
public class MultiplexedSocket extends DelegatingSocket implements MultiplexedXXXSocket {
    /**
     * The Logger used by the MultiplexedSocket class and its
     * instances for logging output.
     */
    private static final Logger logger = Logger.getLogger(MultiplexedSocket.class.getName());

    /**
     * The DatagramPacketFilter which determines which
     * DatagramPackets read from the network by {@link #multiplexing}
     * are to be received through this instance.
     */
    private final DatagramPacketFilter filter;

    /**
     * The custom InputStream for this MultiplexedSocket.
     */
    private final InputStream inputStream = new InputStreamImpl();

    /**
     * The MultiplexingSocket which does the actual reading from the
     * network and which forwards DatagramPackets accepted by
     * {@link #filter} for receipt to this instance.
     */
    private final MultiplexingSocket multiplexing;

    /**
     * The list of DatagramPackets to be received through this
     * Socket i.e. accepted by {@link #filter}.
     */
    final List<DatagramPacket> received = new SocketReceiveBuffer() {
        private static final long serialVersionUID = 678744096057601141L;

        @Override
        public int getReceiveBufferSize() throws SocketException {
            return MultiplexedSocket.this.getReceiveBufferSize();
        }
    };

    /**
     * Initializes a new MultiplexedSocket which is unbound and filters
     * DatagramPackets away from a specific MultiplexingSocket
     * using a specific DatagramPacketFilter.
     *
     * @param multiplexing the MultiplexingSocket which does the actual
     * reading from the network and which forwards DatagramPackets
     * accepted by the specified filter to the new instance
     * @param filter the DatagramPacketFilter which determines which
     * DatagramPackets read from the network by the specified
     * multiplexing are to be received through the new instance
     * @throws SocketException if the socket could not be opened
     */
    MultiplexedSocket(MultiplexingSocket multiplexing, DatagramPacketFilter filter) throws SocketException {
        /*
         * Even if MultiplexingSocket allows MultiplexedSocket to perform bind, binding in the super will not execute correctly this early in the construction because the
         * multiplexing field is not set yet. That is why MultiplexedSocket does not currently support bind at construction time.
         */
        super(multiplexing);

        if (multiplexing == null)
            throw new NullPointerException("multiplexing");

        this.multiplexing = multiplexing;
        this.filter = filter;
    }

    /**
     * Closes this datagram socket.
     * <p>
     * Any thread currently blocked in {@link #receive(DatagramPacket)} upon
     * this socket will throw a {@link SocketException}.
     * </p>
     *
     * @see Socket#close()
     */
    @Override
    public void close() {
        multiplexing.close(this);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public DatagramPacketFilter getFilter() {
        return filter;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public InputStream getInputStream() {
        return inputStream;
    }

    /**
     * Receives a datagram packet from this socket. When this method returns,
     * the DatagramPacket's buffer is filled with the data received.
     * The datagram packet also contains the sender's IP address, and the port
     * number on the sender's machine.
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
     * @see MultiplexingSocket#receive(DatagramPacket)
     */
    @Override
    public void receive(DatagramPacket p) throws IOException {
        multiplexing.receive(this, p);
    }

    /**
     * Implements an InputStream for this MultiplexedSocket,
     * reading data using {@link #receive(java.net.DatagramPacket)}.
     */
    private class InputStreamImpl extends InputStream {
        /**
         * A buffer to receive data into.
         */
        private final byte[] buf = new byte[1500];

        /**
         * A DatagramPacket instance to receive data into.
         */
        private final DatagramPacket packet = new DatagramPacket(buf, 1500);

        /**
         * Initializes a new TCPInputStream.
         */
        public InputStreamImpl() {
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public int available() {
            return 0;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean markSupported() {
            return false;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public int read() throws IOException {
            // We don't support reading a single byte
            return 0;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public int read(byte[] b) throws IOException {
            return read(b, 0, b.length);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (off == 0) // optimization: avoid copy to b
            {
                packet.setData(b);
                receive(packet);

                int lengthRead = packet.getLength();

                if (packet.getData() == b && lengthRead <= len) {
                    return lengthRead;
                } else {
                    logger.warning("Failed to read directly into the provided buffer, len=" + len + " lengthRead=" + lengthRead + " (packet.getData() == b)=" + (packet.getData() == b));
                }
            }

            // either there's an offset to take into account, or receiving
            // directly in 'b' failed.

            packet.setData(buf);
            receive(packet);

            int packetLen = packet.getLength();
            int lengthRead = Math.min(len, packetLen);

            System.arraycopy(packet.getData(), packet.getOffset(), b, off, lengthRead);

            return lengthRead;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void reset() throws IOException {
            if (!markSupported()) {
                throw new IOException("InputStreamImpl does not support reset()");
            }
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public long skip(long n) throws IOException {
            throw new IOException("InputStreamImpl does not support skip.");
        }
    }
}
