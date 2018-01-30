/* See LICENSE.md for license information */
package org.ice4j.socket;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

/**
 * TCP implementation of the IceSocketWrapper.
 *
 * @author Sebastien Vincent
 * @author Paul Gregoire
 */
public class IceTcpSocketWrapper extends IceSocketWrapper {

    /**
     * The ByteBuffer instance used in {@link #receiveFromChannel(java.nio.channels.SocketChannel, java.net.DatagramPacket)} to read the 2-byte length field into.
     */
    private final ByteBuffer frameLengthByteBuffer = ByteBuffer.allocate(2);

    /**
     * Constructor.
     *
     * @param delegate delegate Socket
     *
     * @throws IOException if something goes wrong during initialization
     */
    public IceTcpSocketWrapper(SocketChannel channel) throws IOException {
        super(channel);
        try {
            channel.setOption(StandardSocketOptions.TCP_NODELAY, true);
        } catch (SocketException ex) {
        }
    }

    /** {@inheritDoc} */
    @Override
    public void send(DatagramPacket p) throws IOException {
        int len = p.getLength();
        int off = p.getOffset();
        ByteBuffer data = ByteBuffer.allocate(len + 2);
        data.put((byte) ((len >> 8) & 0xff));
        data.put((byte) (len & 0xff));
        data.put(p.getData(), off, len);
        ((SocketChannel) channel).write(data);
    }

    /**
     * {@inheritDoc}
     * <br>
     * Receives an RFC4571-formatted frame from channel into p, and sets p's port and address to the remote port
     * and address of this Socket.
     */
    @Override
    public void receive(DatagramPacket p) throws IOException {
        SocketChannel socketChannel = (SocketChannel) channel;
        while (frameLengthByteBuffer.hasRemaining()) {
            int read = socketChannel.read(frameLengthByteBuffer);
            if (read == -1) {
                throw new SocketException("Failed to receive data from socket.");
            }
        }
        frameLengthByteBuffer.flip();
        int b0 = frameLengthByteBuffer.get();
        int b1 = frameLengthByteBuffer.get();
        int frameLength = ((b0 & 0xFF) << 8) | (b1 & 0xFF);
        frameLengthByteBuffer.flip();
        byte[] data = p.getData();
        if (data == null || data.length < frameLength) {
            data = new byte[frameLength];
        }
        ByteBuffer byteBuffer = ByteBuffer.wrap(data, 0, frameLength);
        while (byteBuffer.hasRemaining()) {
            int read = socketChannel.read(byteBuffer);
            if (read == -1) {
                throw new SocketException("Failed to receive data from socket.");
            }
        }
        p.setAddress(socketChannel.socket().getInetAddress());
        p.setData(data, 0, frameLength);
        p.setPort(socketChannel.socket().getPort());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public InetAddress getLocalAddress() {
        return ((SocketChannel) channel).socket().getLocalAddress();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getLocalPort() {
        return ((SocketChannel) channel).socket().getLocalPort();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public SocketAddress getLocalSocketAddress() {
        try {
            return ((SocketChannel) channel).getLocalAddress();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}
