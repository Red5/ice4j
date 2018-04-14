/* See LICENSE.md for license information */
package org.ice4j.socket;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;

import org.apache.mina.core.session.IoSession;
import org.ice4j.Transport;
import org.ice4j.TransportAddress;

/**
 * TCP implementation of the IceSocketWrapper.
 * 
 * @author Paul Gregoire
 */
public class IceTcpSocketWrapper extends IceSocketWrapper {

    /**
     * Constructor.
     *
     * @param delegate delegate Socket
     *
     * @throws IOException if something goes wrong during initialization
     */
    public IceTcpSocketWrapper(IoSession session) throws IOException {
        super(session);
        try {
            transportAddress = new TransportAddress((InetSocketAddress) session.getLocalAddress(), Transport.TCP);
        } catch (Exception e) {
            logger.warn("Exception configuring transport address", e);
        }
    }

    /**
     * Constructor.
     *
     * @param address TransportAddress
     * @throws IOException 
     */
    public IceTcpSocketWrapper(TransportAddress address) throws IOException {
        super((IoSession) null);
        transportAddress = address;
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
        session.write(data);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public InetAddress getLocalAddress() {
        return transportAddress.getAddress();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getLocalPort() {
        return transportAddress.getPort();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public SocketAddress getLocalSocketAddress() {
        if (session == null) {
            return transportAddress;
        }
        return session.getLocalAddress();
    }

    @Override
    public String toString() {
        return "IceTcpSocketWrapper [transportAddress=" + transportAddress + ", session=" + session + "]";
    }

}

