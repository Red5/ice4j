/* See LICENSE.md for license information */
package org.ice4j.socket;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.future.ConnectFuture;
import org.apache.mina.core.future.IoFutureListener;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.transport.socket.nio.NioDatagramConnector;
import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.ice.nio.IceUdpTransport;

/**
 * UDP implementation of the IceSocketWrapper.
 *
 * @author Paul Gregoire
 */
public class IceUdpSocketWrapper extends IceSocketWrapper {

    /**
     * Constructor.
     *
     * @param session
     */
    public IceUdpSocketWrapper(IoSession session) {
        super(session);
        if (session != null) {
            try {
                transportAddress = new TransportAddress((InetSocketAddress) session.getLocalAddress(), Transport.UDP);
            } catch (Exception e) {
                logger.warn("Exception configuring transport address", e);
            }
        } else {
            logger.debug("Datagram channel is not bound");
        }
    }

    /**
     * Constructor.
     *
     * @param address TransportAddress
     * @throws IOException 
     */
    public IceUdpSocketWrapper(TransportAddress address) throws IOException {
        super((IoSession) null);
        transportAddress = address;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void send(DatagramPacket p) throws IOException {
        if (logger.isDebugEnabled()) {
            logger.debug("send: {}", p);
        }
        if (session != null) {
            session.write(IoBuffer.wrap(p.getData()), p.getSocketAddress());
        } else {
            //InetSocketAddress inetAddr = InetSocketAddress.createUnresolved(transportAddress.getHostString(), transportAddress.getPort());
            logger.debug("No session, attempting connect: {}", transportAddress);
            NioDatagramConnector connector = new NioDatagramConnector();
            // re-use the io handler
            connector.setHandler(IceUdpTransport.getInstance().getIoHandler());
            ConnectFuture future = connector.connect(p.getSocketAddress(), transportAddress);
            future.addListener(new IoFutureListener<ConnectFuture>() {

                @Override
                public void operationComplete(ConnectFuture future) {
                    session = future.getSession();
                }

            });
            if (future.awaitUninterruptibly(3000L)) {
                session.write(IoBuffer.wrap(p.getData()), p.getSocketAddress());
            } else {
                logger.warn("Send failed");
            }
        }
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

}
