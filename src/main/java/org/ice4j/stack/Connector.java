/* See LICENSE.md for license information */
package org.ice4j.stack;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.mina.core.buffer.IoBuffer;
import org.ice4j.TransportAddress;
import org.ice4j.socket.IceSocketWrapper;

/**
 * The Network Access Point is the most outward part of the stack. It is constructed around socket and sends datagrams to the STUN server
 * specified by the original NetAccessPointDescriptor.
 *
 * @author Emil Ivov
 */
class Connector {

    /**
     * The socket object that used by this access point to access the network.
     */
    private final IceSocketWrapper sock;

    /**
     * The address that we are listening to.
     */
    private final TransportAddress listenAddress;

    /**
     * The remote address of the socket of this Connector if it is a TCP socket, or null if it is UDP.
     */
    private final TransportAddress remoteAddress;

    private final NetAccessManager netAccessManager;

    /**
     * Whether or not the connector is alive (not yet stopped)
     */
    private final AtomicBoolean alive = new AtomicBoolean(true);

    /**
     * Creates a network access point.
     * 
     * @param socket the socket that this access point is supposed to use for communication
     * @param remoteAddress the remote address of the socket of this {@link Connector} if it is a TCP socket, or null if it is UDP
     */
    protected Connector(IceSocketWrapper socket, TransportAddress remoteAddress, NetAccessManager netAccessManager) {
        this.sock = socket;
        this.remoteAddress = remoteAddress;
        this.netAccessManager = netAccessManager;
        listenAddress = socket.getTransportAddress();
    }

    /**
     * Returns the DatagramSocket that contains the port and address associated with this access point.
     *
     * @return the DatagramSocket associated with this AP.
     */
    protected IceSocketWrapper getSocket() {
        return sock;
    }

    /**
     * Returns alive status.
     * 
     * @return true if alive and false if stopped
     */
    public boolean isAlive() {
        return alive.get();
    }

    /**
     * Makes the access point stop listening on its socket.
     */
    protected void stop() {
        if (alive.compareAndSet(true, false)) {
            netAccessManager.removeSocket(listenAddress, remoteAddress);
            sock.close();
        }
    }

    /**
     * Sends message through this access point's socket.
     *
     * @param message the bytes to send
     * @param address message destination
     * @throws IOException if an exception occurs while sending the message
     */
    void sendMessage(byte[] message, TransportAddress address) throws IOException {
        // update stun/turn message/byte counters
        sock.updateWriteCounters((message != null ? message.length : 0), 1);
        // send the message
        sock.send(IoBuffer.wrap(message), address);
    }

    /**
     * Returns the TransportAddress that this access point is bound on.
     *
     * @return the TransportAddress associated with this AP.
     */
    TransportAddress getListenAddress() {
        return listenAddress;
    }

    /**
     * Returns the remote TransportAddress or null if none is specified.
     *
     * @return the remote TransportAddress or null if none is specified.
     */
    TransportAddress getRemoteAddress() {
        return remoteAddress;
    }

    /**
     * Returns a String representation of the object.
     * @return a String representation of the object.
     */
    @Override
    public String toString() {
        return "ice4j.Connector@" + listenAddress;
    }

}
