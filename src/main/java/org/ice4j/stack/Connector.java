/* See LICENSE.md for license information */
package org.ice4j.stack;

import java.io.IOException;

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
     * Creates a network access point.
     * @param socket the socket that this access point is supposed to use for communication.
     * @param remoteAddress the remote address of the socket of this {@link Connector} if it is a TCP socket, or null if it is UDP.
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
     * Makes the access point stop listening on its socket.
     */
    protected void stop() {
        netAccessManager.removeSocket(listenAddress, remoteAddress);
        if (!sock.isClosed()) {
            sock.close();
        }
    }

    /**
     * Receives a message from the socket.
     * 
     * @param message the bytes received
     * @param address message origin
     */
//    void receiveMessage(byte[] message, TransportAddress address) {
//        messageQueue.add(RawMessage.build(message, message.length, address, listenAddress));
//    }

    /**
     * Sends message through this access point's socket.
     *
     * @param message the bytes to send
     * @param address message destination
     * @throws IOException if an exception occurs while sending the message
     */
    void sendMessage(byte[] message, TransportAddress address) throws IOException {
        //        DatagramPacket datagramPacket = new DatagramPacket(message, 0, message.length, address);
        //        sock.send(datagramPacket);
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
