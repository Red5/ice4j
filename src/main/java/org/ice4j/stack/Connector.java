/* See LICENSE.md for license information */
package org.ice4j.stack;

import java.io.IOException;
import java.net.DatagramPacket;
import java.util.Queue;

import org.ice4j.TransportAddress;
import org.ice4j.socket.IceSocketWrapper;

/**
 * The Network Access Point is the most outward part of the stack. It is constructed around a datagram socket and takes care of forwarding incoming
 * messages to the MessageProcessor as well as sending datagrams to the STUN server specified by the original NetAccessPointDescriptor.
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
     * The message queue is where incoming messages are added.
     */
    private final Queue<RawMessage> messageQueue;

    /**
     * Creates a network access point.
     * @param socket the socket that this access point is supposed to use for communication.
     * @param remoteAddress the remote address of the socket of this {@link Connector} if it is a TCP socket, or null if it is UDP.
     * @param messageQueue the Queue where incoming messages should be queued
     */
    protected Connector(IceSocketWrapper socket, TransportAddress remoteAddress, NetAccessManager netAccessManager, Queue<RawMessage> messageQueue) {
        this.sock = socket;
        this.remoteAddress = remoteAddress;
        this.netAccessManager = netAccessManager;
        this.messageQueue = messageQueue;
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
        if (sock != null) {
            sock.close();
        }
    }

    /**
     * Receives a message from the socket.
     * 
     * @param message the bytes received
     * @param address message origin
     */
    void receiveMessage(byte[] message, TransportAddress address) {
        RawMessage rawMessage = new RawMessage(message, message.length, address, listenAddress);
        messageQueue.add(rawMessage);
    }

    /**
     * Sends message through this access point's socket.
     *
     * @param message the bytes to send
     * @param address message destination
     * @throws IOException if an exception occurs while sending the message
     */
    void sendMessage(byte[] message, TransportAddress address) throws IOException {
        DatagramPacket datagramPacket = new DatagramPacket(message, 0, message.length, address);
        sock.send(datagramPacket);
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
