/* See LICENSE.md for license information */
package org.ice4j.stack;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.SocketException;
import java.nio.channels.ClosedChannelException;
import java.util.Queue;

import org.ice4j.TransportAddress;
import org.ice4j.socket.IceSocketWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The Network Access Point is the most outward part of the stack. It is constructed around a datagram socket and takes care of forwarding incoming
 * messages to the MessageProcessor as well as sending datagrams to the STUN server specified by the original NetAccessPointDescriptor.
 *
 * @author Emil Ivov
 */
class Connector implements Runnable {

    private static final Logger logger = LoggerFactory.getLogger(Connector.class);

    private final NetAccessManager netAccessManager;

    /**
     * The message queue is where incoming messages are added.
     */
    private final Queue<RawMessage> messageQueue;

    /**
     * The socket object that used by this access point to access the network.
     */
    private IceSocketWrapper sock;

    /**
     * A flag that is set to false to exit the message processor.
     */
    private boolean running;

    /**
     * The address that we are listening to.
     */
    private final TransportAddress listenAddress;

    /**
     * The remote address of the socket of this Connector if it is a TCP socket, or null if it is UDP.
     */
    private final TransportAddress remoteAddress;

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
     * The listening thread's run method.
     */
    @Override
    public void run() {
        running = true;
        Thread.currentThread().setName("IceConnector@" + hashCode());
        // Make sure localSock's receiveBufferSize is taken into account including after it gets changed.
        int receiveBufferSize = 1500;
        DatagramPacket packet = new DatagramPacket(new byte[receiveBufferSize], receiveBufferSize);
        while (running) {
            try {
                byte[] packetData = packet.getData();
                if (packetData == null || packetData.length < receiveBufferSize) {
                    packet.setData(new byte[receiveBufferSize], 0, receiveBufferSize);
                } else {
                    // XXX Tell the packet it is large enough because the socket will not look at the length of the 
                    //data array property and will just respect the length property.
                    packet.setLength(receiveBufferSize);
                }
                // blocking
                sock.receive(packet);
                //get lost if we are no longer running.
                if (!running) {
                    return;
                }
                if (logger.isTraceEnabled()) {
                    logger.trace("received datagram packet - {}:{}", packet.getAddress(), packet.getPort());
                }
                if (packet.getPort() < 0) {
                    logger.warn("Out of range packet port, resetting to 0");
                    // force a minimum port of 0 to prevent out of range errors
                    packet.setPort(0);
                }
                RawMessage rawMessage = new RawMessage(packet.getData(), packet.getLength(), new TransportAddress(packet.getAddress(), packet.getPort(), listenAddress.getTransport()), listenAddress);
                messageQueue.add(rawMessage);
            } catch (SocketException ex) {
                if (running) {
                    logger.warn("Connector died: {} -> {}", listenAddress, remoteAddress, ex);
                    stop();
                }
            } catch (ClosedChannelException cce) {
                // The socket was closed, possibly by the remote peer. If we were already stopped, just ignore it.
                if (running) {
                    // We could be the first thread to realize that the socket was closed. But that's normal operation, so don't
                    // complain too much.
                    logger.warn("The socket was closed");
                    stop();
                }
            } catch (IOException ex) {
                logger.warn("A net access point has gone useless", ex);
                // do not stop the thread
            } catch (Throwable ex) {
                logger.warn("Unknown error occurred while listening for messages!", ex);
                stop();
            }
        }
    }

    /**
     * Makes the access point stop listening on its socket.
     */
    protected void stop() {
        running = false;
        netAccessManager.removeSocket(listenAddress, remoteAddress);
        if (sock != null) {
            sock.close();
            sock = null;
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
        return "ice4j.Connector@" + listenAddress + " status: " + (running ? "not running" : "running");
    }
}
