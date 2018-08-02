/* See LICENSE.md for license information */
package org.ice4j.stack;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.ice4j.StunException;
import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.message.ChannelData;
import org.ice4j.message.Message;
import org.ice4j.socket.IceSocketWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages Connectors and MessageProcessor pooling. This class serves as a layer that masks network primitives and provides equivalent STUN
 * abstractions. Instances that operate with the NetAccessManager are only supposed to understand STUN talk and shouldn't be aware of datagrams sockets, etc.
 * 
 * @author Emil Ivov
 * @author Aakash Garg
 * @author Boris Grozev
 * @author Paul Gregoire
 */
public class NetAccessManager {

    private static final Logger logger = LoggerFactory.getLogger(NetAccessManager.class);

    /**
     * All Connectors currently in use with UDP. The table maps a local TransportAddress and and a remote TransportAddress to
     * a Connector. We allow a Connector to be added without a specified remote address, under the null key.
     *
     * Due to the final hashCode() method of InetSocketAddress, TransportAddress cannot override and it causes problem to store both UDP and TCP address
     * (i.e. 192.168.0.3:5000/tcp has the same hashcode as 192.168.0.3:5000/udp because InetSocketAddress does not take into account transport).
     */
    private final ConcurrentMap<TransportAddress, Map<TransportAddress, Connector>> udpConnectors = new ConcurrentHashMap<>();

    /**
     * All Connectors currently in use with TCP. The table maps a local TransportAddress and and a remote TransportAddress to
     * a Connector. We allow a Connector to be added without a specified remote address, under the null key.
     *
     * Due to the final hashCode() method of InetSocketAddress, TransportAddress cannot override and it causes problem to store both UDP and TCP address
     * (i.e. 192.168.0.3:5000/tcp has the same hashcode as 192.168.0.3:5000/udp because InetSocketAddress does not take into account transport).
     */
    private final ConcurrentMap<TransportAddress, Map<TransportAddress, Connector>> tcpConnectors = new ConcurrentHashMap<>();

    /**
     * The StunStack which has created this instance, is its owner and is the handler that incoming message requests should be passed to.
     */
    private final StunStack stunStack;

    /**
     * Constructs a NetAccessManager.
     *
     * @param stunStack the StunStack which is creating the new instance, is going to be its owner and is the handler that incoming
     * message requests should be passed to
     */
    NetAccessManager(StunStack stunStack) {
        this.stunStack = stunStack;
    }

    /**
     * Gets the StunStack which has created this instance and is its owner.
     *
     * @return the StunStack which has created this instance and is its owner
     */
    StunStack getStunStack() {
        return stunStack;
    }

    /**
     * Creates and starts a new access point based on the specified socket. If the specified access point has already been installed the method
     * has no effect.
     *
     * @param socket the socket that the access point should use.
     */
    public void addSocket(IceSocketWrapper socket) {
        logger.debug("addSocket: {}", socket);
        // UDP connections will normally have null remote transport addresses
        addSocket(socket, socket.getRemoteTransportAddress());
    }

    /**
     * Creates and starts a new access point based on the specified socket. If the specified access point already exists the method has no effect.
     *
     * @param socket the socket that the access point should use
     * @param remoteAddress the remote address the {@link Connector} if its TCP or null if its UDP
     * @throws IOException 
     */
    public void addSocket(IceSocketWrapper socket, TransportAddress remoteAddress) {
        logger.debug("addSocket: {} remote address: {}", socket, remoteAddress);
        TransportAddress localAddress = socket.getTransportAddress();
        // determine if UDP or TCP
        boolean udp = socket.isUDP();
        // keyed by local address
        final ConcurrentMap<TransportAddress, Map<TransportAddress, Connector>> connectorsMap = udp ? udpConnectors : tcpConnectors;
        // keyed by remote address
        Map<TransportAddress, Connector> connectorsForLocalAddress = connectorsMap.get(localAddress);
        if (logger.isDebugEnabled()) {
            logger.debug("Existing connectors (pre-add): {}", connectorsForLocalAddress);
        }
        if (connectorsForLocalAddress == null) {
            connectorsForLocalAddress = new HashMap<>();
            connectorsMap.put(localAddress, connectorsForLocalAddress);
            Connector connector = new Connector(socket, remoteAddress, this);
            connectorsForLocalAddress.put(remoteAddress, connector);
        } else if (connectorsForLocalAddress.containsKey(remoteAddress)) {
            logger.info("Not creating a new Connector, because we already have one for the given address pair: {} -> {}", localAddress, remoteAddress);
        } else {
            Connector connector = new Connector(socket, remoteAddress, this);
            logger.warn("New connector: {}", connector);
            Connector prevConnector = connectorsForLocalAddress.put(remoteAddress, connector);
            logger.warn("Previous connector (replaced): {}", prevConnector);
        }
        if (logger.isDebugEnabled()) {
            logger.debug("Existing connectors (post-add): {}", connectorsForLocalAddress);
        }
    }

    /**
     * Stops and deletes the specified access point.
     *
     * @param localAddress the local address of the connector to remove.
     * @param remoteAddress the remote address of the connector to remote. Use null to match the Connector with no specified remote address.
     */
    public void removeSocket(TransportAddress localAddress, TransportAddress remoteAddress) {
        final ConcurrentMap<TransportAddress, Map<TransportAddress, Connector>> connectorsMap = (localAddress.getTransport() == Transport.UDP) ? udpConnectors : tcpConnectors;
        Map<TransportAddress, Connector> connectorsForLocalAddress = connectorsMap.get(localAddress);
        if (connectorsForLocalAddress != null) {
            Connector connector = connectorsForLocalAddress.remove(remoteAddress);
            if (connector != null) {
                connector.stop();
            }
            if (connectorsForLocalAddress.isEmpty()) {
                connectorsMap.remove(localAddress);
            }
        }
    }

    /**
     * Stops NetAccessManager and all of its MessageProcessor.
     */
    public void stop() {
        logger.debug("stop");
        // close all udp
        for (Map<TransportAddress, Connector> map : udpConnectors.values()) {
            // TODO fix ConcurrentModificationException that may occur here
            for (Connector connector : map.values()) {
                connector.stop();
            }
        }
        // close all tcp
        for (Map<TransportAddress, Connector> map : tcpConnectors.values()) {
            // TODO fix ConcurrentModificationException that may occur here
            for (Connector connector : map.values()) {
                connector.stop();
            }
        }
    }

    /**
     * Returns the Connector responsible for a particular source address and a particular destination address.
     *
     * @param localAddress the source address.
     * @param remoteAddress the destination address.
     * @return Connector responsible for a given source and destination address otherwise null
     */
    private Connector getConnector(TransportAddress localAddress, TransportAddress remoteAddress) {
        logger.debug("getConnector - local: {} remote: {}", localAddress, remoteAddress);
        boolean udp = localAddress.getTransport() == Transport.UDP;
        //logger.debug("Local UDP transport: {}", udp);
        final ConcurrentMap<TransportAddress, Map<TransportAddress, Connector>> connectorsMap = udp ? udpConnectors : tcpConnectors;
        Connector connector = null;
        Map<TransportAddress, Connector> connectorsForLocalAddress = connectorsMap.get(localAddress);
        if (logger.isTraceEnabled()) {
            logger.trace("Local connectors: {}", connectorsForLocalAddress);
        }
        if (connectorsForLocalAddress != null) {
            connector = connectorsForLocalAddress.get(remoteAddress);
            // Fallback to the socket with no specific remote address
            if (udp && connector == null) {
                connector = connectorsForLocalAddress.get(null);
            }
        }
        logger.debug("Returning connector: {}", connector);
        return connector;
    }

    //--------------- SENDING MESSAGES -----------------------------------------
    /**
     * Sends the specified stun message through the specified access point.
     *
     * @param stunMessage the message to send
     * @param srcAddr the access point to use to send the message
     * @param remoteAddr the destination of the message
     *
     * @throws IllegalArgumentException if the apDescriptor references an access point that had not been installed
     * @throws IOException  if an error occurs while sending message bytes through the network socket
     */
    void sendMessage(Message stunMessage, TransportAddress srcAddr, TransportAddress remoteAddr) throws IllegalArgumentException, IOException {
        sendMessage(stunMessage.encode(stunStack), srcAddr, remoteAddr);
    }

    /**
     * Sends the specified stun message through the specified access point.
     *
     * @param channelData the message to send
     * @param srcAddr the access point to use to send the message
     * @param remoteAddr the destination of the message
     *
     * @throws IllegalArgumentException if the apDescriptor references an access point that had not been installed
     * @throws IOException  if an error occurs while sending message bytes through the network socket
     * @throws StunException 
     */
    void sendMessage(ChannelData channelData, TransportAddress srcAddr, TransportAddress remoteAddr) throws IllegalArgumentException, IOException, StunException {
        boolean pad = srcAddr.getTransport() == Transport.TCP || srcAddr.getTransport() == Transport.TLS;
        sendMessage(channelData.encode(pad), srcAddr, remoteAddr);
    }

    /**
     * Sends the specified bytes through the specified access point.
     *
     * @param bytes the bytes to send
     * @param srcAddr the access point to use to send the bytes
     * @param remoteAddr the destination of the message
     *
     * @throws IllegalArgumentException if the descriptor references an access point that had not been installed
     * @throws IOException  if an error occurs while sending message bytes through the network socket
     */
    void sendMessage(byte[] bytes, TransportAddress srcAddr, TransportAddress remoteAddr) throws IllegalArgumentException, IOException {
        Connector ap = getConnector(srcAddr, remoteAddr);
        if (ap == null) {
            throw new IllegalArgumentException("No socket found for " + srcAddr + "->" + remoteAddr);
        }
        ap.sendMessage(bytes, remoteAddr);
    }

    /**
     * Receives the specified bytes on the specified access point.
     *
     * @param bytes the bytes received
     * @param srcAddr the access point on which the bytes were received
     * @param remoteAddr the origin of the message
     *
     * @throws IllegalArgumentException if the descriptor references an access point that had not been installed
     * @throws IOException  if an error occurs while sending message bytes through the network socket
     */
//    void receiveMessage(byte[] bytes, TransportAddress srcAddr, TransportAddress remoteAddr) throws IllegalArgumentException, IOException {
//        Connector ap = getConnector(srcAddr, remoteAddr);
//        if (ap == null) {
//            throw new IllegalArgumentException("No socket found for " + srcAddr + "->" + remoteAddr);
//        }
//        ap.receiveMessage(bytes, remoteAddr);
//    }

}
