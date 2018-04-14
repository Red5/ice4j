/* See LICENSE.md for license information */
package org.ice4j.ice.harvest;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.ice4j.StackProperties;
import org.ice4j.StunMessageEvent;
import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.attribute.Attribute;
import org.ice4j.attribute.UsernameAttribute;
import org.ice4j.ice.nio.IceUdpTransport;
import org.ice4j.socket.IceSocketWrapper;
import org.ice4j.socket.IceUdpSocketWrapper;
import org.ice4j.stack.RequestListener;
import org.ice4j.stack.StunStack;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A class which holds a {@link DatagramSocket} and runs a thread ({@link #thread}) which perpetually reads from it.
 *
 * When a datagram from an unknown source is received, it is parsed as a STUN Binding Request, and if it has a USERNAME attribute, its ufrag is extracted.
 * At this point, an implementing class may choose to create a mapping for the remote address of the datagram, which will be used for further packets
 * from this address.
 *
 * @author Boris Grozev
 * @author Paul Gregoire
 */
public abstract class AbstractUdpListener {

    private static final Logger logger = LoggerFactory.getLogger(AbstractUdpListener.class);

    /**
     * Returns the list of {@link TransportAddress}es, one for each allowed IP address found on each allowed network interface, with the given port.
     *
     * @param port the UDP port number.
     * @return the list of allowed transport addresses.
     */
    public static List<TransportAddress> getAllowedAddresses(int port) {
        List<TransportAddress> addresses = new LinkedList<>();
        for (InetAddress address : HostCandidateHarvester.getAllAllowedAddresses()) {
            addresses.add(new TransportAddress(address, port, Transport.UDP));
        }
        return addresses;
    }

    /**
     * The map which keeps the known remote addresses and their associated candidateSockets.
     * {@link #thread} is the only thread which adds new entries, while other threads remove entries when candidates are freed.
     */
    protected final Map<SocketAddress, IceUdpSocketWrapper> sockets = new ConcurrentHashMap<>();

    /**
     * The local address that this harvester is bound to.
     */
    protected final TransportAddress localAddress;

    /**
     * Initializes a new SinglePortUdpHarvester instance which is to bind on the specified local address.
     * 
     * @param localAddress the address to bind to.
     * @throws IOException if initialization fails.
     */
    protected AbstractUdpListener(TransportAddress localAddress) throws IOException {
        boolean bindWildcard = !StackProperties.getBoolean(StackProperties.BIND_WILDCARD, false);
        if (bindWildcard) {
            this.localAddress = new TransportAddress((InetAddress) null, localAddress.getPort(), localAddress.getTransport());
        } else {
            this.localAddress = localAddress;
        }
        // create a stun stack and unconnected udp socket wrapper, then add them to the udp transport
        IceUdpSocketWrapper iceSocket = new IceUdpSocketWrapper(this.localAddress);
        StunStack stunStack = new StunStack();
        stunStack.addRequestListener(localAddress, new RequestListener() {

            @Override
            public void processRequest(StunMessageEvent evt) throws IllegalArgumentException {
                TransportAddress remoteAddress = evt.getRemoteAddress();
                sockets.put(remoteAddress, iceSocket);
                UsernameAttribute ua = (UsernameAttribute) evt.getMessage().getAttribute(Attribute.Type.USERNAME);
                if (ua != null) {
                    logger.debug("Username length: {} data length: {}", ua.getUsername().length, ua.getDataLength());
                    String ufrag = new String(ua.getUsername()).split(":")[0];
                    updateCandidate(iceSocket, remoteAddress, ufrag);
                }
            }

        });
        IceUdpTransport.getInstance().addBinding(stunStack, iceSocket);
    }

    /**
     * Looks for a registered ICE candidate, which has a local ufrag of {@code ufrag}, and if one is found it accepts the new socket and adds it to the candidate.
     * 
     * @param iceSocket
     * @param remoteAddress
     * @param ufrag
     */
    protected abstract void updateCandidate(IceSocketWrapper iceSocket, InetSocketAddress remoteAddress, String ufrag);

}
