/* See LICENSE.md for license information */
package org.ice4j.ice.harvest;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicBoolean;

import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.ice.Agent;
import org.ice4j.ice.Component;
import org.ice4j.ice.HostCandidate;
import org.ice4j.ice.IceMediaStream;
import org.ice4j.ice.IceProcessingState;
import org.ice4j.ice.LocalCandidate;
import org.ice4j.socket.IceSocketWrapper;
import org.ice4j.socket.IceUdpSocketWrapper;
import org.ice4j.socket.filter.StunDatagramPacketFilter;
import org.ice4j.stack.StunStack;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A harvester implementation which binds to a single DatagramSocket and provides local candidates of type "host". It runs a thread
 * ({@link #thread}) which perpetually reads from the socket.
 *
 * When {@link #harvest(org.ice4j.ice.Component)} is called, this harvester creates and adds to the component a
 * {@link org.ice4j.ice.harvest.SinglePortUdpHarvester.MyCandidate} instance, and associates the component's local username fragment (ufrag) with this
 * candidate.
 *
 * When a STUN Binding Request with a given ufrag is received, if the ufrag matches one of the registered candidates, then a new socket is created, which
 * is to receive further packets from the remote address, and the socket is added to the candidate.
 *
 * @author Boris Grozev
 */
public class SinglePortUdpHarvester extends AbstractUdpListener implements CandidateHarvester {
 
    private static final Logger logger = LoggerFactory.getLogger(SinglePortUdpHarvester.class);

    /**
     * Creates a new SinglePortUdpHarvester instance for each allowed IP address found on each allowed network interface, with the given port.
     *
     * @param port the UDP port number to use.
     * @return the list of created SinglePortUdpHarvesters.
     */
    public static List<SinglePortUdpHarvester> createHarvesters(int port) {
        List<SinglePortUdpHarvester> harvesters = new LinkedList<>();
        for (TransportAddress address : AbstractUdpListener.getAllowedAddresses(port)) {
            try {
                harvesters.add(new SinglePortUdpHarvester(address));
            } catch (IOException ioe) {
                logger.warn("Failed to create SinglePortUdpHarvester foraddress {}", address, ioe);
            }
        }
        return harvesters;
    }

    /**
     * The map which keeps all currently active Candidates created by this harvester. The keys are the local username fragments (ufrags) of
     * the components for which the candidates are harvested.
     */
    private final ConcurrentMap<String, MyCandidate> candidates = new ConcurrentHashMap<>();

    /**
     * Manages statistics about harvesting time.
     */
    private HarvestStatistics harvestStatistics = new HarvestStatistics();

    /**
     * Initializes a new SinglePortUdpHarvester instance which is to bind on the specified local address.
     * @param localAddress the address to bind to.
     * @throws IOException if initialization fails.
     */
    public SinglePortUdpHarvester(TransportAddress localAddress) throws IOException {
        super(localAddress);
        logger.info("Initialized SinglePortUdpHarvester with address {}", localAddress);
    }

    /**
     * {@inheritDoc}
     */
    public HarvestStatistics getHarvestStatistics() {
        return harvestStatistics;
    }

    /**
     * {@inheritDoc}
     *
     * Looks for an ICE candidate registered with this harvester, which has a local ufrag of {@code ufrag}, and if one is found it accepts the new
     * socket and adds it to the candidate.
     */
    protected void maybeAcceptNewSession(byte[] buf, InetSocketAddress remoteAddress, String ufrag) {
        MyCandidate candidate = candidates.get(ufrag);
        if (candidate == null) {
            // A STUN Binding Request with an unknown USERNAME. Drop it.
            return;
        }
        // This is a STUN Binding Request destined for this specific Candidate/Component/Agent.
        try {
            // 1. Create a socket for this remote address
            // 2. Set-up de-multiplexing for future datagrams with this address to this socket.
            MySocket newSocket = addSocket(remoteAddress);
            // 3. Let the candidate and its STUN stack no about the new socket.
            candidate.addSocket(newSocket, remoteAddress);
            // 4. Add the original datagram to the new socket.
            newSocket.addBuffer(buf);
        } catch (SocketException se) {
            logger.warn("Could not create a socket", se);
        } catch (IOException ioe) {
            logger.warn("Failed to handle new socket", ioe);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Collection<LocalCandidate> harvest(Component component) {
        IceMediaStream stream = component.getParentStream();
        Agent agent = stream.getParentAgent();
        String ufrag = agent.getLocalUfrag();
        if (stream.getComponentCount() != 1 || agent.getStreamCount() != 1) {
            // SinglePortUdpHarvester only works with streams with a single component, and agents with a single stream.
            // This is because we use the local "ufrag" from an incoming STUN packet to setup de-multiplexing based on remote transport address.
            logger.info("More than one Component for an Agent, cannot harvest.");
            return new LinkedList<>();
        }
        MyCandidate candidate = new MyCandidate(component, ufrag);
        candidates.put(ufrag, candidate);
        component.addLocalCandidate(candidate);
        return new ArrayList<LocalCandidate>(Arrays.asList(candidate));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isHostHarvester() {
        return true;
    }

    /**
     * Implements a Candidate for the purposes of this SinglePortUdpHarvester.
     */
    private class MyCandidate extends HostCandidate {
        /**
         * The local username fragment associated with this candidate.
         */
        private final String ufrag;

        /**
         * The flag which indicates that this MyCandidate has been freed.
         */
        private AtomicBoolean freed = new AtomicBoolean(false);

        /**
         * The collection of IceSocketWrappers that can potentially be used by the ice4j user to read/write from/to this candidate.
         * The keys are the remote addresses for each socket.
         * <br>
         * There are wrappers over MultiplexedDatagramSockets over a corresponding socket in {@link #sockets}.
         */
        private final ConcurrentMap<SocketAddress, IceSocketWrapper> candidateSockets = new ConcurrentHashMap<>();

        /**
         * The collection of DatagramSockets added to this candidate.
         * The keys are the remote addresses for each socket.
         * <br>
         * These are the "raw" sockets, before any wrappers are added for the STUN stack or the user of ice4j.
         */
        private final ConcurrentMap<SocketAddress, DatagramSocket> sockets = new ConcurrentHashMap<>();

        /**
         * Initializes a new MyCandidate instance with the given Component and the given local username fragment.
         *
         * @param component the Component for which this candidate will serve.
         * @param ufrag the local ICE username fragment for this candidate (and its Component and Agent).
         */
        private MyCandidate(Component component, String ufrag) {
            super(localAddress, component);
            this.ufrag = ufrag;
        }

        /**
         * Adds a new Socket to this candidate, which is associated with a particular remote address.
         *
         * @param socket the socket to add.
         * @param remoteAddress the remote address for the socket.
         */
        private void addSocket(DatagramSocket socket, InetSocketAddress remoteAddress) throws IOException {
            if (freed.get()) {
                throw new IOException("Candidate freed");
            }
            Component component = getParentComponent();
            if (component == null) {
                throw new IOException("No parent component");
            }
            IceProcessingState state = component.getParentStream().getParentAgent().getState();
            if (state == IceProcessingState.FAILED) {
                throw new IOException("Cannot add socket to an Agent in state FAILED.");
            } else if (state != null && state.isOver()) {
                logger.debug("Adding a socket to a completed Agent, state: {}", state);
            }
            // Socket to add to the candidate
            IceSocketWrapper candidateSocket = new IceUdpSocketWrapper(socket.getChannel());
            // STUN-only filtered socket to add to the StunStack
            candidateSocket.addFilter(new StunDatagramPacketFilter());
            component.getParentStream().getParentAgent().getStunStack().addSocket(candidateSocket, new TransportAddress(remoteAddress, Transport.UDP));
            // TODO: maybe move this code to the candidates.
            component.getComponentSocket().setSocket(candidateSocket);
            // if a socket already exists, it will be returned and closed after being replaced in the map
            IceSocketWrapper oldSocket = candidateSockets.put(remoteAddress, candidateSocket);
            if (oldSocket != null) {
                logger.info("Replacing the socket for remote address {}", remoteAddress);
                oldSocket.close();
            }
            sockets.put(remoteAddress, socket);
        }

        /**
         * {@inheritDoc}
         * <br>
         * Closes all sockets in use by this LocalCandidate.
         */
        @Override
        public void free() {
            if (freed.compareAndSet(false, true)) {
                candidates.remove(ufrag);
                StunStack stunStack = getStunStack();
                for (Map.Entry<SocketAddress, DatagramSocket> e : sockets.entrySet()) {
                    DatagramSocket socket = e.getValue();
                    if (stunStack != null) {
                        // XXX optimize this to remove without creating two new objects * n
                        TransportAddress localAddress = new TransportAddress(socket.getLocalAddress(), socket.getLocalPort(), Transport.UDP);
                        TransportAddress remoteAddress = new TransportAddress((InetSocketAddress) e.getKey(), Transport.UDP);
                        stunStack.removeSocket(localAddress, remoteAddress);
                    }
                    socket.close();
                }
                sockets.clear();
                for (IceSocketWrapper wrapper : candidateSockets.values()) {
                    wrapper.close();
                }
                candidateSockets.clear();
                super.free();
            }
        }

        /**
         * {@inheritDoc}
         */
        @Override
        protected IceSocketWrapper getCandidateIceSocketWrapper(SocketAddress remoteAddress) {
            return candidateSockets.get(remoteAddress);
        }

    }
}
