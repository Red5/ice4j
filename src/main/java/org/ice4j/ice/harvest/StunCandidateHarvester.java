/* See LICENSE.md for license information */
package org.ice4j.ice.harvest;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.CountDownLatch;

import org.apache.mina.core.future.ConnectFuture;
import org.apache.mina.core.session.IdleStatus;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.transport.socket.SocketSessionConfig;
import org.apache.mina.transport.socket.nio.NioSocketConnector;
import org.ice4j.StackProperties;
import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.ice.Candidate;
import org.ice4j.ice.CandidateTcpType;
import org.ice4j.ice.Component;
import org.ice4j.ice.HostCandidate;
import org.ice4j.ice.LocalCandidate;
import org.ice4j.ice.nio.IceHandler;
import org.ice4j.ice.nio.IceTransport;
import org.ice4j.security.LongTermCredential;
import org.ice4j.socket.IceSocketWrapper;
import org.ice4j.stack.StunStack;
import org.slf4j.LoggerFactory;

/**
 * Implements a CandidateHarvester which gathers Candidates for a specified {@link Component} using STUN as defined in RFC 5389 "Session
 * Traversal Utilities for NAT (STUN)" only.
 *
 * @author Emil Ivov
 * @author Lyubomir Marinov
 */
public class StunCandidateHarvester extends AbstractCandidateHarvester {

    {
        logger = LoggerFactory.getLogger(StunCandidateHarvester.class);
    }

    /**
     * The list of StunCandidateHarvests which have been successfully completed i.e. have harvested Candidates.
     */
    private final List<StunCandidateHarvest> completedHarvests = new LinkedList<>();

    /**
     * The username used by this StunCandidateHarvester for the purposes of the STUN short-term credential mechanism.
     */
    private final String shortTermCredentialUsername;

    /**
     * The list of StunCandidateHarvests which have been started to harvest Candidates for HostCandidates and which have
     * not completed yet so {@link #harvest(Component)} has to wait for them.
     */
    private final List<StunCandidateHarvest> startedHarvests = new LinkedList<>();

    /**
     * The address of the STUN server that we will be sending our requests to.
     */
    public final TransportAddress stunServer;

    /**
     * The StunStack used by this instance for the purposes of STUN communication.
     */
    private StunStack stunStack;

    /**
     * Used to control connection flow with TCP.
     */
    protected CountDownLatch connectLatch = new CountDownLatch(1);

    /**
     * Creates a new STUN harvester that will be running against the specified stunServer using a specific username for the purposes of the
     * STUN short-term credential mechanism.
     *
     * @param stunServer the address of the STUN server that we will be querying for our public bindings
     */
    public StunCandidateHarvester(TransportAddress stunServer) {
        this(stunServer, null);
    }

    /**
     * Creates a new STUN harvester that will be running against the specified stunServer using a specific username for the purposes of the
     * STUN short-term credential mechanism.
     *
     * @param stunServer the address of the STUN server that we will be querying for our public bindings
     * @param shortTermCredentialUsername the username to be used by the new instance for the purposes of the STUN short-term credential mechanism or
     * null if the use of the STUN short-term credential mechanism is not determined at the time of the construction of the new instance
     */
    public StunCandidateHarvester(TransportAddress stunServer, String shortTermCredentialUsername) {
        logger.debug("StunCandidateHarvester - server: {} user name: {}", stunServer, shortTermCredentialUsername);
        this.stunServer = stunServer;
        this.shortTermCredentialUsername = shortTermCredentialUsername;
        //these should be configurable.
        if (System.getProperty(StackProperties.MAX_CTRAN_RETRANS_TIMER) == null) {
            System.setProperty(StackProperties.MAX_CTRAN_RETRANS_TIMER, "400");
        }
        if (System.getProperty(StackProperties.MAX_CTRAN_RETRANSMISSIONS) == null) {
            System.setProperty(StackProperties.MAX_CTRAN_RETRANSMISSIONS, "3");
        }
    }

    /**
     * Notifies this StunCandidateHarvester that a specific StunCandidateHarvest has been completed. If the specified
     * harvest has harvested Candidates, it is moved from {@link #startedHarvests} to {@link #completedHarvests}. Otherwise, it is
     * just removed from {@link #startedHarvests}.
     *
     * @param harvest the StunCandidateHarvest which has been completed
     */
    void completedResolvingCandidate(StunCandidateHarvest harvest) {
        boolean doNotify = false;
        synchronized (startedHarvests) {
            startedHarvests.remove(harvest);
            // If this was the last candidate, we are done with the STUN
            // resolution and need to notify the waiters.
            if (startedHarvests.isEmpty()) {
                doNotify = true;
            }
        }
        synchronized (completedHarvests) {
            if (harvest.getCandidateCount() < 1) {
                completedHarvests.remove(harvest);
            } else if (!completedHarvests.contains(harvest)) {
                completedHarvests.add(harvest);
            }
        }
        synchronized (startedHarvests) {
            if (doNotify) {
                startedHarvests.notify();
            }
        }
    }

    /**
     * Creates a new StunCandidateHarvest instance which is to perform STUN harvesting of a specific HostCandidate.
     *
     * @param hostCandidate the HostCandidate for which harvesting is to be performed by the new StunCandidateHarvest instance
     * @return a new StunCandidateHarvest instance which is to perform STUN harvesting of the specified hostCandidate
     */
    protected StunCandidateHarvest createHarvest(HostCandidate hostCandidate) {
        return new StunCandidateHarvest(this, hostCandidate);
    }

    /**
     * Creates a LongTermCredential to be used by a specific StunCandidateHarvest for the purposes of the long-term
     * credential mechanism in a specific realm of the STUN server associated with this StunCandidateHarvester. The default
     * implementation returns null and allows extenders to override in order to support the long-term credential mechanism.
     *
     * @param harvest the StunCandidateHarvest which asks for the LongTermCredential
     * @param realm the realm of the STUN server associated with this StunCandidateHarvester in which harvest will use the
     * returned LongTermCredential
     * @return a LongTermCredential to be used by harvest for the purposes of the long-term credential mechanism in the specified
     * realm of the STUN server associated with this StunCandidateHarvester
     */
    protected LongTermCredential createLongTermCredential(StunCandidateHarvest harvest, byte[] realm) {
        // The long-term credential mechanism is not utilized by default.
        return null;
    }

    /**
     * Gets the username to be used by this StunCandidateHarvester for the purposes of the STUN short-term credential mechanism.
     *
     * @return the username to be used by this StunCandidateHarvester for the purposes of the STUN short-term credential mechanism or
     * null if the STUN short-term credential mechanism is not to be utilized
     */
    protected String getShortTermCredentialUsername() {
        return shortTermCredentialUsername;
    }

    /**
     * Gets the StunStack used by this CandidateHarvester for the purposes of STUN communication. It is guaranteed to be available only
     * during the execution of {@link CandidateHarvester#harvest(Component)}.
     *
     * @return the StunStack used by this CandidateHarvester for the purposes of STUN communication
     * @see CandidateHarvester#harvest(Component)
     */
    public StunStack getStunStack() {
        return stunStack;
    }

    /**
     * Gathers STUN candidates for all host Candidates that are already present in the specified component. This method relies on the
     * specified component to already contain all its host candidates so that it would resolve them.
     *
     * @param component the {@link Component} that we'd like to gather candidate STUN Candidates for
     * @return the LocalCandidates gathered by this CandidateHarvester
     */
    @Override
    public Collection<LocalCandidate> harvest(Component component) {
        if (logger.isDebugEnabled()) {
            logger.debug("Starting {} harvest for: {}", component.toShortString(), toString());
        }
        stunStack = component.getParentStream().getParentAgent().getStunStack();
        for (Candidate<?> cand : component.getLocalCandidates()) {
            if ((cand instanceof HostCandidate) && (cand.getTransport() == stunServer.getTransport())) {
                startResolvingCandidate((HostCandidate) cand);
            }
        }
        waitForResolutionEnd();
        // Report the LocalCandidates gathered by this CandidateHarvester so that the harvest is sure to be considered successful.
        Collection<LocalCandidate> candidates = new HashSet<>();
        synchronized (completedHarvests) {
            for (StunCandidateHarvest completedHarvest : completedHarvests) {
                LocalCandidate[] completedHarvestCandidates = completedHarvest.getCandidates();
                if ((completedHarvestCandidates != null) && (completedHarvestCandidates.length != 0)) {
                    candidates.addAll(Arrays.asList(completedHarvestCandidates));
                }
            }
            completedHarvests.clear();
        }
        if (logger.isDebugEnabled()) {
            int cands = candidates.size();
            if (cands == 0) {
                logger.debug("Completed {} harvest: {}. Found 0 candidates", component.toShortString(), toString());
            } else {
                logger.debug("Completed {} harvest: {}. Found {} candidates: {}", component.toShortString(), toString(), cands, listCandidates(candidates));
            }
        }
        return candidates;
    }

    private String listCandidates(Collection<? extends Candidate<?>> candidates) {
        StringBuilder retval = new StringBuilder();
        for (Candidate<?> candidate : candidates) {
            retval.append(candidate.toShortString());
            retval.append(' ');
        }
        return retval.toString();
    }

    /**
     * Sends a binding request to our stun server through the specified hostCand candidate and adds it to the list of addresses still
     * waiting for resolution.
     *
     * @param hostCand the HostCandidate that we'd like to resolve.
     */
    private void startResolvingCandidate(HostCandidate hostCand) {
        logger.info("startResolvingCandidate: {}", hostCand);
        // get the transport address for the incoming host candidate
        TransportAddress hostAddress = hostCand.getTransportAddress();
        // first of all, make sure that the STUN server and the Candidate address are of the same type and that they can communicate.
        if (!hostAddress.canReach(stunServer)) {
            logger.info("Transport mismatch, skipping candidate in this harvester");
            return;
        }
        // Sets the host candidate. For UDP it simply returns the candidate passed as a parameter. For TCP, we cannot return the same hostCandidate
        // because in Java a server socket cannot connect to a destination with the same local address/port (i.e. a Java Socket cannot act as both server/client).
        HostCandidate cand = null;
        // create a new TCP HostCandidate
        if (hostCand.getTransport() == Transport.TCP) {
            logger.info("Creating a new TCP HostCandidate");
            try {
                final IceHandler handler = IceTransport.getIceHandler();
                // lookup the existing host candidates ice socket (should have been created by host harvester)
                IceSocketWrapper iceSocket = handler.lookupBinding(hostAddress);
                if (iceSocket == null) {
                    // do secondary lookup by destination, just to be sure
                    iceSocket = IceTransport.getIceHandler().lookupBindingByRemote(stunServer);
                    if (iceSocket == null) {
                        // last-ditch effort
                        iceSocket = IceSocketWrapper.build(hostAddress, stunServer);
                    }
                }
                if (iceSocket != null) {
                    // create a new session connected to the stun server and add it to the existing ice socket
                    NioSocketConnector connector = new NioSocketConnector();
                    SocketSessionConfig config = connector.getSessionConfig();
                    config.setReuseAddress(true);
                    config.setTcpNoDelay(true);
                    // set an idle time of 30s (default)
                    config.setIdleTime(IdleStatus.BOTH_IDLE, IceTransport.getTimeout());
                    // QoS
                    config.setTrafficClass(IceTransport.trafficClass);
                    // set connection timeout of x milliseconds
                    connector.setConnectTimeoutMillis(3000L);
                    // add the ice protocol encoder/decoder
                    connector.getFilterChain().addLast("protocol", IceTransport.getProtocolcodecfilter());
                    // set the handler on the connector
                    connector.setHandler(handler);
                    // check for existing registration
                    if (handler.lookupBinding(hostAddress) == null) {
                        // add this socket for attachment to the session upon opening
                        handler.registerStackAndSocket(stunStack, iceSocket);
                    }
                    // connect 
                    ConnectFuture future = connector.connect(stunServer, hostAddress);
                    future.awaitUninterruptibly(500L);
                    if (future.isConnected()) {
                        IoSession sess = future.getSession();
                        if (sess != null) {
                            iceSocket.setSession(sess);
                            Component component = hostCand.getParentComponent();
                            // create a new host candidate 
                            cand = new HostCandidate(iceSocket, component, Transport.TCP);
                            // set the tcptype (we need to know if the other end is active, but for now all the browsers appear to be
                            cand.setTcpType(CandidateTcpType.PASSIVE);
                            stunStack.addSocket(iceSocket, iceSocket.getRemoteTransportAddress(), true); // passive == bind, active == no 
                            component.getComponentSocket().setSocketWrapper(iceSocket);
                        }
                    }
                } else {
                    logger.warn("Session failed to complete, no host candidate available for {}", hostCand.getTransportAddress());
                }
            } catch (Exception e) {
                logger.warn("Exception resolving TCP HostCandidate", e);
            }
        } else {
            logger.trace("Using existing UDP HostCandidate");
            cand = hostCand;
        }
        if (cand != null) {
            logger.debug("HostCandidate: {}", cand);
            StunCandidateHarvest harvest = createHarvest(cand);
            if (harvest == null) {
                logger.warn("Failed to create harvest");
                return;
            }
            synchronized (startedHarvests) {
                startedHarvests.add(harvest);
                boolean started = false;
                try {
                    started = harvest.startResolvingCandidate();
                } catch (Exception ex) {
                    started = false;
                    logger.warn("Failed to start resolving host candidate {}", hostCand, ex);
                } finally {
                    if (!started) {
                        try {
                            startedHarvests.remove(harvest);
                            logger.warn("harvest did not start, removed: {}", harvest);
                        } finally {
                            // For the sake of completeness, explicitly close the harvest.
                            try {
                                harvest.close();
                            } catch (Exception ex) {
                            }
                        }
                    }
                }
            }
        } else {
            logger.debug("No usable host candidate available for {}", hostCand);
        }
    }

    /**
     * Blocks the current thread until all resolutions in this harvester have terminated one way or another.
     */
    private void waitForResolutionEnd() {
        synchronized (startedHarvests) {
            boolean interrupted = false;
            // Handle spurious wakeups
            while (!startedHarvests.isEmpty()) {
                try {
                    startedHarvests.wait();
                } catch (InterruptedException iex) {
                    logger.info("Interrupted waiting for harvests to complete, startedHarvests: {}", startedHarvests.size());
                    interrupted = true;
                }
            }
            // Restore the interrupted status.
            if (interrupted) {
                Thread.currentThread().interrupt();
            }
        }
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((shortTermCredentialUsername == null) ? 0 : shortTermCredentialUsername.hashCode());
        result = prime * result + ((stunServer == null) ? 0 : stunServer.hashCode());
        result = prime * result + (Transport.UDP.equals(stunServer.getTransport()) ? 2 : 4);
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        if (!Transport.UDP.equals(stunServer.getTransport())) {
            return false;
        }
        StunCandidateHarvester other = (StunCandidateHarvester) obj;
        if (shortTermCredentialUsername == null) {
            if (other.shortTermCredentialUsername != null)
                return false;
        } else if (!shortTermCredentialUsername.equals(other.shortTermCredentialUsername))
            return false;
        if (stunServer == null) {
            if (other.stunServer != null)
                return false;
        } else if (!stunServer.equals(other.stunServer))
            return false;
        return true;
    }

    /**
     * Returns a String representation of this harvester containing its type and server address.
     *
     * @return a String representation of this harvester containing its type and server address.
     */
    @Override
    public String toString() {
        return String.format("%s harvester(srvr: %s)", ((this instanceof TurnCandidateHarvester) ? "TURN" : "STUN"), stunServer.toString());
    }

}
