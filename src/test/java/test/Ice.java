/* See LICENSE.md for license information */
package test;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.Collection;
import java.util.List;

import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.ice.Agent;
import org.ice4j.ice.Candidate;
import org.ice4j.ice.Component;
import org.ice4j.ice.IceMediaStream;
import org.ice4j.ice.IceProcessingState;
import org.ice4j.ice.LocalCandidate;
import org.ice4j.ice.NominationStrategy;
import org.ice4j.ice.RemoteCandidate;
import org.ice4j.ice.harvest.CandidateHarvester;
import org.ice4j.ice.harvest.StunCandidateHarvester;
import org.ice4j.ice.harvest.TurnCandidateHarvester;
import org.ice4j.security.LongTermCredential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Simple ice4j testing scenario. The sample application would create and start
 * both agents and make one of them run checks against the other.
 *
 * @author Emil Ivov
 * @author Lyubomir Marinov
 */
public class Ice {

    private static final Logger logger = LoggerFactory.getLogger(Ice.class);

    /**
     * The indicator which determines whether the Ice application (i.e.
     * the run-sample Ant target) is to start connectivity establishment of the
     * remote peer (in addition to the connectivity establishment of the local
     * agent which is always started, of course).
     */
    private static final boolean START_CONNECTIVITY_ESTABLISHMENT_OF_REMOTE_PEER = false;

    /**
     * Start time for debugging purposes.
     */
    static long startTime;

    // local coTurn testing
    //private static final TransportAddress stun4 = new TransportAddress("10.0.0.5", 3478, Transport.UDP);

    // stun.l.google.com stun1.l.google.com stun2.l.google.com stun3.l.google.com
    private static final TransportAddress stun4 = new TransportAddress("173.194.196.127", 19302, Transport.UDP);

    // jitsi stun
    //private static final TransportAddress stun4 = new TransportAddress("stun.jitsi.net", 3478, Transport.UDP);

    private static final TransportAddress stun6 = new TransportAddress("stun6.jitsi.net", 3478, Transport.UDP);

    /**
     * Runs the test
     * @param args command line arguments
     *
     * @throws Throwable if bad stuff happens.
     */
    public static void main(String[] args) throws Throwable {
        // disable IPv6 for this test
        System.setProperty("org.ice4j.ipv6.DISABLED", "true");
        //System.setProperty("NIO_SHARED_MODE", "false");
        System.setProperty("org.ice4j.TERMINATION_DELAY", "10");
        // set blocking or non-blocking
        System.setProperty("IO_BLOCKING", "true");
        startTime = System.currentTimeMillis();
        Agent localAgent = createAgent(9090, false);
        localAgent.setNominationStrategy(NominationStrategy.NOMINATE_HIGHEST_PRIO);
        Agent remotePeer = createAgent(6060, false);
        localAgent.addStateChangeListener(new IceProcessingListener());
        //let them fight ... fights forge character.
        localAgent.setControlling(true);
        remotePeer.setControlling(false);
        long endTime = System.currentTimeMillis();
        transferRemoteCandidates(localAgent, remotePeer);
        for (IceMediaStream stream : localAgent.getStreams()) {
            stream.setRemoteUfrag(remotePeer.getLocalUfrag());
            stream.setRemotePassword(remotePeer.getLocalPassword());
        }
        if (START_CONNECTIVITY_ESTABLISHMENT_OF_REMOTE_PEER) {
            transferRemoteCandidates(remotePeer, localAgent);
        }
        for (IceMediaStream stream : remotePeer.getStreams()) {
            stream.setRemoteUfrag(localAgent.getLocalUfrag());
            stream.setRemotePassword(localAgent.getLocalPassword());
        }
        logger.info("Total candidate gathering time: {}ms\nLocalAgent:\n{}", (endTime - startTime), localAgent);
        localAgent.startConnectivityEstablishment();
        if (START_CONNECTIVITY_ESTABLISHMENT_OF_REMOTE_PEER) {
            remotePeer.startConnectivityEstablishment();
        }
        logger.info("Local audio clist:\n{}", localAgent.getStream("audio").getCheckList());
        IceMediaStream videoStream = localAgent.getStream("video");
        if (videoStream != null) {
            logger.info("Local video clist:\n{}", videoStream.getCheckList());
        }
        // Give processing enough time to finish. We'll System.exit() anyway as soon as localAgent enters a final state.
        Thread.sleep(60000);
        logger.info("Finished");
        System.exit(0);
    }

    /**
     * The listener that would end example execution once we enter the
     * completed state.
     */
    public static final class IceProcessingListener implements PropertyChangeListener {
        /**
         * System.exit()s as soon as ICE processing enters a final state.
         *
         * @param evt the {@link PropertyChangeEvent} containing the old and new states of ICE processing.
         */
        public void propertyChange(PropertyChangeEvent evt) {
            Object iceProcessingState = evt.getNewValue();
            if (logger.isDebugEnabled()) {
                logger.debug("Agent entered the {} state after {} ms", iceProcessingState, (System.currentTimeMillis() - startTime));
            }
            if (iceProcessingState == IceProcessingState.COMPLETED) {
                Agent agent = (Agent) evt.getSource();
                Collection<IceMediaStream> streams = agent.getStreams();
                for (IceMediaStream stream : streams) {
                    String streamName = stream.getName();
                    logger.info("Pairs selected for stream: {}", streamName);
                    List<Component> components = stream.getComponents();
                    for (Component cmp : components) {
                        logger.info("{}: {}", cmp.getComponentID(), cmp.getSelectedPair());
                    }
                }
                for (IceMediaStream stream : streams) {
                    String streamName = stream.getName();
                    logger.info("Check list for stream: {}\n{}", streamName, stream.getCheckList().toString());
                }
            } else if (iceProcessingState == IceProcessingState.TERMINATED || iceProcessingState == IceProcessingState.FAILED) {
                // Though the process will be instructed to die, demonstrate that Agent instances are to be explicitly prepared for garbage collection.
                ((Agent) evt.getSource()).free();
                System.exit(0);
            }
        }
    }

    /**
     * Installs remote candidates in localAgent..
     *
     * @param localAgent a reference to the agent that we will pretend to be the local
     * @param remotePeer a reference to what we'll pretend to be a remote agent.
     */
    static void transferRemoteCandidates(Agent localAgent, Agent remotePeer) {
        Collection<IceMediaStream> streams = localAgent.getStreams();
        for (IceMediaStream localStream : streams) {
            String streamName = localStream.getName();
            //get a reference to the local stream
            IceMediaStream remoteStream = remotePeer.getStream(streamName);
            if (remoteStream != null) {
                transferRemoteCandidates(localStream, remoteStream);
            } else {
                localAgent.removeStream(localStream);
            }
        }
    }

    /**
     * Installs remote candidates in localStream..
     *
     * @param localStream the stream where we will be adding remote candidates
     * to.
     * @param remoteStream the stream that we should extract remote candidates
     * from.
     */
    private static void transferRemoteCandidates(IceMediaStream localStream, IceMediaStream remoteStream) {
        List<Component> localComponents = localStream.getComponents();
        for (Component localComponent : localComponents) {
            int id = localComponent.getComponentID();
            Component remoteComponent = remoteStream.getComponent(id);
            if (remoteComponent != null) {
                transferRemoteCandidates(localComponent, remoteComponent);
            } else {
                localStream.removeComponent(localComponent);
            }
        }
    }

    /**
     * Adds to localComponent a list of remote candidates that are
     * actually the local candidates from remoteComponent.
     *
     * @param localComponent the Component where that we should be
     * adding remoteCandidates to.
     * @param remoteComponent the source of remote candidates.
     */
    private static void transferRemoteCandidates(Component localComponent, Component remoteComponent) {
        List<LocalCandidate> remoteCandidates = remoteComponent.getLocalCandidates();
        localComponent.setDefaultRemoteCandidate(remoteComponent.getDefaultCandidate());
        for (Candidate<?> rCand : remoteCandidates) {
            localComponent.addRemoteCandidate(new RemoteCandidate(rCand.getTransportAddress(), localComponent, rCand.getType(), rCand.getFoundation(), rCand.getPriority(), null));
        }
    }

    /**
     * Creates a vanilla ICE Agent and adds to it an audio and a video
     * stream with RTP and RTCP components.
     *
     * @param rtpPort the port that we should try to bind the RTP component on
     * (the RTCP one would automatically go to rtpPort + 1)
     * @return an ICE Agent with an audio stream with RTP and RTCP
     * components.
     *
     * @throws Throwable if anything goes wrong.
     */
    protected static Agent createAgent(int rtpPort) throws Throwable {
        return createAgent(rtpPort, false);
    }

    /**
     * Creates an ICE Agent (vanilla or trickle, depending on the
     * value of isTrickling) and adds to it an audio and a video stream
     * with RTP and RTCP components.
     *
     * @param rtpPort the port that we should try to bind the RTP component on
     * (the RTCP one would automatically go to rtpPort + 1)
     * @return an ICE Agent with an audio stream with RTP and RTCP
     * components.
     * @param isTrickling indicates whether the newly created agent should be
     * performing trickle ICE.
     *
     * @throws Throwable if anything goes wrong.
     */
    protected static Agent createAgent(int rtpPort, boolean isTrickling) throws Throwable {
        return createAgent(rtpPort, isTrickling, null);
    }

    /**
     * Creates an ICE Agent (vanilla or trickle, depending on the
     * value of isTrickling) and adds to it an audio and a video stream
     * with RTP and RTCP components.
     *
     * @param rtpPort the port that we should try to bind the RTP component on
     * (the RTCP one would automatically go to rtpPort + 1)
     * @return an ICE Agent with an audio stream with RTP and RTCP
     * components.
     * @param isTrickling indicates whether the newly created agent should be
     * performing trickle ICE.
     * @param harvesters the list of {@link CandidateHarvester}s that the new
     * agent should use or null if it should include the default ones.
     *
     * @throws Throwable if anything goes wrong.
     */
    protected static Agent createAgent(int rtpPort, boolean isTrickling, List<CandidateHarvester> harvesters) throws Throwable {
        long startTime = System.currentTimeMillis();
        Agent agent = new Agent();
        agent.setTrickling(isTrickling);
        if (harvesters == null) {
            // STUN
            StunCandidateHarvester stunHarv = new StunCandidateHarvester(stun4);
            agent.addCandidateHarvester(stunHarv);
            StunCandidateHarvester stun6Harv = new StunCandidateHarvester(stun6);
            agent.addCandidateHarvester(stun6Harv);
            // TURN 
            String[] hostnames = new String[] { stun4.getHostString(), stun6.getHostString() };
            int port = stun4.getPort();
            LongTermCredential longTermCredential = new LongTermCredential("guest", "anonymouspower!!");
            for (String hostname : hostnames) {
                agent.addCandidateHarvester(new TurnCandidateHarvester(new TransportAddress(hostname, port, Transport.UDP), longTermCredential));
            }
        } else {
            for (CandidateHarvester harvester : harvesters) {
                agent.addCandidateHarvester(harvester);
            }
        }
        //STREAMS
        createStream(rtpPort, "audio", agent);
        createStream(rtpPort + 2, "video", agent);
        long endTime = System.currentTimeMillis();
        long total = endTime - startTime;
        logger.info("Total harvesting time: {}ms", total);
        return agent;
    }

    /**
     * Creates an IceMediaStream and adds to it an RTP and and RTCP
     * component.
     *
     * @param rtpPort the port that we should try to bind the RTP component on
     * (the RTCP one would automatically go to rtpPort + 1)
     * @param streamName the name of the stream to create
     * @param agent the Agent that should create the stream.
     *
     * @return the newly created IceMediaStream.
     * @throws Throwable if anything goes wrong.
     */
    private static IceMediaStream createStream(int rtpPort, String streamName, Agent agent) throws Throwable {
        IceMediaStream stream = agent.createMediaStream(streamName);
        long startTime = System.currentTimeMillis();
        //TODO: component creation should probably be part of the library. it should also be started after we've defined all components to be
        //created so that we could run the harvesting for everyone of them simultaneously with the others.

        //rtp
        agent.createComponent(stream, Transport.UDP, rtpPort, rtpPort, rtpPort + 100);
        long endTime = System.currentTimeMillis();
        logger.info("RTP Component created in " + (endTime - startTime) + " ms");
        startTime = endTime;
        //rtcpComp
        agent.createComponent(stream, Transport.UDP, rtpPort + 1, rtpPort + 1, rtpPort + 101);
        endTime = System.currentTimeMillis();
        logger.info("RTCP Component created in " + (endTime - startTime) + " ms");
        return stream;
    }
}
