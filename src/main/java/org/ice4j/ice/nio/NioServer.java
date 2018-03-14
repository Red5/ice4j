package org.ice4j.ice.nio;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.StandardSocketOptions;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicReference;

import org.ice4j.StackProperties;
import org.ice4j.socket.IceSocketWrapper;
import org.ice4j.stack.StunStack;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>A robust class for establishing simultaneous TCP and UDP servers and manipulating their listening ports.
 * The {@link Event}s and property change events make it an appropriate tool in a threaded, GUI application.</p>
 *
 * <p>To start a server, create a new NioServer and call start():</p>
 *
 * <pre> NioServer server = new NioServer();
 * server.start();</pre>
 *
 * <p>You'll want to bind to a port or two:</p>
 *
 * <pre> server.addTcpBinding( new InetSocketAddress( 80 ) );
 * server.addUdpBinding( new InetSocketAddress( 80 ) );</pre>
 *
 * <p>Of course it won't be much help unless you register as a listener so you'll know when data has come in:</p>
 *
 * <pre> server.addNioServerListener( new NioServer.Adapter(){
 *     public void tcpDataReceived( NioServer.Event evt ){
 *         ByteBuffer buff = evt.getBuffer();
 *         ...
 *     }   // end data received
 *
 *     public void udpDataReceived( NioServer.Event evt ){
 *         ByteBuffer buff = evt.getBuffer();
 *         ...
 *     }   // end data received
 * });</pre>
 *
 * <p>The server runs on one thread, and all events are fired on that thread.
 * Consider off-loading heavy processing to another thread. Be aware that
 * you can register multiple listeners to respond to incoming data
 * so be mindful of more than one listener being around to makes calls
 * on the data.</p>
 *
 * <p>The public methods are all synchronized on <tt>this</tt>, and great
 * care has been taken to avoid deadlocks and race conditions. That being said,
 * there may still be bugs (please contact the author if you find any), and
 * you certainly still have the power to introduce these problems yourself.</p>
 *
 * <p>It's often handy to have your own class extend this one rather than
 * making an instance field to hold a NioServer where you'd have to
 * pass along all the setPort(...) methods and so forth.</p>
 *
 * <p>The supporting {@link Event}, {@link Listener}, and {@link Adapter}
 * classes are static inner classes in this file so that you have only one
 * file to copy to your project. You're welcome.</p>
 *
 * <p>This code is released into the Public Domain.
 * Since this is Public Domain, you don't need to worry about
 * licensing, and you can simply copy this NioServer.java file
 * to your own package and use it as you like. Enjoy.
 * Please consider leaving the following statement here in this code:</p>
 *
 * <p><em>This <tt>NioServer</tt> class was copied to this project from its source as
 * found at <a href="http://iharder.net" target="_blank">iHarder.net</a>.</em></p>
 *
 * @author Robert Harder (rharder@users.sourceforge.net)
 * @author Paul Gregoire
 * @version 0.2
 * @see NioServer
 * @see Adapter
 * @see Event
 * @see Listener
 */
public class NioServer {

    private final static Logger logger = LoggerFactory.getLogger(NioServer.class);

    // if we're using a single instance of the server for all stack instances
    private static NioServer instance;

    private static boolean SHARED_MODE = StackProperties.getBoolean("NIO_SHARED_MODE", false);

    private final static int BUFFER_SIZE_DEFAULT = 4096;

    private int inputBufferSize = BUFFER_SIZE_DEFAULT;

    private int outputBufferSize = BUFFER_SIZE_DEFAULT;

    /**
     * <p>One of four possible states for the server to be in:</p>
     *
     * <ul>
     *  <li>STARTING</li>
     *  <li>STARTED</li>
     *  <li>STOPPING</li>
     *  <li>STOPPED</li>
     * </ul>
     *
     * @see #getState() 
     */
    public static enum State {
        STARTING, STARTED, STOPPING, STOPPED
    };

    private AtomicReference<State> currentState = new AtomicReference<>(State.STOPPED);

    /**
     * Refers to the state of the server (STARTING, STARTED, STOPPING, STOPPED).
     * @see #getState() 
     */
    public final static String STATE_PROP = "state";

    /**
     * Refers to the last exception encountered internally on the server thread.
     *
     * @see #getLastException() 
     */
    public final static String LAST_EXCEPTION_PROP = "lastException";

    private Throwable lastException;

    private final Collection<NioServer.Listener> listeners = new ConcurrentLinkedQueue<NioServer.Listener>(); // Event listeners

    private final NioServer.Event event = new NioServer.Event(this); // Shared event

    private final PropertyChangeSupport propSupport = new PropertyChangeSupport(this); // Properties

    // I/O thread priority
    private int priority = Thread.MAX_PRIORITY - 4;

    // Blocking or Non-blocking I/O setting
    private boolean blockingIO;

    // The future for the submitted worker
    private Future<?> future;

    // Worker buffers
    private ByteBuffer inBuff, outBuff;

    private Selector selector; // Brokers all the connections

    /**
     * Refers to the TCP bindings for the server.
     * @see #addTcpBinding(java.net.SocketAddress)
     * @see #getTcpBindings()
     * @see #clearTcpBindings()
     * @see #setSingleTcpPort(int)
     * @see #getSingleTcpPort()
     */
    public final static String TCP_BINDINGS_PROP = "tcpBindings";

    /**
     * Refers to the UDP bindings for the server.
     * @see #addUdpBinding(java.net.SocketAddress)
     * @see #getUdpBindings()
     * @see #clearUdpBindings()
     * @see #setSingleUdpPort(int)
     * @see #getSingleUdpPort()
     */
    public final static String UDP_BINDINGS_PROP = "udpBindings";

    /**
     * Refers to the convenience methods for listening on a single port.
     * @see #addTcpBinding(java.net.SocketAddress)
     * @see #getTcpBindings()
     * @see #clearTcpBindings()
     * @see #setSingleTcpPort(int)
     * @see #getSingleTcpPort()
     */
    public final static String SINGLE_TCP_PORT_PROP = "singleTcpPort";

    /**
     * Refers to the convenience methods for listening on a single port.
     * @see #addUdpBinding(java.net.SocketAddress)
     * @see #getUdpBindings()
     * @see #clearUdpBindings()
     * @see #setSingleUdpPort(int)
     * @see #getSingleUdpPort()
     */
    public final static String SINGLE_UDP_PORT_PROP = "singleUdpPort";

    private final Map<SocketAddress, SelectionKey> tcpBindings = new HashMap<>();// Requested TCP bindings, e.g., "listen on port 80"

    private final Map<SocketAddress, SelectionKey> udpBindings = new HashMap<>();// Requested UDP bindings

    private final Set<SocketAddress> pendingTcpAdds = new CopyOnWriteArraySet<>(); // TCP bindings to add to selector on next cycle

    private final Set<SocketAddress> pendingUdpAdds = new CopyOnWriteArraySet<>(); // UDP bindings to add to selector on next cycle

    private final Map<SocketAddress, SelectionKey> pendingTcpRemoves = new HashMap<>(); // TCP bindings to remove from selector on next cycle

    private final Map<SocketAddress, SelectionKey> pendingUdpRemoves = new HashMap<>(); // UDP bindings to remove from selector on next cycle

    private final Map<SelectionKey, Boolean> pendingTcpNotifyOnWritable = new HashMap<>(); // Turning on and off writable notifications

    private final Map<SelectionKey, ByteBuffer> leftoverForReading = new HashMap<>(); // Store leftovers from the last read

    private final Map<SelectionKey, ByteBuffer> leftoverForWriting = new HashMap<>(); // Store leftovers that still need to be written

    private final Set<SelectionKey> closeAfterWriting = new HashSet<>();

    // simple identifier for the thread
    private final long id;

    // stun stack instance
    private StunStack stunStack;

    /* ******** C O N S T R U C T O R S ******** */

    /**
     * Constructs a new NioServer, listening to nothing, and not started.
     */
    private NioServer(StunStack stunStack) {
        // generate an id
        id = System.nanoTime();
        // set the stun stack
        this.stunStack = stunStack;
        logger.info("New NIO ICE {}server instanced: {}", (SHARED_MODE ? "shared " : ""), id);
        // create direct buffers for in/out
        inBuff = ByteBuffer.allocateDirect(inputBufferSize); // Buffer to use for everything
        outBuff = ByteBuffer.allocateDirect(outputBufferSize); // Buffer to use for everything
    }

    /**
     * Returns a static instance or a new instance, based upon the NIO_SHARED_MODE configuration property.
     * 
     * @return NioServer
     */
    public static NioServer getInstance(StunStack stunStack) {
        if (SHARED_MODE) {
            if (instance == null) {
                instance = new NioServer(stunStack);
            }
            return instance;
        }
        return new NioServer(stunStack);
    }

    /**
     * Returns whether or not shared mode is in-use.
     * 
     * @return true if shared and false otherwise
     */
    public static boolean isShared() {
        return SHARED_MODE;
    }

    /**
     * Used to aid in assertions. If you are running with assertions
     * turned off, then this method will never be run since it is
     * always called in the form <code>assert knownState(buff, "[PL..]").</code>
     *
     * @param buff the buffer
     * @param seq the format
     */
    private static boolean knownState(Buffer buff, CharSequence seq) {
        boolean dotFound = false; // .
        boolean undFound = false; // _
        boolean rFound = false; // r
        boolean PFound = false; // P
        boolean LFound = false; // L
        boolean endFound = false; // ]

        assert seq.charAt(0) == '[' : seq + " Expected '[' at beginning: " + seq.charAt(0);
        assert seq.charAt(seq.length() - 1) == ']' : seq + " Expected ']': " + seq.charAt(seq.length() - 1);
        for (int i = 1; i < seq.length(); i++) {
            char c = seq.charAt(i);
            switch (c) {
                case '.':
                    assert !(PFound && !LFound) : seq + " Between 'P' and 'L' should be 'r': " + c;
                    assert !undFound : seq + " Should not mix '.' and '_'";
                    dotFound = true;
                    break;

                case '_':
                    assert !(PFound && !LFound) : seq + " Between 'P' and 'L' should be 'r': " + c;
                    assert !dotFound : seq + " Should not mix '.' and '_'";
                    undFound = true;
                    break;

                case 'r':
                    assert PFound && !LFound : seq + " Should only see 'r' between 'P' and 'L'";
                    rFound = true;
                    break;

                case 'P':
                    assert !PFound : seq + " Too many P's";
                    if (undFound) {
                        assert buff.position() > 0 : seq + " Expected position to be positive: " + buff;
                    } else if (!dotFound) {
                        assert buff.position() == 0 : seq + " Expected position to be zero: " + buff;
                    }
                    PFound = true;
                    dotFound = false;
                    undFound = false;
                    break;

                case 'L':
                    assert PFound : seq + " 'L' should not come before 'P'";
                    assert !LFound : seq + " Too many L's";
                    if (rFound) {
                        assert buff.position() <= buff.limit() : seq + " Expected possible space between position and limit: " + buff;
                    } else {
                        assert buff.position() == buff.limit() : seq + " Expected position to equal limit: " + buff;
                    }
                    LFound = true;
                    rFound = false;
                    break;

                case ']':
                    assert PFound && LFound : seq + " 'P' and 'L' not found before ']'";
                    assert !endFound : seq + " Too many ]'s";
                    if (undFound) {
                        assert buff.limit() < buff.capacity() : seq + " Expected space between limit and capacity: " + buff;
                    } else if (!dotFound) {
                        assert buff.limit() == buff.capacity() : seq + " Expected limit to equal capacity: " + buff;
                    }
                    endFound = true;
                    dotFound = false;
                    undFound = false;
                    break;
                default:
                    assert false : seq + " Unexpected character: " + c;
            } // end switch curr char
        } // end for: through sequence
        return true;
    }

    /* ******** R U N N I N G ******** */

    /**
     * Attempts to start the server listening and returns immediately.
     * Listen for start events to know if the server was successfully started.
     *
     * @see NioServer.Listener
     */
    public void start() {
        if (currentState.compareAndSet(State.STOPPED, State.STARTING)) { // Only if we're stopped now
            setState(State.STARTED); // Mark as started
            pendingTcpAdds.addAll(tcpBindings.keySet());
            pendingUdpAdds.addAll(udpBindings.keySet());
            future = stunStack.submit(new Runnable() {
                @Override
                public void run() {
                    Thread.currentThread().setName(String.format("NioServer@%d", id));
                    Thread.currentThread().setPriority(priority);
                    runServer();
                    logger.debug("Server loop exited: {}", id);
                    stop();
                } // end run
            }); // end runnable
        } // end if: currently stopped
    } // end start

    /**
     * Attempts to stop the server, if the server is in the STARTED state, and returns immediately.
     * Be sure to listen for stop events to know if the server was successfully stopped.
     *
     * @see NioServer.Listener
     */
    public void stop() {
        logger.info("stop: {} state: {}", id, getState());
        if (currentState.compareAndSet(State.STARTED, State.STOPPING) || currentState.compareAndSet(State.STARTING, State.STOPPING)) { // Only if already STARTED
            // cancel future first to interrupt the runnable
            if (future.cancel(true)) {
                logger.info("Cancelling job: {}", id);
            } else {
                logger.warn("Job: {} could not be cancelled", id);
            }
            // try the wakeup
            if (selector != null) {
                selector.wakeup();
            } // end if: not null
            setState(State.STOPPED);
        } // end if: already STARTED
    } // end stop

    /**
     * Returns the current state of the server, one of STARTING, STARTED, STOPPING, or STOPPED.
     * 
     * @return state of the server
     */
    public State getState() {
        return currentState.get();
    }

    /**
     * Sets the state and fires an event. This method does not change what the server is doing, only
     * what is reflected by the currentState variable.
     * 
     * @param state the new state of the server
     */
    protected void setState(State state) {
        logger.info("setState to {} from {}", state, currentState.get());
        State oldVal = currentState.getAndSet(state);
        firePropertyChange(STATE_PROP, oldVal, state);
    }

    /**
     * Resets the server, if it is running, otherwise does nothing.
     * This is accomplished by registering as a listener, stopping
     * the server, detecting the stop, unregistering, and starting
     * the server again. It's a useful design pattern, and you may
     * want to look at the source code for this method to check it out.
     */
    @SuppressWarnings("incomplete-switch")
    public void reset() {
        switch (currentState.get()) {
            case STARTED:
                addPropertyChangeListener(STATE_PROP, new PropertyChangeListener() {
                    public void propertyChange(PropertyChangeEvent evt) {
                        State newState = (State) evt.getNewValue();
                        if (newState == State.STOPPED) {
                            NioServer server = (NioServer) evt.getSource();
                            server.removePropertyChangeListener(STATE_PROP, this);
                            server.start();
                        } // end if: stopped
                    } // end prop change
                });
                stop();
                break;
        } // end switch
    }

    /**
     * This method starts up and listens indefinitely for network connections. On entering this method,
     * the state is assumed to be STARTING. Upon exiting this method, the state will be STOPPING.
     */
    private void runServer() {
        try {
            while (runLoopCheck()) {
                ////////  B L O C K S   H E R E
                if (selector.select() <= 0) { // Block until notified
                    //Thread.sleep(1L);
                    //Thread.yield();
                }
                ///////  B L O C K S   H E R E
                if (currentState.get() == State.STARTED) {
                    // Possibly resize outBuff if a change was requested since last cycle
                    if (inputBufferSize != inBuff.capacity()) { // Mismatch size means someone asked for something new
                        assert inputBufferSize >= 0 : inputBufferSize; // We check for this in setBufferSize(..)
                        inBuff = ByteBuffer.allocateDirect(inputBufferSize); // Resize and use direct for OS efficiencies
                    }
                    // Possibly resize outBuff if a change was requested since last cycle
                    if (outputBufferSize != outBuff.capacity()) { // Mismatch size means someone asked for something new
                        assert outputBufferSize >= 0 : outputBufferSize; // We check for this in setBufferSize(..)
                        outBuff = ByteBuffer.allocateDirect(outputBufferSize); // Resize and use direct for OS efficiencies
                    }
                    Set<SelectionKey> keys = selector.selectedKeys(); // These keys need attention
                    if (logger.isTraceEnabled()) { // Only report this at finest grained logging level
                        logger.trace("Keys: {}", keys); // Which keys are being examined this round
                    }
                    Iterator<SelectionKey> iter = keys.iterator(); // Iterate over keys -- cannot use "for" loop since we remove keys
                    while (iter.hasNext()) { // Each accKey
                        SelectionKey key = iter.next(); // The accKey
                        iter.remove(); // Remove from list
                        try {
                            // Accept connections
                            // This should only be from the TCP bindings
                            if (key.isAcceptable()) { // New, incoming connection?
                                handleAccept(key, outBuff); // Handle accepting connections
                            }
                            // Data to read
                            // This could be an ongoing TCP connection or a new (is there any other kind) UDP datagram
                            else if (key.isReadable()) { // Existing connection has data (or is closing)
                                handleRead(key, inBuff, outBuff); // Handle data
                            } // end if: readable
                              // Available to write
                              // This could be an ongoing TCP connection or a new (is there any other kind) UDP datagram
                            else if (key.isWritable()) { // Existing connection has data (or is closing)
                                handleWrite(key, inBuff, outBuff); // Handle data
                            } // end if: readable
                        } catch (IOException exc) {
                            logger.warn("Encountered an error with a connection", exc);
                            fireExceptionNotification(exc);
                            key.channel().close();
                        } // end catch
                    } // end while: keys
                } else {
                    for (SelectionKey key : selector.keys()) {
                        key.channel().close();
                        key.cancel();
                        fireConnectionClosed(key); // Fire event for connection closed
                    }
                }
            } // end while: selector is open
        } catch (Exception exc) {
            logger.error("An error occurred while closing the server. This may have left the server in an undefined state.", exc);
            fireExceptionNotification(exc);
        } finally {
            if (selector != null) {
                try {
                    selector.close();
                } catch (IOException exc2) {
                    logger.error("An error occurred while closing the server. This may have left the server in an undefined state.", exc2);
                    fireExceptionNotification(exc2);
                } // end catch IOException
            } // end if: not null
            selector = null;
        } // end finally
        logger.info("Server exit: {}", id);
    }

    /**
     * Determines if server's "while" loop should continue and performs inter-cycle actions such as modifying server bindings.
     * @return true if while loop should continue
     * @throws java.io.IOException if something within throws it
     */
    private boolean runLoopCheck() throws IOException {
        if (currentState.get() == State.STOPPING) {
            logger.debug("Stopping server by request");
            assert selector != null;
            // no key needed on close
            fireConnectionClosed(null); // Fire event for connection closed
            selector.close();
        } else if (selector == null) {
            selector = Selector.open();
        }
        if (!selector.isOpen()) {
            return false;
        }
        // Pending TCP Adds
        for (SocketAddress addr : pendingTcpAdds) { // For each add
            logger.debug("Binding TCP: {}", addr);
            // Open a channel
            ServerSocketChannel sc = ServerSocketChannel.open();
            sc.setOption(StandardSocketOptions.SO_REUSEADDR, Boolean.TRUE);
            // Bind as requested
            sc.bind(addr);
            sc.configureBlocking(blockingIO); // set per blocking config
            // Register with master Selector
            SelectionKey acceptKey = sc.register(selector, SelectionKey.OP_ACCEPT); // We want to "accept" connections
            tcpBindings.put(addr, acceptKey); // Save the accKey
            // fire event for those listeners needing to know about bindings
            fireNewBinding(sc); // Fire event
        } // end for: each address
        pendingTcpAdds.clear(); // Remove list of pending adds
        // Pending UDP Adds
        for (SocketAddress addr : pendingUdpAdds) { // Same comments as for TCP
            logger.debug("Binding UDP: {}", addr);
            DatagramChannel dc = DatagramChannel.open();
            dc.bind(addr);
            dc.configureBlocking(false); // UDP + blocking causes IllegalBlockingModeEx
            SelectionKey acceptKey = dc.register(selector, SelectionKey.OP_READ);
            udpBindings.put(addr, acceptKey);
            // fire event for those listeners needing to know about bindings
            fireNewBinding(dc); // Fire event
        } // end for: each address
        pendingUdpAdds.clear();
        // Pending TCP Removes
        for (Map.Entry<SocketAddress, SelectionKey> e : pendingTcpRemoves.entrySet()) {
            SelectionKey key = e.getValue(); // Get the registered accKey
            if (key != null) { // Might be null if someone gave us bogus address
                key.channel().close(); // Close the channel
                key.cancel(); // And cancel the accKey (redundant?)
            } // end if: accKey != null
        } // end for: each remove
        pendingTcpRemoves.clear(); // Remove from list of pending removes
        // Pending UDP Removes
        for (Map.Entry<SocketAddress, SelectionKey> e : pendingUdpRemoves.entrySet()) {
            SelectionKey key = e.getValue(); // Get the registered accKey
            if (key != null) { // Might be null if someone gave us bogus address
                key.channel().close(); // Close the channel
                key.cancel(); // And cancel the accKey (redundant?)
            } // end if: accKey != null
        } // end for: each remove
        pendingUdpRemoves.clear(); // Remove from list of pending removes
        // Pending TCP Notify on Writable
        for (Map.Entry<SelectionKey, Boolean> e : pendingTcpNotifyOnWritable.entrySet()) {
            SelectionKey key = e.getKey();
            if (key != null && key.isValid()) {
                int ops = e.getKey().interestOps(); // Current ops
                if (e.getValue()) { // Notify?
                    ops |= SelectionKey.OP_WRITE; // Add OP_WRITE
                } else {
                    ops &= ~SelectionKey.OP_WRITE; // Remove OP_WRITE
                }
                e.getKey().interestOps(ops); // Set new interests
            } // end if: valid accKey
        } // end for: each notify on writable
        pendingTcpNotifyOnWritable.clear(); // Remove from list of pending changes
        return true; // Continue main run loop
    }

    /**
     * Handles accepting new connections.
     * @param sel The selector with which we'll register
     * @param key The OP_ACCEPT accKey
     * @throws java.io.IOException if an error occurs
     */
    private void handleAccept(SelectionKey accKey, ByteBuffer outBuff) throws IOException {
        assert accKey.isAcceptable() : accKey.readyOps(); // We know it should be acceptable
        assert selector.isOpen(); // Not sure this matters. Meh.
        SelectableChannel sc = accKey.channel(); // Channel for th accKey
        assert sc instanceof ServerSocketChannel : sc; // Only our TCP connections have OP_ACCEPT
        ServerSocketChannel ch = (ServerSocketChannel) accKey.channel(); // Server channel
        SocketChannel incoming = null; // Reusable for all pending connections
        while ((incoming = ch.accept()) != null) { // Iterate over all pending connections
            incoming.configureBlocking(blockingIO); // set per blocking config
            SelectionKey incomingReadKey = incoming.register( // Register new connection
                    selector, // With the Selector
                    SelectionKey.OP_READ | SelectionKey.OP_WRITE); // Want to READ and write data

            outBuff.clear().flip(); // Show outBuff as having nothing
            ////////  FIRE EVENT  ////////
            fireNewConnection(incomingReadKey, outBuff); // Fire new connection event
            ////////  FIRE EVENT  ////////
            // If there are leftovers, save them for next time the channel is ready.
            if (outBuff.remaining() > 0) { // Did the user leave data to be written?
                ByteBuffer leftover = ByteBuffer.allocateDirect(outBuff.remaining()); // Create/resize
                leftover.put(outBuff).flip(); // Save new leftovers
                assert knownState(leftover, "[PrrL..]");
                leftoverForWriting.put(incomingReadKey, leftover); // Save leftovers for next time
                setNotifyOnWritable(incomingReadKey, true); // Notify that we have something to write
            } // end if: has remaining bytes
            if (logger.isTraceEnabled()) {
                logger.trace("  {}, key: {}", incoming, incomingReadKey);
            }
        } // end while: each incoming connection
    }

    /**
     * Handles reading incoming data and then firing events.
     * @param key The accKey associated with the reading
     * @param buff the ByteBuffer to hold the data
     * @throws java.io.IOException if an error occurs
     */
    private void handleRead(SelectionKey key, ByteBuffer inBuff, ByteBuffer outBuff) throws IOException {
        SelectableChannel sc = key.channel();
        inBuff.clear(); // Clear input outBuff
        assert knownState(inBuff, "[PrrrL]");
        // TCP
        if (sc instanceof SocketChannel) {
            SocketChannel client = (SocketChannel) key.channel(); // Source socket
            ByteBuffer leftoverR = this.leftoverForReading.get(key); // Leftover data from last read
            // See if there's leftover data to be read and copy that into inBuff first.
            if (leftoverR != null && leftoverR.remaining() > 0) { // Have a leftoverR outBuff
                assert knownState(leftoverR, "[..PrrL..]");
                if (leftoverR.remaining() <= inBuff.remaining()) { // Is inBuff big enough to hold leftover
                    inBuff.put(leftoverR); // Preload all of leftoverR
                    assert knownState(inBuff, "[..PrrL]");
                } else {
                    while (leftoverR.hasRemaining() && inBuff.hasRemaining()) { // While they both have more to copy
                        inBuff.put(leftoverR.get()); // Copy one byte at a time. Yuck.
                    } // end while
                    assert knownState(inBuff, "[..PL]");
                } // end else
            } // end if: have leftoverR outBuff
              // Read into the outBuff here
              // If End of Stream
            if (client.read(inBuff) == -1) { // End of stream?
                key.cancel(); // Cancel the accKey
                client.close(); // And cancel the client
                cleanupClosedConnection(key);
                fireConnectionClosed(key); // Fire event for connection closed
                if (logger.isDebugEnabled()) {
                    logger.debug("Connection closed: " + key);
                }
            } else { // Not End of Stream
                inBuff.flip(); // Flip the outBuff to prepare to be read
                outBuff.clear().flip(); // Empty output outBuff
                assert knownState(inBuff, "[PrrL..]");
                assert knownState(outBuff, "[PL...]");
                fireTcpDataReceived(key, inBuff, outBuff); // Fire event for new data
                // If there is also data to be written, save them in the leftover-for-writing outBuff
                // and indicate that we should be notified about writability.
                if (outBuff.remaining() > 0) { // Did the user leave data to be written?
                    ByteBuffer leftoverW = leftoverForWriting.get(key); // Leftover still to be written
                    if (leftoverW == null) { // Leftover outBuff not yet created?
                        leftoverW = ByteBuffer.allocateDirect(outBuff.remaining()); // Create/resize
                    } else {
                        assert knownState(outBuff, "[..PrrL..]");
                        if (outBuff.remaining() > // Amount requested to be written
                        leftoverW.capacity() - leftoverW.limit()) { // vs. space remaining in leftoverW

                            ByteBuffer temp = ByteBuffer.allocateDirect( // Resize outBuff to...
                                    leftoverW.limit() - leftoverW.position() + // data remaining in leftover plus
                                            outBuff.remaining()); // amount requested this round

                            temp.put(leftoverW).flip(); // Put new buff in proper state (ready to be read)
                            leftoverW = temp; // Replace old leftoverW outBuff
                            assert knownState(leftoverW, "[PrrL__]");

                        } // end if: resize leftoverW
                        assert knownState(leftoverW, "[PrrL..]");
                        leftoverW.position(leftoverW.limit()); // Move position to end of relevant data
                        leftoverW.limit(leftoverW.capacity()); // Move limit to end of outBuff
                        assert knownState(leftoverW, "[..PrrL]");
                    }
                    assert knownState(leftoverW, "[..PrrL]");
                    assert knownState(outBuff, "[..PrrL..]");
                    leftoverW.put(outBuff).flip(); // Record newly-arrived data and flip leftoverW

                    assert knownState(leftoverW, "[PrrL..]");
                    assert knownState(outBuff, "[..PL..]");

                    leftoverForWriting.put(key, leftoverW); // Save leftovers for next time
                    setNotifyOnWritable(key, true); // Make sure server processes writes
                } // end if: has remaining bytes

                // If there's leftover data that wasn't read, save that for next time the event is fired.
                if (inBuff.remaining() > 0) { // Did the user leave data for next time?
                    if (leftoverR == null || // Leftover outBuff not yet created?
                            inBuff.remaining() > leftoverR.capacity()) { // Or is too small?
                        leftoverR = ByteBuffer.allocateDirect(inBuff.remaining()); // Create/resize
                    } // end if: need to resize
                    assert knownState(inBuff, "[..PrrL..]");
                    leftoverR.clear(); // Clear old leftovers
                    leftoverR.put(inBuff).flip(); // Save new leftovers
                    assert knownState(leftoverR, "[PrrL..]");

                } // end if: has remaining bytes
                this.leftoverForReading.put(key, leftoverR); // Save leftovers for next time
            } // end else: read
        } // end if: SocketChannel
          // Datagram
        else if (sc instanceof DatagramChannel) {
            DatagramChannel dc = (DatagramChannel) sc; // Cast to datagram channel
            SocketAddress remote = null;
            while ((remote = dc.receive(inBuff)) != null) { // Loop over all pending datagrams
                inBuff.flip(); // Flip after reading in
                outBuff.clear().flip();
                key.attach(inBuff); // Attach outBuff to accKey
                fireUdpDataReceived(key, inBuff, outBuff, remote); // Fire event
                if (outBuff.hasRemaining()) { // User left data for response?
                    dc.send(outBuff, remote); // Try sending it
                } // end if: something to write
            } // end while: each pending datagram
        } // end else: UDP
    } // end handleRead

    /**
     * Handles notifying listeners that a channel is ready to write.
     * @param key The accKey associated with the writing
     * @param buff the ByteBuffer to hold the data
     * @throws java.io.IOException if an error occurs
     */
    private void handleWrite(SelectionKey key, ByteBuffer inBuff, ByteBuffer outBuff) throws IOException {
        SocketChannel ch = (SocketChannel) key.channel(); // Source socket
        // First see if we need to write old data that still hasn't been sent.
        ByteBuffer leftover = this.leftoverForWriting.get(key); // Leftover data still needing to be written
        if (leftover != null && leftover.remaining() > 0) { // Have a leftoverR outBuff
            assert knownState(leftover, "[PrrL..]");
            // DISCUSSION POINT:
            //     On the one hand, "leftover" will never be bigger than the output buffer because we only give
            // the user an opportunity to load the output buffer when the leftover buffer is empty. In this case, we don't
            // need to worry about the leftover buffer somehow growing too big such that we might hog the server's thread,
            // especially on a slow connection.
            //     However it's possible that someone could resize the output buffer with setOutputBufferSize(..) and that
            // could result in a larger or smaller leftover buffer. This doesn't seem so bad since the leftover size must
            // still be something reasonable that was _once_ the output buffer size and was therefore _once_ considered
            // a reasonable size perhaps.
            //     In any event, there would be no need to copy the leftover buffer to the output buffer before writing,
            // a notion that might come up for efficiency reasons, since A) the leftover buffer is a direct buffer anyway,
            // and B) if it wasn't, the system would automatically copy the data to system memory eventually anyway.
            ch.write(leftover);
            if (!leftover.hasRemaining()) {
                leftover.clear().flip();
            }
        } // end if: have leftoverW outBuff
          // If we're done with leftovers, or there were none, notify user to ask for more.
        if (leftover == null || !leftover.hasRemaining()) {
            outBuff.clear().flip(); // Clear outBuff
            ////////  FIRE EVENT  ////////
            fireTcpReadyToWrite(key, outBuff); // Notify listeners who will load outBuff
            ////////  FIRE EVENT  ////////
            if (outBuff.hasRemaining()) { // Did they give us something?
                ch.write(outBuff); // Write what we can of it
            } else { // They gave us nothing
                this.setNotifyOnWritable(key, false); // Stop notifying 
            }
            // If there are new leftovers, save them for next
            // time the channel is ready.
            if (outBuff.hasRemaining()) { // Is there _still_ data left to write?
                if (leftover == null || // Leftover outBuff not yet created?
                        outBuff.remaining() > leftover.capacity()) { // Or is too small?
                    leftover = ByteBuffer.allocateDirect(outBuff.remaining()); // Create/resize
                } // end if: need to resize
                leftover.clear(); // Clear old leftovers
                assert knownState(outBuff, "[..PrrL..]");
                leftover.put(outBuff).flip(); // Save new leftovers
                assert knownState(leftover, "[PrrL..]");
            }
            leftoverForWriting.put(key, leftover); // Save leftovers for next time
        } // end if: proceed with fresh buffer to user
          // After all this writing, see if there's anything left.
          // If nothing is left, and "close after writing" has been set, then close the channel.
        if (closeAfterWriting.contains(key) && // Has user requested "close after writing?"
                (leftover == null || !leftover.hasRemaining())) { // And is there nothing left to write?
            ch.close(); // Then close the channel
        }
    } // end handleWrite

    /**
     * Removes the accKey and associated data from any maps, sets, etc
     * that the server uses for state information.
     * @param key the accKey that's closing
     */
    private void cleanupClosedConnection(SelectionKey key) {
        pendingTcpNotifyOnWritable.remove(key);
        leftoverForReading.remove(key);
        leftoverForWriting.remove(key);
        closeAfterWriting.remove(key);
        pendingTcpNotifyOnWritable.remove(key);
    }

    /**
     * Sets whether or not events will fire when a channel is ready
     * to be written to. After a
     * {@link NioServer.Listener#tcpReadyToWrite(NioServer.Event)}
     * returns with no data in the output buffer, this will
     * be turned off until you either A) turn it on yourself, or
     * B) provide data in an output buffer from another event.</p>
     *
     * @param key The accKey representing the connection in question
     * @param notify Whether or not to notify
     * @throws NullPointerException if accKey is null
     */
    public synchronized void setNotifyOnWritable(SelectionKey key, boolean notify) {
        //if(notify){
        //    System.out.println("Turning on notifications for " + accKey );
        //} else {
        //    System.out.println("Turning off notifications for " + accKey );
        //}
        if (key == null) {
            throw new NullPointerException("Cannot set notifications for null key.");
        }
        pendingTcpNotifyOnWritable.put(key, notify);
        if (selector != null) {
            selector.wakeup();
        }
    }

    /**
     * Convenience method for telling the server to close the connection
     * after the last byte of the output buffer has been written.
     * @param key the SelectionKey for the corresponding connection
     */
    public void closeAfterWriting(SelectionKey key) {
        closeAfterWriting.add(key);
    } // end closeAfterWriting

    /**
     * Sets the I/O thread priority. Default is (Maximum priority - 4) or 6.
     * 
     * @param priority
     */
    public void setPriority(int priority) {
        this.priority = priority;
    }

    /**
     * Sets the time to sleep in milliseconds between selector checks.
     * 
     * @param selectorSleepMs
     */
    @Deprecated
    public void setSelectorSleepMs(long selectorSleepMs) {
        //this.selectorSleepMs = selectorSleepMs;
    }

    /**
     * Whether or not blocking I/O is enabled.
     * 
     * @return true if blocking and false if non-blocking
     */
    public boolean isBlockingIO() {
        return blockingIO;
    }

    /**
     * Sets blocking I/O to enabled or disable.
     * 
     * @param blockingIO true for BIO and false for NIO (default)
     */
    public void setBlockingIO(boolean blockingIO) {
        this.blockingIO = blockingIO;
    }

    /**
     * Returns the size of the ByteBuffer used to read
     * from the connections. This refers to the buffer
     * that will be passed along with {@link Event}
     * objects as data is received and so forth.
     * @return The size of the ByteBuffer
     */
    public int getInputBufferSize() {
        return inputBufferSize;
    }

    /**
     * Sets the size of the ByteBuffer used to read from the connections. This refers to the buffer
     * that will be passed along with {@link Event} objects as data is received and so forth.
     * 
     * @param size The size of the ByteBuffer
     * @throws IllegalArgumentException if size is not positive
     */
    public void setInputBufferSize(int size) {
        if (size <= 0) {
            throw new IllegalArgumentException("New buffer size must be positive: " + size);
        } // end if: size outside range
          //int oldVal = inputBufferSize;
        inputBufferSize = size;
        if (selector != null) {
            selector.wakeup();
        }
        //firePropertyChange(INPUT_BUFFER_SIZE_PROP, oldVal, size);
    }

    /**
     * Returns the size of the ByteBuffer used to write to the connections. This refers to the buffer
     * that will be passed along with {@link Event} objects.
     * 
     * @return The size of the ByteBuffer
     */
    public int getOutputBufferSize() {
        return outputBufferSize;
    }

    /**
     * Sets the size of the ByteBuffer used to write
     * from the connections. This refers to the buffer
     * that will be passed along with {@link Event}
     * objects.
     * @param size The size of the ByteBuffer
     * @throws IllegalArgumentException if size is not positive
     */
    public void setOutputBufferSize(int size) {
        if (size <= 0) {
            throw new IllegalArgumentException("New buffer size must be positive: " + size);
        } // end if: size outside range
          //int oldVal = outputBufferSize;
        outputBufferSize = size;
        if (selector != null) {
            selector.wakeup();
        }
        //firePropertyChange(OUTPUT_BUFFER_SIZE_PROP, oldVal, size);
    }

    /* ******** T C P B I N D I N G S ******** */

    /**
     * Adds a TCP binding to the server. Effectively this is how you
     * set which ports and on which interfaces you want the server
     * to listen. In the simplest case, you might do the following
     * to listen generically on port 80:
     * <code>addTcpBinding( new InetAddress(80) );</code>.
     * The server can listen on multiple ports at once.
     * @param addr The address on which to listen
     * @return "this" to aid in chaining commands
     */
    public synchronized NioServer addTcpBinding(SocketAddress addr) {
        Set<SocketAddress> oldVal = getTcpBindings(); // Save old set for prop change event
        tcpBindings.put(addr, null); // Add binding
        Set<SocketAddress> newVal = getTcpBindings(); // Save new set for prop change event
        pendingTcpAdds.add(addr); // Prepare pending add action
        pendingTcpRemoves.remove(addr); // In case it's also pending a remove
        if (selector != null) { // If there's a selector...
            selector.wakeup(); // Wake it up to handle the add action
        }
        firePropertyChange(TCP_BINDINGS_PROP, oldVal, newVal); // Fire prop change
        return this;
    }

    /**
     * Removes a TCP binding. Effectively stops the server from
     * listening to this or that port.
     * @param addr The address to stop listening to
     * @return "this" to aid in chaining commands
     */
    public synchronized NioServer removeTcpBinding(SocketAddress addr) {
        Set<SocketAddress> oldVal = getTcpBindings(); // Save old set for prop change event
        pendingTcpRemoves.put(addr, tcpBindings.get(addr)); // Prepare pending remove action
        tcpBindings.remove(addr); // Remove binding
        pendingTcpAdds.remove(addr); // In case it's also pending an add
        Set<SocketAddress> newVal = getTcpBindings(); // Save new set for prop change event
        if (selector != null) { // If there's a selector...
            selector.wakeup(); // Wake it up to handle the remove action
        }
        // remove any listeners for the binding as well
        for (Listener listener : listeners) {
            IceSocketWrapper wrapper = ((Adapter) listener).getWrapper();
            if (wrapper != null && wrapper.getTransportAddress().equals(addr)) {
                removeNioServerListener(listener);
                break;
            }
        }
        firePropertyChange(TCP_BINDINGS_PROP, oldVal, newVal); // Fire prop change
        return this;
    }

    /**
     * Returns a set of socket addresses that the server is (or will be when started) bound to/listening on. This set is not
     * backed by the actual data structures. Changes to this returned set have no effect on the server.
     * @return set of tcp listening points
     */
    public Set<SocketAddress> getTcpBindings() {
        return Collections.unmodifiableSet(tcpBindings.keySet());
    }

    /**
     * <p>Sets the TCP bindings that the server should use. The expression <code>setTcpBindings( getTcpBindings() )</code>
     * should result in no change to the server.</p>
     * @param newSet
     * @return "this" to aid in chaining commands
     */
    public synchronized NioServer setTcpBindings(Set<SocketAddress> newSet) {
        Set<SocketAddress> toAdd = new HashSet<SocketAddress>();
        Set<SocketAddress> toRemove = getTcpBindings();
        for (SocketAddress addr : newSet) {
            if (toRemove.contains(addr)) {
                toRemove.remove(addr);
            } else {
                toAdd.add(addr);
            }
        } // end for: each new addr
        for (SocketAddress addr : toRemove) {
            removeTcpBinding(addr);
        } // end for: each new addr
        for (SocketAddress addr : toAdd) {
            addTcpBinding(addr);
        } // end for: each new addr
        return this;
    }

    /**
     * Clears all TCP bindings.
     * @return "this" to aid in chaining commands
     */
    public NioServer clearTcpBindings() {
        for (SocketAddress addr : getTcpBindings()) {
            removeTcpBinding(addr);
        }
        return this;
    }

    /* ******** U D P B I N D I N G S ******** */

    /**
     * Adds a UDP binding to the server. Effectively this is how you
     * set which ports and on which interfaces you want the server
     * to listen. In the simplest case, you might do the following
     * to listen generically on port 6997:
     * <code>addUdpBinding( new InetAddress(6997) );</code>.
     * The server can listen on multiple ports at once.
     * @param addr The address on which to listen
     * @return "this" to aid in chaining commands
     */
    public synchronized NioServer addUdpBinding(SocketAddress addr) {
        Set<SocketAddress> oldVal = getUdpBindings();
        udpBindings.put(addr, null);
        pendingUdpAdds.add(addr);
        pendingUdpRemoves.remove(addr);
        Set<SocketAddress> newVal = getUdpBindings();
        if (selector != null) {
            selector.wakeup();
        }
        firePropertyChange(UDP_BINDINGS_PROP, oldVal, newVal);
        return this;
    }

    /**
     * Removes a UDP binding. Effectively stops the server from
     * listening to this or that port.
     * @param addr The address to stop listening to
     * @return "this" to aid in chaining commands
     */
    public synchronized NioServer removeUdpBinding(SocketAddress addr) {
        Set<SocketAddress> oldVal = getUdpBindings(); // Save old set for prop change event
        pendingUdpRemoves.put(addr, udpBindings.get(addr)); // Prepare pending remove action
        udpBindings.remove(addr); // Remove binding
        pendingUdpAdds.remove(addr); // In case it's also pending an add
        Set<SocketAddress> newVal = getUdpBindings(); // Save new set for prop change event
        if (selector != null) { // If there's a selector...
            selector.wakeup(); // Wake it up to handle the remove action
        }
        // remove any listeners for the binding as well
        for (Listener listener : listeners) {
            IceSocketWrapper wrapper = ((Adapter) listener).getWrapper();
            if (wrapper != null && wrapper.getTransportAddress().equals(addr)) {
                removeNioServerListener(listener);
                break;
            }
        }
        firePropertyChange(UDP_BINDINGS_PROP, oldVal, newVal); // Fire prop change
        return this;
    }

    /**
     * Returns a map of socket addresses that the server is (or will be when started) bound to/listening on. This set is not
     * backed by the actual data structures. Changes to this returned set have no effect on the server.
     * @return set of udp listening points
     */
    public Set<SocketAddress> getUdpBindings() {
        return Collections.unmodifiableSet(udpBindings.keySet());
    }

    /**
     * <p>Sets the UDP bindings that the server should use.
     * The expression <code>setTcpBindings( getTcpBindings() )</code>
     * should result in no change to the server.</p>
     *
     * @param newSet
     * @return "this" to aid in chaining commands
     */
    public synchronized NioServer setUdpBindings(Set<SocketAddress> newSet) {
        Set<SocketAddress> toAdd = new HashSet<SocketAddress>();
        Set<SocketAddress> toRemove = getUdpBindings();
        for (SocketAddress addr : newSet) {
            if (toRemove.contains(addr)) {
                toRemove.remove(addr);
            } else {
                toAdd.add(addr);
            }
        } // end for: each new addr
        for (SocketAddress addr : toRemove) {
            removeUdpBinding(addr);
        } // end for: each new addr
        for (SocketAddress addr : toAdd) {
            addUdpBinding(addr);
        } // end for: each new addr
        return this;
    }

    /**
     * Clears all UDP bindings.
     * @return "this" to aid in chaining commands
     */
    public NioServer clearUdpBindings() {
        for (SocketAddress addr : getUdpBindings()) {
            removeUdpBinding(addr);
        }
        return this;
    }

    /* ******** S I N G L E P O R T ******** */

    /**
     * Convenience method for clearing all bindings and
     * setting up listening for TCP on the given port.
     * @param port the port to listen to
     * @return <code>this</code> to aid in chaining
     * @throws IllegalArgumentException if port is out of range
     */
    public synchronized NioServer setSingleTcpPort(int port) {
        int oldVal = getSingleTcpPort();
        if (oldVal == port) {
            return this;
        }
        clearTcpBindings();
        addTcpBinding(new InetSocketAddress(port));
        int newVal = port;
        firePropertyChange(SINGLE_TCP_PORT_PROP, oldVal, newVal);
        return this;
    }

    /**
     * Convenience method for clearing all bindings and setting up listening for UDP on the given port.
     * @param port the port to listen to
     * @return <code>this</code> to aid in chaining
     * @throws IllegalArgumentException if port is out of range
     */
    public synchronized NioServer setSingleUdpPort(int port) {
        int oldVal = getSingleUdpPort();
        if (oldVal == port) {
            return this;
        }
        clearUdpBindings();
        addUdpBinding(new InetSocketAddress(port));
        int newVal = port;
        firePropertyChange(SINGLE_UDP_PORT_PROP, oldVal, newVal);
        return this;
    }

    /**
     * Returns the port for the single TCP binding in effect, or -1 (minus one) if there are no or multiple TCP
     * bindings or some other error.
     * @return TCP listening port or -1
     */
    public synchronized int getSingleTcpPort() {
        int port = -1;
        Set<SocketAddress> bindings = getTcpBindings();
        if (bindings.size() == 1) {
            SocketAddress sa = bindings.iterator().next();
            if (sa instanceof InetSocketAddress) {
                port = ((InetSocketAddress) sa).getPort();
            } // end if: inet
        } // end if: only one binding
        return port;
    }

    /**
     * Returns the port for the single UDP binding in effect,
     * or -1 (minus one) if there are no or multiple UDP
     * bindings or some other error.
     * @return UDP listening port or -1
     */
    public synchronized int getSingleUdpPort() {
        int port = -1;
        Set<SocketAddress> bindings = getUdpBindings();
        if (bindings.size() == 1) {
            SocketAddress sa = bindings.iterator().next();
            if (sa instanceof InetSocketAddress) {
                port = ((InetSocketAddress) sa).getPort();
            } // end if: inet
        } // end if: only one binding
        return port;
    }

    /* ******** E V E N T S ******** */

    /**
     * Adds a {@link Listener}.
     * @param l the listener
     */
    public void addNioServerListener(NioServer.Listener l) {
        listeners.add(l);
    }

    /**
     * Removes a {@link Listener}.
     * @param l the listener
     */
    public void removeNioServerListener(NioServer.Listener l) {
        listeners.remove(l);
    }

    /**
     * Fire when data is received.
     * @param key the SelectionKey associated with the data
     * @param outBuff the outBuff containing the new (and possibly leftoverR) data
     */
    protected synchronized void fireTcpDataReceived(SelectionKey key, ByteBuffer inBuff, ByteBuffer outBuff) {
        this.event.reset(key, inBuff, outBuff, null);
        // Make a Runnable object to execute the calls to listeners.
        // In the event we don't have an Executor, this results in an unnecessary object instantiation, but it also makes
        // the code more maintainable.
        for (NioServer.Listener l : listeners) {
            try {
                l.tcpDataReceived(event);
            } catch (Exception exc) {
                logger.warn("NioServer.Listener {} threw an exception: ", l, exc);
                fireExceptionNotification(exc);
            } // end catch
        } // end for: each listener
    }

    /**
     * Fire when data is received.
     * @param key the SelectionKey associated with the data
     * @param outBuff the outBuff containing the new (and possibly leftoverR) data
     */
    protected synchronized void fireTcpReadyToWrite(SelectionKey key, ByteBuffer outBuff) {
        assert knownState(outBuff, "[PL..]");
        this.event.reset(key, null, outBuff, null);
        // Make a Runnable object to execute the calls to listeners.
        // In the event we don't have an Executor, this results in an unnecessary object instantiation, but it also makes
        // the code more maintainable.
        for (NioServer.Listener l : listeners) {
            try {
                l.tcpReadyToWrite(event);
            } catch (Exception exc) {
                exc.printStackTrace();//TODO REMOVE THIS
                logger.warn("NioServer.Listener {} threw an exception: ", l, exc);
                fireExceptionNotification(exc);
            } // end catch
        } // end for: each listener
    }

    /**
     * Fire when data is received.
     * @param key the SelectionKey associated with the data
     * @param inBuff the input buffer containing the data
     * @param remote the source address of the datagram or null if not available
     * @param outBuff the output buffer for writing data
     */
    protected synchronized void fireUdpDataReceived(SelectionKey key, ByteBuffer inBuff, ByteBuffer outBuff, SocketAddress remote) {
        this.event.reset(key, inBuff, outBuff, remote);
        // Make a Runnable object to execute the calls to listeners.
        // In the event we don't have an Executor, this results in an unnecessary object instantiation, but it also makes
        // the code more maintainable.
        for (NioServer.Listener l : listeners) {
            try {
                l.udpDataReceived(event);
            } catch (Exception exc) {
                logger.warn("NioServer.Listener {} threw an exception: ", l, exc);
                fireExceptionNotification(exc);
            } // end catch
        } // end for: each listener
    } // end fireNioServerPacketReceived

    /**
     * Fire when a connection is closed remotely.
     * @param key The accKey for the closed connection.
     */
    protected synchronized void fireConnectionClosed(SelectionKey key) {
        this.event.reset(key, null, null, null);
        // Make a Runnable object to execute the calls to listeners.
        // In the event we don't have an Executor, this results in an unnecessary object instantiation, but it also makes
        // the code more maintainable.
        for (NioServer.Listener l : listeners) {
            try {
                l.connectionClosed(event);
            } catch (Exception exc) {
                logger.warn("NioServer.Listener {} threw an exception: ", l, exc);
                fireExceptionNotification(exc);
            } // end catch
        } // end for: each listener
    } // end fireNioServerPacketReceived

    /**
     * Fire when a new connection is established.
     * @param key the SelectionKey associated with the connection
     */
    protected synchronized void fireNewConnection(SelectionKey key, ByteBuffer outBuff) {
        this.event.reset(key, null, outBuff, null);
        // Make a Runnable object to execute the calls to listeners.
        // In the event we don't have an Executor, this results in an unnecessary object instantiation, but it also makes
        // the code more maintainable.
        for (NioServer.Listener l : listeners) {
            try {
                l.newConnectionReceived(event);
            } catch (Exception exc) {
                logger.warn("NioServer.Listener {} threw an exception: ", l, exc);
                fireExceptionNotification(exc);
            } // end catch
        } // end for: each listener
    } // end fireNioServerPacketReceived

    /**
     * Fire when a local binding is established.
     * @param channel SelectableChannel that has been bound
     */
    protected synchronized void fireNewBinding(SelectableChannel channel) {
        BindingEvent bound = new BindingEvent(this, channel);
        // Make a Runnable object to execute the calls to listeners.
        // In the event we don't have an Executor, this results in an unnecessary object instantiation, but it also makes
        // the code more maintainable.
        for (NioServer.Listener l : listeners) {
            try {
                l.newBinding(bound);
            } catch (Exception exc) {
                logger.warn("NioServer.Listener {} threw an exception: ", l, exc);
                fireExceptionNotification(exc);
            } // end catch
        } // end for: each listener
    } // end fireNioServerPacketReceived

    /* ******** P R O P E R T Y C H A N G E ******** */

    /**
     * Fires property chagne events for all current values
     * setting the old value to null and new value to the current.
     */
    public synchronized void fireProperties() {
        firePropertyChange(STATE_PROP, null, getState());
        //firePropertyChange(INPUT_BUFFER_SIZE_PROP, null, getInputBufferSize());
        //firePropertyChange(OUTPUT_BUFFER_SIZE_PROP, null, getOutputBufferSize());
    }

    /**
     * Fire a property change event on the current thread.
     *
     * @param prop      name of property
     * @param oldVal    old value
     * @param newVal    new value
     */
    protected synchronized void firePropertyChange(final String prop, final Object oldVal, final Object newVal) {
        try {
            propSupport.firePropertyChange(prop, oldVal, newVal);
        } catch (Exception exc) {
            logger.warn("A property change listener threw an exception", exc);
            fireExceptionNotification(exc);
        } // end catch
    } // end fire

    /**
     * Add a property listener.
     * @param listener the listener
     */
    public synchronized void addPropertyChangeListener(PropertyChangeListener listener) {
        propSupport.addPropertyChangeListener(listener);
    }

    /**
     * Add a property listener for the named property.
     * @param property the property name
     * @param listener the listener
     */
    public synchronized void addPropertyChangeListener(String property, PropertyChangeListener listener) {
        propSupport.addPropertyChangeListener(property, listener);
    }

    /**
     * Remove a property listener.
     * @param listener the listener
     */
    public synchronized void removePropertyChangeListener(PropertyChangeListener listener) {
        propSupport.removePropertyChangeListener(listener);
    }

    /**
     * Remove a property listener for the named property.
     * @param property the property name
     * @param listener the listener
     */
    public synchronized void removePropertyChangeListener(String property, PropertyChangeListener listener) {
        propSupport.removePropertyChangeListener(property, listener);
    }

    /* ******** E X C E P T I O N S ******** */

    /**
     * Returns the last exception (Throwable, actually)
     * that the server encountered.
     * @return last exception
     */
    public synchronized Throwable getLastException() {
        return this.lastException;
    }

    /**
     * Fires a property change event with the new exception.
     * @param t
     */
    protected void fireExceptionNotification(Throwable t) {
        Throwable oldVal = this.lastException;
        this.lastException = t;
        firePropertyChange(LAST_EXCEPTION_PROP, oldVal, t);
    }

    /* ******** ******** */
    /* ******** ******** */
    /* ******** S T A T I C I N N E R C L A S S L I S T E N E R ******** */
    /* ******** ******** */
    /* ******** ******** */

    /**
     * <p>An interface for listening to events from a {@link NioServer}.
     * A single {@link Event} is shared for all invocations of these methods.</p>
     *
     * <p>Of critical importance are the input and output buffers, as provided by
     * {@link NioServer.Event#getInputBuffer()} and {@link NioServer.Event#getOutputBuffer()}. Below is a table
     * describing the significance of the input and output buffers upon entering and exiting the listener's events.<p>
     *
     * <table>
     *  <thead>
     *   <tr><th>Event</th><th>Input outBuff upon entering event</th><th>Output outBuff upon exiting event</th></tr>
     *  </thead>
     *  <tbody>
     *   <tr>
     *    <td>New connection received</td>
     *    <td><code>null</code></td>
     *    <td>NA</td>
     *   </tr>
     *  </tbody>
     * </table>
     */
    public static interface Listener extends java.util.EventListener {

        /**
         * <p>Called when a new connection is received. The SelectionKey associated
         * with the event (with <code>OP_READ</code> interest), is the accKey that will be
         * used with the data received event. In this way, you can seed a
         * <code>Map</code> or other data structure and associate this very
         * accKey with the connection. You will only get new connection
         * events for TCP connections (not UDP).</p>
         *
         * <p>The accKey's attachment mechanism is unused by NioServer and is
         * available for you to store whatever you like.</p>
         *
         * <p>If your protocol requires the server to respond to a client
         * upon connection, this sample code demonstrates such an arrangement
         * being careful not to instantiate objects at each event:</p>
         *
         * <pre>
         *   private CharsetEncoder encoder = Charset.forName("US-ASCII");
         *   private CharBuffer greeting = CharBuffer.wrap("Greetings\r\n");
         *   ...
         *   public void newConnectionReceived(NioServer.Event evt) {
         *       ByteBuffer outBuff = evt.getOutputBuffer();
         *       outBuff.clear();
         *       greeting.rewind();
         *       encoder.reset().encode( greeting, outBuff, true );
         *       outBuff.flip();
         *   }
         * </pre>
         *
         * @param evt the shared event
         */
        public abstract void newConnectionReceived(NioServer.Event evt);

        /**
         * <p>Called when TCP data is received. Retrieve the associated ByteBuffer
         * with {@link NioServer.Event#getInputBuffer()}.
         * This is the source ByteBuffer
         * used by the server directly to receive the data. It is a
         * "direct" ByteBuffer (created with <code>ByteBuffer.allocateDirect(..)</code>).</p>
         *
         * <p>Read from it as much as
         * you can. Any data that remains on or after the value
         * of <code>position()</code> will be saved for the next
         * time an event is fired. In this way, you can defer
         * processing incomplete data until everything arrives.</p>
         *
         * <p><em>If you leave the buffer full, all the way up to the
         * very last byte at <code>capacity()</code>, then that
         * connection cannot receive any more data.</em> On some operating systems
         * and Java virtual machines, this will serve to throttle back
         * the client sending the data.</p>
         *
         * <p>The accKey's attachment mechanism is unused by NioServer and is
         * available for you to store whatever you like.</p>
         *
         * <p>If you wish to also write data as a result of what is read,
         * the preferred method is to retrieve the output buffer with
         * {@link NioServer.Event#getOutputBuffer()} and write bytes
         * there, leaving the buffer in a ready-to-read state:</p>
         *
         * <pre>
         *       ByteBuffer buff = evt.getOutputBuffer();       // Reuse it since it's already allocated
         *       buff.clear();                                  // Prepare outBuff for writing
         *       buff.putLong( System.currentTimeMillis() );    // Store data
         *       buff.flip();                                   // Put outBuff in "read me from here" mode
         * </pre>
         *
         * <p>To make a trivial "echo" program, simple copy the contents
         * of the input buffer to the output buffer:</p>
         *
         * <pre>
         * NioServer ns = new NioServer();
         * ns.addNioServerListener(new NioServer.Adapter(){
         *      public void tcpDataReceived(NioServer.Event evt) {
         *          ByteBuffer inBuff = evt.getInputBuffer();
         *          ByteBuffer outBuff = evt.getOutputBuffer();
         *          outBuff.clear();
         *          outBuff.put(inBuff);
         *          outBuff.flip();
         *      }
         * });
         * </pre>
         *
         * @param evt the shared event
         */
        public abstract void tcpDataReceived(NioServer.Event evt);

        /**
         * <p>Called when UDP data is received. Retrieve the associated ByteBuffer
         * with {@link NioServer.Event#getInputBuffer()}.
         * This is the source ByteBuffer
         * used by the server directly to receive the data. It is a
         * "direct" ByteBuffer (created with <code>ByteBuffer.allocateDirect(..)</code>).
         * The contents of the ByteBuffer will be the entire contents
         * received from the UDP datagram. If you leave data in the output buffer
         * ({@link NioServer.Event#getOutputBuffer()}), the server will attempt
         * to send a UDP reply to the IP and port specified as the source
         * IP and port in the datagram. Your firewall mileage may vary.</p>
         *
         * @param evt the shared event
         */
        public abstract void udpDataReceived(NioServer.Event evt);

        /**
         * <p>Fired when a TCP channel is ready to be written to.
         * The preferred way to write is to leave data in the output buffer
         * ({@link NioServer.Event#getOutputBuffer()})
         * attached to the event. The server will take care of sending
         * it even if it can't all be sent at once (perhaps a slow
         * network connection).</p>
         *
         * <p>Here is an example of how to write to the channel:</p>
         *
         * <pre>
         *   public void tcpReadyToWrite(NioServer.Event evt) {
         *       ByteBuffer buff = evt.getOutputBuffer();       // Reuse it since it's already allocated
         *       buff.clear();                                  // Prepare outBuff for writing
         *       buff.putLong( System.currentTimeMillis() );    // Store data
         *       buff.flip();                                   // Put outBuff in "read me from here" mode
         *   }</pre>
         *
         * <p>You can also just retrieve the accKey's channel, cast it to
         * a <code>SocketChannel</code> and write to it that way, but
         * you risk stalling the whole server if you're writing large
         * amounts of data over a slow connection. Plus if there is
         * data leftover from an earlier write via the output buffer,
         * then you risk writing your data out of sequence.</p>
         *
         * <p>Be aware of how large the output buffer is. You can change the
         * output buffer size that the server uses with the 
         * {@link NioServer#setOutputBufferSize(int)}
         * method, but that will not take effect until the server has finished processing
         * the current set of selected SelectionKeys.</p>
         *
         *
         * @param evt the shared event
         */
        public abstract void tcpReadyToWrite(NioServer.Event evt);

        /**
         * Called when a TCP connection is closed.
         * @param evt the shared event
         */
        public abstract void connectionClosed(NioServer.Event evt);

        /**
         * Called when a channel is bound.
         * @param evt the event
         */
        public abstract void newBinding(NioServer.BindingEvent evt);

    } // end inner static class Listener

    /* ******** ******** */
    /* ******** ******** */
    /* ******** S T A T I C I N N E R C L A S S A D A P T E R ******** */
    /* ******** ******** */
    /* ******** ******** */

    /**
     * A helper class that implements all methods of the {@link NioServer.Listener} interface with empty methods.
     */
    public static class Adapter implements NioServer.Listener {

        protected final IceSocketWrapper wrapper;

        /**
         * Constructor taking a wrapper for reference use.
         * 
         * @param wrapper the IceSocketWrapper instance which created this adapter
         */
        public Adapter(IceSocketWrapper wrapper) {
            logger.debug("Adapter for: {}", wrapper.getTransportAddress());
            this.wrapper = wrapper;
        }

        /**
         * Returns the IceSocketWrapper instance which created this adapter.
         * 
         * @return wrapper
         */
        public IceSocketWrapper getWrapper() {
            return wrapper;
        }

        /**
         * Empty method.
         * @see Listener
         * @param evt the shared event
         */
        public void tcpDataReceived(NioServer.Event evt) {
        }

        /**
         * Empty method.
         * @see Listener
         * @param evt the shared event
         */
        public void udpDataReceived(NioServer.Event evt) {
        }

        /**
         * Empty method.
         * @see Listener
         * @param evt the shared event
         */
        public void newConnectionReceived(NioServer.Event evt) {
        }

        /**
         * Empty method.
         * @see Listener
         * @param evt the shared event
         */
        public void connectionClosed(NioServer.Event evt) {
        }

        /**
         * Empty method.
         * @see Listener
         * @param evt the shared event
         */
        public void tcpReadyToWrite(NioServer.Event evt) {
        }

        /**
         * Empty method.
         * @see Listener
         * @param evt the event
         */
        public void newBinding(BindingEvent evt) {
        }

    } // end static inner class Adapter

    /* ******** ******** */
    /* ******** ******** */
    /* ******** S T A T I C I N N E R C L A S S E V E N T ******** */
    /* ******** ******** */
    /* ******** ******** */

    public static class BindingEvent extends java.util.EventObject {

        private final static long serialVersionUID = 1;

        private final NioServer server;

        public BindingEvent(NioServer server, SelectableChannel src) {
            super(src);
            this.server = server;
        }

        public Object getSource() {
            return source;
        }

        /**
         * Returns the server to which the binding completed, a {@link NioServer}.
         * 
         * @return the server
         */
        public NioServer getNioServer() {
            return server;
        }

    }

    /**
     * An event representing activity by a {@link NioServer}.
     */
    public static class Event extends java.util.EventObject {

        private final static long serialVersionUID = 1;

        /**
         * The accKey associated with this (reusable) event.
         * Use setKey(..) to change the accKey between firings.
         */
        private SelectionKey key;

        /**
         * The outBuff that holds the data from the client, for some events.
         */
        private ByteBuffer inBuff;

        /**
         * The outBuff that holds the data to send to the client, for some events.
         */
        private ByteBuffer outBuff;

        /**
         * The source address for incoming UDP datagrams.
         * The {@link #getRemoteSocketAddress} method will return this value if data is from UDP.
         */
        private SocketAddress remoteUdp;

        /**
         * Creates a Event based on the given {@link NioServer}.
         * @param src the source of the event
         */
        public Event(NioServer src) {
            super(src);
        }

        /**
         * Returns the source of the event, a {@link NioServer}.
         * Shorthand for <tt>(NioServer)getSource()</tt>.
         * @return the server
         */
        public NioServer getNioServer() {
            return (NioServer) getSource();
        }

        /**
         * Shorthand for <tt>getNioServer().getState()</tt>.
         * @return the state of the server
         * @see NioServer.State
         */
        public NioServer.State getState() {
            return getNioServer().getState();
        }

        /**
         * Returns the SelectionKey associated with this event.
         *
         * @return the SelectionKey
         */
        public SelectionKey getKey() {
            return this.key;
        }

        /**
         * Resets an event between firings by updating the parameters
         * that change.
         * @param key The SelectionKey for the event
         * @param remoteUdp the remote UDP source or null for TCP
         */
        protected void reset(SelectionKey key, ByteBuffer inBuff, ByteBuffer outBuff, SocketAddress remoteUdp) {
            this.key = key;
            this.inBuff = inBuff;
            this.outBuff = outBuff;
            this.remoteUdp = remoteUdp;
        }

        /**
         * <p>Returns the {@link java.nio.ByteBuffer} that contains
         * the incoming data for this connection. Read from it as much as
         * you can. Any data that remains on or after the value
         * of <code>position()</code> will be saved for the next
         * time an event is fired. In this way, you can defer
         * processing incomplete data until everything arrives.
         * This applies to the
         * {@link NioServer.Listener#tcpDataReceived(NioServer.Event)}
         * event.</p>
         *
         * <p>Example: You are receiving lines of text. The ByteBuffer
         * returned here contains one and a half lines of text.
         * When you realize this, you process the first line as you
         * like, but you leave this outBuff's position at the beginning
         * of the second line. In this way, The beginning of the second
         * line will be the start of the outBuff the next time around.</p>
         * @return outBuff with the data
         */
        public ByteBuffer getInputBuffer() {
            return this.inBuff;
        }

        /**
         * <p>Returns the {@link java.nio.ByteBuffer} in which you leave
         * data to be written to the client.
         * This applies to the
         * {@link NioServer.Listener#newConnectionReceived(NioServer.Event)},
         * {@link NioServer.Listener#tcpDataReceived(NioServer.Event)}, and
         * {@link NioServer.Listener#tcpReadyToWrite(NioServer.Event)}
         * events.</p>
         *
         * @return outBuff with the data
         */
        public ByteBuffer getOutputBuffer() {
            return this.outBuff;
        }

        /**
         * <p>Returns the local address/port to which this connection
         * is bound. That is, if you are listening on port 80, then
         * this might return something like an InetSocketAddress
         * (probably) that indicated /127.0.0.1:80.</p>
         * <p>This is
         * essentially a convenience method for returning the same-name
         * methods from the accKey's channel after checking the type
         * of channel (SocketChannel or DatagramChannel).</p>
         *
         * @return local address that server is bound to for this connection
         */
        public SocketAddress getLocalSocketAddress() {
            SocketAddress addr = null;
            if (this.key != null) {
                SelectableChannel sc = this.key.channel();
                if (sc instanceof SocketChannel) {
                    addr = ((SocketChannel) sc).socket().getLocalSocketAddress();
                } else if (sc instanceof DatagramChannel) {
                    addr = ((DatagramChannel) sc).socket().getLocalSocketAddress();
                }
            }
            return addr;
        }

        /**
         * <p>Returns the address of the endpoint this socket is connected to, or null if it is unconnected. </p>
         * <p>This is essentially a convenience method for returning the same-name methods from the accKey's channel
         * after checking the type of channel (SocketChannel or DatagramChannel).</p>
         *
         * @return remote address from which connection came
         */
        public SocketAddress getRemoteSocketAddress() {
            SocketAddress addr = null;
            if (this.key != null) {
                SelectableChannel sc = this.key.channel();
                if (sc instanceof SocketChannel) {
                    addr = ((SocketChannel) sc).socket().getRemoteSocketAddress();
                } else if (sc instanceof DatagramChannel) {
                    addr = this.remoteUdp;
                }
            }
            return addr;
        }

        /**
         * Convenience method for checking <code>getKey().channel() instanceof SocketChannel</code>.
         * @return true if a TCP connection
         */
        public boolean isTcp() {
            return this.key == null ? false : this.key.channel() instanceof SocketChannel;
        }

        /**
         * Convenience method for checking <code>getKey().channel() instanceof DatagramChannel</code>.
         * @return true if a UDP connection
         */
        public boolean isUdp() {
            return this.key == null ? false : this.key.channel() instanceof DatagramChannel;
        }

        /**
         * Convenience method for turning on and off writable notifications.
         * Equivalent to <code>evt.getNioServer().setNotifyOnWritable(evt.getKey(), notify);</code>.
         * @param notify whether or not to provide notifications.
         */
        public void setNotifyOnTcpWritable(boolean notify) {
            this.getNioServer().setNotifyOnWritable(this.key, notify);
        }

        /**
         * Convenience method for indicating that you would like the connection closed after the last byte in the output buffer
         * is written. Equivalent to <code>evt.getNioServer().closeAfterWriting(evt.getKey());</code>.
         */
        public void closeAfterWriting() {
            this.getNioServer().closeAfterWriting(this.key);
        }

        /**
         * Closes the underlying channel. Convenience method for <code>evt.getKey().channel().close()</code>.
         */
        public void close() throws IOException {
            this.key.channel().close();
        }

    } // end static inner class Event

} // end class NioServer
