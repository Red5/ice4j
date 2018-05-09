/* See LICENSE.md for license information */
package org.ice4j.stack;

import java.io.Closeable;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.ByteBuffer;

import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DatagramCollector implements Runnable {

    private static final Logger logger = LoggerFactory.getLogger(DatagramCollector.class);

    Boolean lock = Boolean.TRUE;

    DatagramPacket receivedPacket;

    Object sock;

    boolean packetReceived;

    TransportAddress transportAddr;

    ServerSocket serverSocket;

    Thread ioThread;

    public void startListening(TransportAddress transportAddr) throws Exception {
        this.transportAddr = transportAddr;
        // allow re-use
        if (ioThread != null) {
            ioThread.interrupt();
            ioThread = null;
        }
        ioThread = new Thread(this);
        ioThread.start();
    }

    public void stopListening() {
        if (ioThread != null) {
            ioThread.interrupt();
            ioThread = null;
        }
        try {
            ((Closeable) sock).close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (serverSocket != null) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        sock = null;
    }

    public void run() {
        if (sock == null) {
            try {
                if (transportAddr.getTransport() == Transport.UDP) {
                    InetSocketAddress dummyServerAddress = new InetSocketAddress("127.0.0.1", transportAddr.getPort());
                    sock = new DatagramSocket(dummyServerAddress);
                    ((DatagramSocket) sock).setReuseAddress(true);
                    logger.debug("Bound: {} connected: {}", ((DatagramSocket) sock).isBound(), ((DatagramSocket) sock).isConnected());
                } else {
                    serverSocket = new ServerSocket(transportAddr.getPort(), 16, transportAddr.getAddress());
                    serverSocket.setReuseAddress(true);
                    sock = serverSocket.accept();
                    logger.debug("Bound: {} connected: {}", ((Socket) sock).isBound(), ((Socket) sock).isConnected());
                }
            } catch (Throwable t) {
                t.printStackTrace();
            }
        }
        if (sock instanceof DatagramSocket) {
            logger.debug("Listening on: {}:{}", ((DatagramSocket) sock).getLocalAddress(), ((DatagramSocket) sock).getLocalPort());
        } else if (sock instanceof Socket) {
            logger.debug("Listening on: {}:{}", ((Socket) sock).getLocalAddress(), ((Socket) sock).getLocalPort());
        } else {
            logger.error("Socket was null");
            return;
        }
        byte[] buf = new byte[4096];
        try {
            receivedPacket = new DatagramPacket(buf, 4096);
            if (sock instanceof DatagramSocket) {
                ((DatagramSocket) sock).receive(receivedPacket);
            } else {
                ByteBuffer dst = ByteBuffer.wrap(buf);
                if (((Socket) sock).getChannel().read(dst) >= 2) {
                    // flip to read
                    dst.flip();
                    // read the length
                    int frameLength = ((dst.get() & 0xFF) << 8) | (dst.get() & 0xFF);
                    logger.debug("Frame length: {}", frameLength);
                    if (frameLength > 0) {
                        byte[] frame = new byte[frameLength];
                        dst.get(frame);
                        receivedPacket.setData(frame, 0, frameLength);
                        receivedPacket.setSocketAddress(((Socket) sock).getRemoteSocketAddress());
                    }
                    dst.clear();
                }
            }
            synchronized (lock) {
                packetReceived = true;
                lock.notify();
            }
        } catch (IOException e) {
            logger.warn("Exception on receive", e);
            receivedPacket = null;
        }
    }

    public void waitForPacket() {
        if (sock instanceof DatagramSocket) {
            logger.debug("waitForPacket: {}:{}", ((DatagramSocket) sock).getLocalAddress(), ((DatagramSocket) sock).getLocalPort());
        } else {
            logger.debug("waitForPacket: {}:{}", ((Socket) sock).getLocalAddress(), ((Socket) sock).getLocalPort());
        }
        synchronized (lock) {
            if (packetReceived) {
                return;
            }
            try {
                lock.wait(50);
            } catch (InterruptedException e) {
                logger.warn("Exception on wait", e);
            }
        }
    }

    public DatagramPacket collectPacket() {
        //recycle
        DatagramPacket returnValue = receivedPacket;
        receivedPacket = null;
        sock = null;
        packetReceived = false;
        //return
        return returnValue;
    }

    public void send(byte[] data, SocketAddress addr) throws IOException {
        if (sock instanceof DatagramSocket) {
            ((DatagramSocket) sock).send(new DatagramPacket(data, data.length, addr));
        } else {
            ByteBuffer src = ByteBuffer.allocate(data.length + 2);
            src.put((byte) ((data.length >> 8) & 0xff));
            src.put((byte) (data.length & 0xff));
            src.put(data);
            src.flip();
            ((Socket) sock).getChannel().write(src);
        }
    }
}
