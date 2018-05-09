/* See LICENSE.md for license information */
package org.ice4j.stack;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
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

    ServerSocket serverSocket;

    public void startListening(TransportAddress transportAddr) throws Exception {
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
        new Thread(this).start();
    }

    public void run() {
        if (sock instanceof DatagramSocket) {
            logger.debug("Listening on: {}:{}", ((DatagramSocket) sock).getLocalAddress(), ((DatagramSocket) sock).getLocalPort());
        } else {
            logger.debug("Listening on: {}:{}", ((Socket) sock).getLocalAddress(), ((Socket) sock).getLocalPort());
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
        if (serverSocket != null) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
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
}
