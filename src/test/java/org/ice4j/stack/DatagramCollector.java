/* See LICENSE.md for license information */
package org.ice4j.stack;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DatagramCollector implements Runnable {

    private static final Logger logger = LoggerFactory.getLogger(DatagramCollector.class);

    Boolean lock = Boolean.TRUE;

    DatagramPacket receivedPacket;

    DatagramSocket sock;

    boolean packetReceived;

    public void run() {
        logger.debug("Listening on: {}:{}", sock.getLocalAddress(), sock.getLocalPort());
        try {
            receivedPacket = new DatagramPacket(new byte[4096], 4096);
            sock.receive(receivedPacket);
            synchronized (lock) {
                packetReceived = true;
                lock.notify();
            }
        } catch (IOException e) {
            logger.warn("Exception on receive", e);
            receivedPacket = null;
        }
    }

    public void startListening(DatagramSocket sock) {
        this.sock = sock;
        logger.debug("Bound: {} connected: {}", sock.isBound(), sock.isConnected());
        new Thread(this).start();
    }

    public void waitForPacket() {
        logger.debug("waitForPacket: {}:{}", sock.getLocalAddress(), sock.getLocalPort());
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
