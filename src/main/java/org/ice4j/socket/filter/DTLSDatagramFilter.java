/* See LICENSE.md for license information */
package org.ice4j.socket.filter;

import java.net.*;

/**
 * A {@code DatagramPacketFilter} which accepts DTLS packets only.
 *
 * @author Boris Grozev
 */
public class DTLSDatagramFilter implements DatagramPacketFilter {

    /**
     * Determines whether {@code p} looks like a DTLS packet.
     *
     * @param p the {@code DatagramPacket} to check.
     * @return {@code true} if {@code p} looks like a DTLS packet; otherwise {@code false}.
     */
    public static boolean isDTLS(DatagramPacket p) {
        int len = p.getLength();
        if (len > 0) {
            byte[] data = p.getData();
            int off = p.getOffset();
            int fb = data[off] & 0xff;
            return 19 < fb && fb < 64;
        }
        return false;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean accept(DatagramPacket p) {
        return isDTLS(p);
    }
}
