/* See LICENSE.md for license information */
package org.ice4j.socket.filter;

/**
 * A {@code DataFilter} which accepts DTLS packets only.
 *
 * @author Boris Grozev
 */
public class DTLSDataFilter implements DataFilter {

    /**
     * Determines whether a byte array looks like a DTLS data.
     *
     * @param buf the bytes to check
     * @return true if the bytes look like DTLS, otherwise false
     */
    @Override
    public boolean accept(byte[] buf) {
        if (buf.length > 0) {
            int fb = buf[0] & 0xff;
            return 19 < fb && fb < 64;
        }
        return false;
    }
}
