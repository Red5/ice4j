/* See LICENSE.md for license information */
package org.ice4j.socket.filter;

/**
 * Implements a DataFilter which only accepts data which represent RTCP messages according to the rules
 * described in RFC5761.
 *
 * @author Emil Ivov
 * @author Boris Grozev
 */
public class RtcpDemuxFilter implements DataFilter {
    /**
     * Determines whether a specific DatagramPacket is an RTCP.
     * DatagramPacket in a selection based on this filter.
     *
     * RTP/RTCP packets are distinguished from other packets (such as STUN,
     * DTLS or ZRTP) by the value of their first byte. See
     * <a href="http://tools.ietf.org/html/rfc5764#section-5.1.2">
     * RFC5764, Section 5.1.2</a> and
     * <a href="http://tools.ietf.org/html/rfc6189#section-5">RFC6189,
     * Section 5</a>.
     *
     * RTCP packets are distinguished from RTP packet based on the second byte
     * (either Packet Type (RTCP) or M-bit and Payload Type (RTP). See
     * <a href="http://tools.ietf.org/html/rfc5761#section-4">RFC5761, Section
     * 4</a>
     *
     * We assume that RTCP packets have a packet type in [200, 211]. This means
     * that RTP packets with Payload Types in [72, 83] (which should not
     * appear, because these PTs are reserved or unassigned by IANA, see
     * <a href="http://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml">
     * IANA RTP Parameters</a>) with the M-bit set will be misidentified as
     * RTCP packets.
     * 
     * Also, any RTCP packets with Packet Types not in [200, 211] will be misidentified as RTP packets.
     *
     * @param p the DatagramPacket whose protocol we'd like to determine
     * @return true if bytes are RTCP, otherwise false
     */
    public boolean accept(byte[] buf) {
        // minimum RTCP message length
        if (buf.length >= 4) {
            int off = 0;
            //RTP/RTCP version field
            if (((buf[off] & 0xc0) >> 6) == 2) {
                int pt = buf[off + 1] & 0xff;
                return (200 <= pt && pt <= 211);
            }
        }
        return false;
    }

}
