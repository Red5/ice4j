/* See LICENSE.md for license information */
package org.ice4j.socket.filter;

import java.net.*;

/**
 * Implements a DatagramPacketFilter which only accepts
 * DatagramPackets which represent RTCP messages according to the rules
 * described in RFC5761.
 *
 * @author Emil Ivov
 * @author Boris Grozev
 */
public class RtcpDemuxPacketFilter implements DatagramPacketFilter {
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
     * Also, any RTCP packets with Packet Types not in [200, 211] will be
     * misidentified as RTP packets.
     *
     * @param p the DatagramPacket whose protocol we'd like to
     * determine.
     * @return true if p is an RTCP and this filter accepts it
     * and false otherwise.
     */
    public static boolean isRtcpPacket(DatagramPacket p) {
        int len = p.getLength();

        if (len >= 4) //minimum RTCP message length
        {
            byte[] data = p.getData();
            int off = p.getOffset();

            if (((data[off] & 0xc0) >> 6) == 2) //RTP/RTCP version field
            {
                int pt = data[off + 1] & 0xff;

                return (200 <= pt && pt <= 211);
            }
        }
        return false;
    }

    /**
     * Returns true if this RtcpDemuxPacketFilter should
     * accept p, that is, if p looks like an RTCP packet.
     * See {@link #isRtcpPacket(java.net.DatagramPacket)}
     * @return true if p looks like an RTCP packet.
     */
    public boolean accept(DatagramPacket p) {
        return isRtcpPacket(p);
    }

}
