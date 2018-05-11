package org.ice4j.ice.nio;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.ProtocolEncoderAdapter;
import org.apache.mina.filter.codec.ProtocolEncoderOutput;
import org.ice4j.Transport;
import org.ice4j.stack.RawMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class handles the ice encoding.
 * 
 * Refs
 * https://tools.ietf.org/html/rfc4571
 * https://tools.ietf.org/html/rfc6544#section-3
 * 
 * @author Paul Gregoire
 */
public class IceEncoder extends ProtocolEncoderAdapter {

    private static final Logger logger = LoggerFactory.getLogger(IceEncoder.class);

    /*
                       +----------+
                       |          |
                       |    App   |
            +----------+----------+     +----------+----------+
            |          |          |     |          |          |
            |   STUN   |  (D)TLS  |     |   STUN   |    App   |
            +----------+----------+     +----------+----------+
            |                     |     |                     |
            |      RFC 4571       |     |      RFC 4571       |
            +---------------------+     +---------------------+
            |                     |     |                     |
            |         TCP         |     |         TCP         |
            +---------------------+     +---------------------+
            |                     |     |                     |
            |         IP          |     |         IP          |
            +---------------------+     +---------------------+

              Figure 1: ICE TCP Stack with and without (D)TLS
     */

    @Override
    public void encode(IoSession session, Object message, ProtocolEncoderOutput out) throws Exception {
        logger.trace("encode (session: {}) local: {} remote: {}\n{}", session.getId(), session.getLocalAddress(), session.getRemoteAddress(), String.valueOf(message));
        if (message instanceof RawMessage) {
            // determine the transport in-use
            Transport transport = (session.getTransportMetadata().isConnectionless() ? Transport.UDP : Transport.TCP);
            RawMessage packet = (RawMessage) message;
            IoBuffer buf = packet.toIoBuffer();
            logger.trace("Byte buffer: {}", buf);
            if (transport == Transport.UDP) {
                session.write(buf, packet.getRemoteAddress());
            } else {
                session.write(buf);
            }
        } else {
            throw new Exception("Message not RawMessage type");
        }
    }

}
