package org.ice4j.ice.nio;

import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.ProtocolEncoderAdapter;
import org.apache.mina.filter.codec.ProtocolEncoderOutput;
import org.ice4j.stack.RawMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class handles the ice encoding.
 * 
 * 
 * @author Paul Gregoire
 */
public class IceEncoder extends ProtocolEncoderAdapter {

    private static final Logger logger = LoggerFactory.getLogger(IceEncoder.class);

    @Override
    public void encode(IoSession session, Object message, ProtocolEncoderOutput out) throws Exception {
        logger.trace("encode (session: {}) local: {} remote: {}\n{}", session.getId(), session.getLocalAddress(), session.getRemoteAddress(), String.valueOf(message));
        if (message instanceof RawMessage) {
            RawMessage packet = (RawMessage) message;
            session.write(packet.toIoBuffer(), packet.getRemoteAddress());
        } else {
            throw new Exception("Message not RawMessage type");
        }
    }

}
