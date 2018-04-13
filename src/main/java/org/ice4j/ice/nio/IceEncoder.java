package org.ice4j.ice.nio;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.ProtocolEncoderAdapter;
import org.apache.mina.filter.codec.ProtocolEncoderOutput;
import org.ice4j.stack.RawMessage;

/**
 * This class handles the socket encoding.
 * 
 * 
 * @author Paul Gregoire
 */
public class IceEncoder extends ProtocolEncoderAdapter {

    //private static final Logger logger = LoggerFactory.getLogger(IceEncoder.class);

    @Override
    public void encode(IoSession session, Object message, ProtocolEncoderOutput out) throws Exception {
        if (message instanceof RawMessage) {
            RawMessage packet = (RawMessage) message;
            session.write(IoBuffer.wrap(packet.getBytes()), packet.getRemoteAddress());
        } else {
            throw new Exception("Message not RawMessage type");
        }
    }

}
