package org.ice4j.ice.nio;

import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.ProtocolCodecFactory;
import org.apache.mina.filter.codec.ProtocolDecoder;
import org.apache.mina.filter.codec.ProtocolEncoder;

/**
 * Codec Factory used for creating ice filter.
 * 
 * @author Paul Gregoire
 */
public class IceCodecFactory implements ProtocolCodecFactory {

    private final ProtocolEncoder encoder;

    private final ProtocolDecoder decoder;

    public IceCodecFactory() {
        encoder = new IceEncoder();
        decoder = new IceDecoder();
    }

    @Override
    public ProtocolDecoder getDecoder(IoSession session) throws Exception {
        return decoder;
    }

    @Override
    public ProtocolEncoder getEncoder(IoSession session) throws Exception {
        return encoder;
    }

}
