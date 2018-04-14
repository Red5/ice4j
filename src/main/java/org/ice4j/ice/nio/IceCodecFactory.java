package org.ice4j.ice.nio;

import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.ProtocolCodecFactory;
import org.apache.mina.filter.codec.ProtocolDecoder;
import org.apache.mina.filter.codec.ProtocolEncoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Codec Factory used for creating ice filter.
 * 
 * @author Paul Gregoire
 */
public class IceCodecFactory implements ProtocolCodecFactory {

    private static final Logger logger = LoggerFactory.getLogger(IceCodecFactory.class);

    private final ProtocolEncoder encoder = new IceEncoder();

    private final ProtocolDecoder decoder = new IceDecoder();

    @Override
    public ProtocolDecoder getDecoder(IoSession session) throws Exception {
        logger.trace("getDecoder: {}", session.getId());
        return decoder;
    }

    @Override
    public ProtocolEncoder getEncoder(IoSession session) throws Exception {
        logger.trace("getEncoder: {}", session.getId());
        return encoder;
    }

}
