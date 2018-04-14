package org.ice4j.ice.nio;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.CumulativeProtocolDecoder;
import org.apache.mina.filter.codec.ProtocolDecoderOutput;
import org.ice4j.StunException;
import org.ice4j.StunMessageEvent;
import org.ice4j.attribute.Attribute;
import org.ice4j.attribute.UsernameAttribute;
import org.ice4j.ice.nio.IceTransport.Ice;
import org.ice4j.message.Message;
import org.ice4j.socket.IceSocketWrapper;
import org.ice4j.stack.RawMessage;
import org.ice4j.stack.StunStack;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class handles the socket decoding.
 * 
 * @author Paul Gregoire
 */
public class IceDecoder extends CumulativeProtocolDecoder {

    private static final Logger logger = LoggerFactory.getLogger(IceDecoder.class);

    /**
     * Keeps track of the decoding state of a data packet.
     */
    private final class DecoderState {

        // payload starting with standard mtu length
        ByteArrayOutputStream payload = new ByteArrayOutputStream(1500);

        @Override
        public String toString() {
            return "DecoderState [payload=" + payload.size() + "]";
        }
    }

    @Override
    protected boolean doDecode(IoSession session, IoBuffer in, ProtocolDecoderOutput out) throws Exception {
        IoBuffer resultBuffer;
        IceSocketWrapper iceSocket = (IceSocketWrapper) session.getAttribute(Ice.CONNECTION);
        if (iceSocket != null) {
            logger.debug("Decode start pos: {}", in.position());
            // grab decoding state
            DecoderState decoderState = (DecoderState) session.getAttribute(Ice.DECODER_STATE_KEY);
            if (decoderState == null) {
                decoderState = new DecoderState();
                session.setAttribute(Ice.DECODER_STATE_KEY, decoderState);
            }
            // there is incoming data from the socket, decode it
            RawMessage message = decodeIncommingData(in, session, decoderState);
            if (logger.isTraceEnabled()) {
                logger.trace("State: {} message: {}", decoderState, message);
            }
            if (message != null) {
                byte[] buf = message.getBytes();
                // if its a stun message, process it
                if (isStun(buf)) {
                    StunStack stunStack = (StunStack) session.getAttribute(Ice.STUN_STACK);
                    try {
                        Message stunMessage = Message.decode(message.getBytes(), 0, message.getMessageLength());
                        logger.trace("Dispatching a StunMessageEvent");
                        StunMessageEvent stunMessageEvent = new StunMessageEvent(stunStack, message, stunMessage);
                        stunStack.handleMessageEvent(stunMessageEvent);
                    } catch (StunException ex) {
                        logger.warn("Failed to decode a stun message!", ex);
                    }
                } else if (isDtls(buf)) {
                    iceSocket.getRawMessageQueue().offer(message);
                } else {
                    // write the message
                    out.write(message);
                }
            } else {
                // there was not enough data in the buffer to parse
                return false;
            }
        } else {
            // no connection, pass through
            resultBuffer = IoBuffer.wrap(in.array(), 0, in.limit());
            in.position(in.limit());
            out.write(resultBuffer);
        }
        return true;
    }

    /**
     * Decode the incoming buffer and return a RawMessage when all its content has arrived.
     * 
     * @param in
     * @param session
     * @param decoderState
     * @return RawMessage
     */
    public RawMessage decodeIncommingData(IoBuffer in, IoSession session, DecoderState decoderState) {
        logger.trace("Decoding: {}", in);
        RawMessage message = null;
        // get the incoming bytes
        byte[] buf = new byte[in.remaining()];
        in.get(buf);
        
/*
 * TCP has a 2b prefix containing its size
     * Receives an RFC4571-formatted frame from channel into p, and sets p's port and address to the remote port
     * and address of this Socket.
    public void receive(DatagramPacket p) throws IOException {
        SocketChannel socketChannel = (SocketChannel) channel;
        while (frameLengthByteBuffer.hasRemaining()) {
            int read = socketChannel.read(frameLengthByteBuffer);
            if (read == -1) {
                throw new SocketException("Failed to receive data from socket.");
            }
        }
        frameLengthByteBuffer.flip();
        int b0 = frameLengthByteBuffer.get();
        int b1 = frameLengthByteBuffer.get();
        int frameLength = ((b0 & 0xFF) << 8) | (b1 & 0xFF);
        frameLengthByteBuffer.flip();
        byte[] data = p.getData();
        if (data == null || data.length < frameLength) {
            data = new byte[frameLength];
        }
        ByteBuffer byteBuffer = ByteBuffer.wrap(data, 0, frameLength);
        while (byteBuffer.hasRemaining()) {
            int read = socketChannel.read(byteBuffer);
            if (read == -1) {
                throw new SocketException("Failed to receive data from socket.");
            }
        }
        p.setAddress(socketChannel.socket().getInetAddress());
        p.setData(data, 0, frameLength);
        p.setPort(socketChannel.socket().getPort());
    }
 */
        
        // does it look like we have a whole message or an ending fragment?
        boolean wholeMessage = (buf.length < 1500);
        // if there are less than 1500 bytes and decoderState is empty, we can be assured its a whole message
        if (wholeMessage && decoderState.payload.size() == 0) {
            // create a message
            message = RawMessage.build(buf, session.getRemoteAddress(), session.getLocalAddress());
        } else {
            // add them to the payload
            try {
                decoderState.payload.write(buf);
            } catch (IOException e) {
            }
            if (wholeMessage) {
                // create a message
                message = RawMessage.build(decoderState.payload.toByteArray(), session.getRemoteAddress(), session.getLocalAddress());
                // reset decoder state payload so it may be re-used
                decoderState.payload.reset();
            }
        }
        return message;
    }

    /**
     * Determines whether data in a byte array represents a STUN message.
     *
     * @param buf the bytes to check
     * @return true if the bytes look like STUN, otherwise false
     */
    public boolean isStun(byte[] buf) {
        // If this is a STUN packet
        boolean isStunPacket = false;
        // All STUN messages MUST start with a 20-byte header followed by zero or more Attributes
        if (buf.length >= 20) {
            // If the MAGIC COOKIE is present this is a STUN packet (RFC5389 compliant).
            if (buf[4] == Message.MAGIC_COOKIE[0] && buf[5] == Message.MAGIC_COOKIE[1] && buf[6] == Message.MAGIC_COOKIE[2] && buf[7] == Message.MAGIC_COOKIE[3]) {
                isStunPacket = true;
            } else {
                // Else, this packet may be a STUN packet (RFC3489 compliant). To determine this, we must continue the checks.
                // The most significant 2 bits of every STUN message MUST be zeroes.  This can be used to differentiate STUN packets from
                // other protocols when STUN is multiplexed with other protocols on the same port.
                byte b0 = buf[0];
                boolean areFirstTwoBitsValid = ((b0 & 0xC0) == 0);
                // Checks if the length of the data correspond to the length field of the STUN header. The message length field of the
                // STUN header does not include the 20-byte of the STUN header.
                int total_header_length = ((((int) buf[2]) & 0xff) << 8) + (((int) buf[3]) & 0xff) + 20;
                boolean isHeaderLengthValid = (buf.length == total_header_length);
                isStunPacket = areFirstTwoBitsValid && isHeaderLengthValid;
            }
        }
        if (isStunPacket) {
            byte b0 = buf[0];
            byte b1 = buf[1];
            // we only accept the method Binding and the reserved methods 0x000 and 0x002/SharedSecret
            int method = (b0 & 0xFE) | (b1 & 0xEF);
            switch (method) {
                case Message.STUN_METHOD_BINDING:
                case Message.STUN_REQUEST:
                case Message.SHARED_SECRET_REQUEST:
                    return true;
            }
        }
        return false;
    }

    /**
     * Determines whether data in a byte array represents a DTLS message.
     *
     * @param buf the bytes to check
     * @return true if the bytes look like DTLS, otherwise false
     */
    public boolean isDtls(byte[] buf) {
        if (buf.length > 0) {
            int fb = buf[0] & 0xff;
            return 19 < fb && fb < 64;
        }
        return false;
    }

    /**
     * Tries to parse the bytes in buf at offset off (and length len) as a STUN Binding Request message. If successful,
     * looks for a USERNAME attribute and returns the local username fragment part (see RFC5245 Section 7.1.2.3).
     * In case of any failure returns null.
     *
     * @param buf the bytes.
     * @param off the offset.
     * @param len the length.
     * @return the local ufrag from the USERNAME attribute of the STUN message contained in buf, or null.
     */
    static String getUfrag(byte[] buf, int off, int len) {
        // RFC5389, Section 6: All STUN messages MUST start with a 20-byte header followed by zero or more Attributes.
        if (buf == null || buf.length < off + len || len < 20) {
            return null;
        }
        // RFC5389, Section 6: The magic cookie field MUST contain the fixed value 0x2112A442 in network byte order.
        if (((buf[off + 4] & 0xFF) == 0x21 && (buf[off + 5] & 0xFF) == 0x12 && (buf[off + 6] & 0xFF) == 0xA4 && (buf[off + 7] & 0xFF) == 0x42)) {
            try {
                Message stunMessage = Message.decode(buf, off, len);
                if (stunMessage.getMessageType() == Message.BINDING_REQUEST) {
                    UsernameAttribute usernameAttribute = (UsernameAttribute) stunMessage.getAttribute(Attribute.Type.USERNAME);
                    if (logger.isTraceEnabled()) {
                        logger.trace("usernameAttribute: {}", usernameAttribute);
                    }
                    if (usernameAttribute != null) {
                        String usernameString = new String(usernameAttribute.getUsername());
                        return usernameString.split(":")[0];
                    }
                }
            } catch (Exception e) {
                // Catch everything. We are going to log, and then drop the packet anyway.
                if (logger.isDebugEnabled()) {
                    logger.warn("Failed to extract local ufrag", e);
                }
            }
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug("Not a STUN packet, magic cookie not found.");
            }
        }
        return null;
    }

}
