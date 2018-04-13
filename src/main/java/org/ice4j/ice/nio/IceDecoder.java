package org.ice4j.ice.nio;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.future.IoFuture;
import org.apache.mina.core.future.IoFutureListener;
import org.apache.mina.core.future.WriteFuture;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.CumulativeProtocolDecoder;
import org.apache.mina.filter.codec.ProtocolDecoderOutput;
import org.ice4j.StunException;
import org.ice4j.StunMessageEvent;
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

    private enum Key {
        DECODER_STATE_KEY, DECODED_MESSAGE_KEY, DECODED_MESSAGE_TYPE_KEY, DECODED_MESSAGE_FRAGMENTS_KEY;
    }

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
        IceSocketWrapper conn = (IceSocketWrapper) session.getAttribute(IceTransport.Ice.CONNECTION);
        if (conn != null) {
            logger.debug("Decode start pos: {}", in.position());
            // grab decoding state
            DecoderState decoderState = (DecoderState) session.getAttribute(Key.DECODER_STATE_KEY);
            if (decoderState == null) {
                decoderState = new DecoderState();
                session.setAttribute(Key.DECODER_STATE_KEY, decoderState);
            }
            // there is incoming data from the socket, decode it
            decodeIncommingData(in, session);
            // this will be null until all the fragments are collected
            RawMessage message = (RawMessage) session.getAttribute(Key.DECODED_MESSAGE_KEY);
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
                    conn.getRawMessageQueue().offer(message);
                } else {
                    // write the message
                    out.write(message);
                }
                // remove decoded message
                session.removeAttribute(Key.DECODED_MESSAGE_KEY);
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
     * Decode the in buffer according to the Section 5.2. RFC 6455. If there are multiple websocket dataframes in the buffer, this will parse all and return one complete decoded buffer.
     * 
     * <pre>
     * 	  0                   1                   2                   3
     * 	  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * 	 +-+-+-+-+-------+-+-------------+-------------------------------+
     * 	 |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
     * 	 |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
     * 	 |N|V|V|V|       |S|             |   (if payload len==126/127)   |
     * 	 | |1|2|3|       |K|             |                               |
     * 	 +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
     * 	 |     Extended payload length continued, if payload len == 127  |
     * 	 + - - - - - - - - - - - - - - - +-------------------------------+
     * 	 |                               |Masking-key, if MASK set to 1  |
     * 	 +-------------------------------+-------------------------------+
     * 	 | Masking-key (continued)       |          Payload Data         |
     * 	 +-------------------------------- - - - - - - - - - - - - - - - +
     * 	 :                     Payload Data continued ...                :
     * 	 + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
     * 	 |                     Payload Data continued ...                |
     * 	 +---------------------------------------------------------------+
     * </pre>
     * 
     * @param in
     * @param session
     */
    public static void decodeIncommingData(IoBuffer in, IoSession session) {
        logger.trace("Decoding: {}", in);
        // get decoder state
        DecoderState decoderState = (DecoderState) session.getAttribute(DECODER_STATE_KEY);
        if (decoderState.fin == Byte.MIN_VALUE) {
            byte frameInfo = in.get();
            // get FIN (1 bit)
            //logger.debug("frameInfo: {}", Integer.toBinaryString((frameInfo & 0xFF) + 256));
            decoderState.fin = (byte) ((frameInfo >>> 7) & 1);
            logger.trace("FIN: {}", decoderState.fin);
            // the next 3 bits are for RSV1-3 (not used here at the moment)			
            // get the opcode (4 bits)
            decoderState.opCode = (byte) (frameInfo & 0x0f);
            logger.trace("Opcode: {}", decoderState.opCode);
            // opcodes 3-7 and b-f are reserved for non-control frames
        }
        if (decoderState.mask == Byte.MIN_VALUE) {
            byte frameInfo2 = in.get();
            // get mask bit (1 bit)
            decoderState.mask = (byte) ((frameInfo2 >>> 7) & 1);
            logger.trace("Mask: {}", decoderState.mask);
            // get payload length (7, 7+16, 7+64 bits)
            decoderState.frameLen = (frameInfo2 & (byte) 0x7F);
            logger.trace("Payload length: {}", decoderState.frameLen);
            if (decoderState.frameLen == 126) {
                decoderState.frameLen = in.getUnsignedShort();
                logger.trace("Payload length updated: {}", decoderState.frameLen);
            } else if (decoderState.frameLen == 127) {
                long extendedLen = in.getLong();
                if (extendedLen >= Integer.MAX_VALUE) {
                    logger.error("Data frame is too large for this implementation. Length: {}", extendedLen);
                } else {
                    decoderState.frameLen = (int) extendedLen;
                }
                logger.trace("Payload length updated: {}", decoderState.frameLen);
            }
        }
        // ensure enough bytes left to fill payload, if masked add 4 additional bytes
        if (decoderState.frameLen + (decoderState.mask == 1 ? 4 : 0) > in.remaining()) {
            logger.info("Not enough data available to decode, socket may be closed/closing");
        } else {
            // if the data is masked (xor'd)
            if (decoderState.mask == 1) {
                // get the mask key
                byte maskKey[] = new byte[4];
                for (int i = 0; i < 4; i++) {
                    maskKey[i] = in.get();
                }
                /*  now un-mask frameLen bytes as per Section 5.3 RFC 6455
                Octet i of the transformed data ("transformed-octet-i") is the XOR of
                octet i of the original data ("original-octet-i") with octet at index
                i modulo 4 of the masking key ("masking-key-octet-j"):
                j                   = i MOD 4
                transformed-octet-i = original-octet-i XOR masking-key-octet-j
                */
                decoderState.payload = new byte[decoderState.frameLen];
                for (int i = 0; i < decoderState.frameLen; i++) {
                    byte maskedByte = in.get();
                    decoderState.payload[i] = (byte) (maskedByte ^ maskKey[i % 4]);
                }
            } else {
                decoderState.payload = new byte[decoderState.frameLen];
                in.get(decoderState.payload);
            }
            // if FIN == 0 we have fragments
            if (decoderState.fin == 0) {
                // store the fragment and continue
                IoBuffer fragments = (IoBuffer) session.getAttribute(DECODED_MESSAGE_FRAGMENTS_KEY);
                if (fragments == null) {
                    fragments = IoBuffer.allocate(decoderState.frameLen);
                    fragments.setAutoExpand(true);
                    session.setAttribute(DECODED_MESSAGE_FRAGMENTS_KEY, fragments);
                    // store message type since following type may be a continuation
                    MessageType messageType = MessageType.CLOSE;
                    switch (decoderState.opCode) {
                        case 0: // continuation
                            messageType = MessageType.CONTINUATION;
                            break;
                        case 1: // text
                            messageType = MessageType.TEXT;
                            break;
                        case 2: // binary
                            messageType = MessageType.BINARY;
                            break;
                        case 9: // ping
                            messageType = MessageType.PING;
                            break;
                        case 0xa: // pong
                            messageType = MessageType.PONG;
                            break;
                    }
                    session.setAttribute(DECODED_MESSAGE_TYPE_KEY, messageType);
                }
                fragments.put(decoderState.payload);
                // remove decoder state
                session.removeAttribute(DECODER_STATE_KEY);
            } else {
                // create a message
                WSMessage message = new WSMessage();
                // check for previously set type from the first fragment (if we have fragments)
                MessageType messageType = (MessageType) session.getAttribute(DECODED_MESSAGE_TYPE_KEY);
                if (messageType == null) {
                    switch (decoderState.opCode) {
                        case 0: // continuation
                            messageType = MessageType.CONTINUATION;
                            break;
                        case 1: // text
                            messageType = MessageType.TEXT;
                            break;
                        case 2: // binary
                            messageType = MessageType.BINARY;
                            break;
                        case 9: // ping
                            messageType = MessageType.PING;
                            break;
                        case 0xa: // pong
                            messageType = MessageType.PONG;
                            break;
                        case 8: // close
                            messageType = MessageType.CLOSE;
                            // handler or listener should close upon receipt
                            break;
                        default:
                            // TODO throw ex?
                            logger.info("Unhandled opcode: {}", decoderState.opCode);
                    }
                }
                // set message type
                message.setMessageType(messageType);
                // check for fragments and piece them together, otherwise just send the single completed frame
                IoBuffer fragments = (IoBuffer) session.removeAttribute(DECODED_MESSAGE_FRAGMENTS_KEY);
                if (fragments != null) {
                    fragments.put(decoderState.payload);
                    fragments.flip();
                    message.setPayload(fragments);
                } else {
                    // add the payload
                    message.addPayload(decoderState.payload);
                }
                // set the message on the session
                session.setAttribute(DECODED_MESSAGE_KEY, message);
                // remove decoder state
                session.removeAttribute(DECODER_STATE_KEY);
                // remove type
                session.removeAttribute(DECODED_MESSAGE_TYPE_KEY);
            }
        }
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

}
