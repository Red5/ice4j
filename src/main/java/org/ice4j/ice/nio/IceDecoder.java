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
import org.ice4j.socket.IceSocketWrapper;
import org.ice4j.stack.RawMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class handles the socket decoding.
 * 
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
            // there is incoming data from the websocket, decode it
            decodeIncommingData(in, session);
            // this will be null until all the fragments are collected
            RawMessage message = (RawMessage) session.getAttribute(Key.DECODED_MESSAGE_KEY);
            if (logger.isTraceEnabled()) {
                logger.trace("State: {} message: {}", decoderState, message);
            }
            if (message != null) {
                // set the originating connection on the message
                message.setConnection(conn);
                // write the message
                out.write(message);
                // remove decoded message
                session.removeAttribute(Key.DECODED_MESSAGE_KEY);
            } else {
                // there was not enough data in the buffer to parse
                return false;
            }
        } else {
            // session is known to be from a native socket. So simply wrap and pass through
            resultBuffer = IoBuffer.wrap(in.array(), 0, in.limit());
            in.position(in.limit());
            out.write(resultBuffer);
        }
        return true;
    }

    /**
     * Try parsing the message as a websocket handshake request. If it is such a request, then send the corresponding handshake response (as in Section 4.2.2 RFC 6455).
     */
    @SuppressWarnings("unchecked")
    private boolean doHandShake(IoSession session, IoBuffer in) {
        if (logger.isDebugEnabled()) {
            logger.debug("Handshake: {}", in);
        }
        // incoming data
        byte[] data = null;
        // check for existing HS data
        if (session.containsAttribute(Constants.WS_HANDSHAKE)) {
            byte[] tmp = (byte[]) session.getAttribute(Constants.WS_HANDSHAKE);
            // size to hold existing and incoming
            data = new byte[tmp.length + in.remaining()];
            System.arraycopy(tmp, 0, data, 0, tmp.length);
            // get incoming bytes
            in.get(data, tmp.length, in.remaining());
        } else {
            // size for incoming bytes
            data = new byte[in.remaining()];
            // get incoming bytes
            in.get(data, 0, data.length);
        }
        // ensure the incoming data is complete (ends with crlfcrlf)
        byte[] tail = Arrays.copyOfRange(data, data.length - 4, data.length);
        if (!Arrays.equals(tail, Constants.END_OF_REQ)) {
            // accumulate the HS data
            session.setAttribute(Constants.WS_HANDSHAKE, data);
            return false;
        }
        // create the connection obj
        WebSocketConnection conn = new WebSocketConnection(session);
        // mark as secure if using ssl
        if (session.getFilterChain().contains("sslFilter")) {
            conn.setSecure(true);
        }
        try {
            Map<String, Object> headers = parseClientRequest(conn, new String(data));
            if (logger.isTraceEnabled()) {
                logger.trace("Header map: {}", headers);
            }
            if (!headers.isEmpty() && headers.containsKey(Constants.WS_HEADER_KEY)) {
                // add the headers to the connection, they may be of use to implementers
                conn.setHeaders(headers);
                // add query string parameters
                if (headers.containsKey(Constants.URI_QS_PARAMETERS)) {
                    conn.setQuerystringParameters((Map<String, Object>) headers.remove(Constants.URI_QS_PARAMETERS));
                }
                // check the version
                if (!"13".equals(headers.get(Constants.WS_HEADER_VERSION))) {
                    logger.info("Version 13 was not found in the request, communications may fail");
                }
                // get the path 
                String path = conn.getPath();
                // get the scope manager
                WebSocketScopeManager manager = (WebSocketScopeManager) session.getAttribute(Constants.MANAGER);
                if (manager == null) {
                    WebSocketPlugin plugin = (WebSocketPlugin) PluginRegistry.getPlugin("WebSocketPlugin");
                    manager = plugin.getManager(path);
                }
                // TODO add handling for extensions

                // TODO expand handling for protocols requested by the client, instead of just echoing back
                if (headers.containsKey(Constants.WS_HEADER_PROTOCOL)) {
                    boolean protocolSupported = false;
                    String protocol = (String) headers.get(Constants.WS_HEADER_PROTOCOL);
                    logger.debug("Protocol '{}' found in the request", protocol);
                    // add protocol to the connection
                    conn.setProtocol(protocol);
                    // TODO check listeners for "protocol" support
                    Set<IWebSocketDataListener> listeners = manager.getScope(path).getListeners();
                    for (IWebSocketDataListener listener : listeners) {
                        if (listener.getProtocol().equals(protocol)) {
                            //logger.debug("Scope has listener support for the {} protocol", protocol);
                            protocolSupported = true;
                            break;
                        }
                    }
                    logger.debug("Scope listener does{} support the '{}' protocol", (protocolSupported ? "" : "n't"), protocol);
                }
                // store manager in the current session
                session.setAttribute(Constants.MANAGER, manager);
                // store connection in the current session
                session.setAttribute(Constants.CONNECTION, conn);
                // handshake is finished
                conn.setConnected();
                // add connection to the manager
                manager.addConnection(conn);
                // prepare response and write it to the directly to the session
                HandshakeResponse wsResponse = buildHandshakeResponse(conn, (String) headers.get(Constants.WS_HEADER_KEY));
                session.write(wsResponse);
                // remove handshake acculator
                session.removeAttribute(Constants.WS_HANDSHAKE);
                logger.debug("Handshake complete");
                return true;
            }
            // set connection as native / direct
            conn.setType(ConnectionType.DIRECT);
        } catch (Exception e) {
            // input is not a websocket handshake request
            logger.warn("Handshake failed", e);
        }
        return false;
    }

    /**
     * Parse the client request and return a map containing the header contents. If the requested application is not enabled, return a 400 error.
     * 
     * @param conn
     * @param requestData
     * @return map of headers
     * @throws WebSocketException
     */
    private Map<String, Object> parseClientRequest(WebSocketConnection conn, String requestData) throws WebSocketException {
        String[] request = requestData.split("\r\n");
        if (logger.isTraceEnabled()) {
            logger.trace("Request: {}", Arrays.toString(request));
        }
        Map<String, Object> map = new HashMap<>();
        for (int i = 0; i < request.length; i++) {
            logger.trace("Request {}: {}", i, request[i]);
            if (request[i].startsWith("GET ") || request[i].startsWith("POST ") || request[i].startsWith("PUT ")) {
                // "GET /chat/room1?id=publisher1 HTTP/1.1"
                // split it on space
                String requestPath = request[i].split("\\s+")[1];
                // get the path data for handShake
                int start = requestPath.indexOf('/');
                int end = requestPath.length();
                int ques = requestPath.indexOf('?');
                if (ques > 0) {
                    end = ques;
                }
                logger.trace("Request path: {} to {} ques: {}", start, end, ques);
                String path = requestPath.substring(start, end).trim();
                logger.trace("Client request path: {}", path);
                conn.setPath(path);
                // check for '?' or included query string
                if (ques > 0) {
                    // parse any included query string
                    String qs = requestPath.substring(ques).trim();
                    logger.trace("Request querystring: {}", qs);
                    map.put(Constants.URI_QS_PARAMETERS, parseQuerystring(qs));
                }
                // get the manager
                WebSocketPlugin plugin = (WebSocketPlugin) PluginRegistry.getPlugin("WebSocketPlugin");
                if (plugin != null) {
                    logger.trace("Found plugin");
                    WebSocketScopeManager manager = plugin.getManager(path);
                    logger.trace("Manager was found? : {}", manager);
                    // only check that the application is enabled, not the room or sub levels
                    if (manager != null && manager.isEnabled(path)) {
                        logger.trace("Path enabled: {}", path);
                    } else {
                        // invalid scope or its application is not enabled, send disconnect message
                        HandshakeResponse errResponse = build400Response(conn);
                        WriteFuture future = conn.getSession().write(errResponse);
                        future.addListener(new IoFutureListener<IoFuture>() {
                            @Override
                            public void operationComplete(IoFuture future) {
                                // close connection
                                future.getSession().closeOnFlush();
                            }
                        });
                        throw new WebSocketException("Handshake failed, path not enabled");
                    }
                } else {
                    logger.warn("Plugin lookup failed");
                    HandshakeResponse errResponse = build400Response(conn);
                    WriteFuture future = conn.getSession().write(errResponse);
                    future.addListener(new IoFutureListener<IoFuture>() {
                        @Override
                        public void operationComplete(IoFuture future) {
                            // close connection
                            future.getSession().closeOnFlush();
                        }
                    });
                    throw new WebSocketException("Handshake failed, missing plugin");
                }
            } else if (request[i].contains(Constants.WS_HEADER_KEY)) {
                map.put(Constants.WS_HEADER_KEY, extractHeaderValue(request[i]));
            } else if (request[i].contains(Constants.WS_HEADER_VERSION)) {
                map.put(Constants.WS_HEADER_VERSION, extractHeaderValue(request[i]));
            } else if (request[i].contains(Constants.WS_HEADER_EXTENSIONS)) {
                map.put(Constants.WS_HEADER_EXTENSIONS, extractHeaderValue(request[i]));
            } else if (request[i].contains(Constants.WS_HEADER_PROTOCOL)) {
                map.put(Constants.WS_HEADER_PROTOCOL, extractHeaderValue(request[i]));
            } else if (request[i].contains(Constants.HTTP_HEADER_HOST)) {
                // get the host data
                conn.setHost(extractHeaderValue(request[i]));
            } else if (request[i].contains(Constants.HTTP_HEADER_ORIGIN)) {
                // get the origin data
                conn.setOrigin(extractHeaderValue(request[i]));
            } else if (request[i].contains(Constants.HTTP_HEADER_USERAGENT)) {
                map.put(Constants.HTTP_HEADER_USERAGENT, extractHeaderValue(request[i]));
            } else if (request[i].startsWith(Constants.WS_HEADER_GENERIC_PREFIX)) {
                map.put(getHeaderName(request[i]), extractHeaderValue(request[i]));
            }
        }
        return map;
    }

    /**
     * Returns the trimmed header name.
     * 
     * @param requestHeader
     * @return value
     */
    private String getHeaderName(String requestHeader) {
        return requestHeader.substring(0, requestHeader.indexOf(':')).trim();
    }

    /**
     * Returns the trimmed header value.
     * 
     * @param requestHeader
     * @return value
     */
    private String extractHeaderValue(String requestHeader) {
        return requestHeader.substring(requestHeader.indexOf(':') + 1).trim();
    }

    /**
     * Build a handshake response based on the given client key.
     * 
     * @param clientKey
     * @return response
     * @throws WebSocketException
     */
    private HandshakeResponse buildHandshakeResponse(WebSocketConnection conn, String clientKey) throws WebSocketException {
        byte[] accept;
        try {
            // performs the accept creation routine from RFC6455 @see <a href="http://tools.ietf.org/html/rfc6455">RFC6455</a>
            // concatenate the key and magic string, then SHA1 hash and base64 encode
            MessageDigest md = MessageDigest.getInstance("SHA1");
            accept = Base64.encode(md.digest((clientKey + Constants.WEBSOCKET_MAGIC_STRING).getBytes()));
        } catch (NoSuchAlgorithmException e) {
            throw new WebSocketException("Algorithm is missing");
        }
        // make up reply data...
        IoBuffer buf = IoBuffer.allocate(308);
        buf.setAutoExpand(true);
        buf.put("HTTP/1.1 101 Switching Protocols".getBytes());
        buf.put(Constants.CRLF);
        buf.put("Upgrade: websocket".getBytes());
        buf.put(Constants.CRLF);
        buf.put("Connection: Upgrade".getBytes());
        buf.put(Constants.CRLF);
        buf.put("Server: Red5".getBytes());
        buf.put(Constants.CRLF);
        buf.put("Sec-WebSocket-Version-Server: 13".getBytes());
        buf.put(Constants.CRLF);
        buf.put(String.format("Sec-WebSocket-Origin: %s", conn.getOrigin()).getBytes());
        buf.put(Constants.CRLF);
        buf.put(String.format("Sec-WebSocket-Location: %s", conn.getHost()).getBytes());
        buf.put(Constants.CRLF);
        // send back extensions if enabled
        if (conn.hasExtensions()) {
            buf.put(String.format("Sec-WebSocket-Extensions: %s", conn.getExtensionsAsString()).getBytes());
            buf.put(Constants.CRLF);
        }
        // send back protocol if enabled
        if (conn.hasProtocol()) {
            buf.put(String.format("Sec-WebSocket-Protocol: %s", conn.getProtocol()).getBytes());
            buf.put(Constants.CRLF);
        }
        buf.put(String.format("Sec-WebSocket-Accept: %s", new String(accept)).getBytes());
        buf.put(Constants.CRLF);
        buf.put(Constants.CRLF);
        // if any bytes follow this crlf, the follow-up data will be corrupted
        if (logger.isTraceEnabled()) {
            logger.trace("Handshake response size: {}", buf.limit());
        }
        return new HandshakeResponse(buf);
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

}
