/* See LICENSE.md for license information */
package org.ice4j;

import java.net.*;

import org.ice4j.ice.*;

/**
 * The Address class is used to define destinations to outgoing Stun Packets.
 *
 * @author Emil Ivov
 * @author Lubomir Marinov
 */
public class TransportAddress extends InetSocketAddress {

    private static final long serialVersionUID = 5076001401234631237L;

    /**
     * The variable that we are using to store the transport that this address is pertaining to.
     */
    private final Transport transport;

    /**
     * Creates an address instance address from an IP address and a port number.
     * <p>
     * A valid port value is between 0 and 65535. A port number of zero will let the system pick up an
     * ephemeral port in a bind operation.
     * <P>
     * A null address will assign the <i>wildcard</i> address.
     * <p>
     * @param   hostname    The IP address
     * @param   port        The port number
     * @param   transport   The transport that this address would be bound to.
     * @throws IllegalArgumentException if the port parameter is outside the
     * specified range of valid port values.
     */
    public TransportAddress(String hostname, int port, Transport transport) {
        super(hostname, port);
        this.transport = transport;
    }

    /**
     * Creates an address instance address from a byte array containing an IP
     * address and a port number.
     * <p>
     * A valid port value is between 0 and 65535.
     * A port number of zero will let the system pick up an
     * ephemeral port in a bind operation.
     * <P>
     * A null address will assign the <i>wildcard</i> address.
     * <p>
     * @param    ipAddress The IP address
     * @param    port      The port number
     * @param    transport The Transport to use with this address.
     *
     * @throws UnknownHostException UnknownHostException  if IP address is of
     * illegal length
     */
    public TransportAddress(byte[] ipAddress, int port, Transport transport) throws UnknownHostException {
        this(InetAddress.getByAddress(ipAddress), port, transport);
    }

    /**
     * Creates an address instance from an InetSocketAddress.
     *
     * @param    address   the address and port.
     * @param    transport the transport to use with this address.
     *
     * @throws IllegalArgumentException if the port parameter is outside the
     * range of valid port values, or if the host name parameter is
     * null.
     */
    public TransportAddress(InetSocketAddress address, Transport transport) {
        this(address.getAddress(), address.getPort(), transport);
    }

    /**
     * Creates an address instance from a host name and a port number.
     * <p>
     * An attempt will be made to resolve the host name into an InetAddress.
     * If that attempt fails, the address will be flagged as <I>unresolved</I>.
     * <p>
     * A valid port value is between 0 and 65535. A port number of zero will
     * let the system pick up an ephemeral port in a bind operation.
     * <p>
     * @param    address   the address itself
     * @param    port      the port number
     * @param    transport the transport to use with this address.
     *
     * @throws IllegalArgumentException if the port parameter is outside the
     * range of valid port values, or if the host name parameter is
     * null.
     */
    public TransportAddress(InetAddress address, int port, Transport transport) {
        super(address, port);
        this.transport = transport;
    }

    /**
     * Returns the raw IP address of this Address object. The result is in
     * network byte order: the highest order byte of the address is in
     * getAddress()[0].
     *
     * @return the raw IP address of this object.
     */
    public byte[] getAddressBytes() {
        return getAddress().getAddress();
    }

    /**
     * Constructs a string representation of this InetSocketAddress. This String
     * is constructed by calling toString() on the InetAddress and concatenating
     * the port number (with a colon). If the address is unresolved then the
     * part before the colon will only contain the host name.
     *
     * @return a string representation of this object.
     */
    public String toString() {
        String hostAddress = getHostAddress();
        if (hostAddress == null) {
            hostAddress = getHostName();
        }
        StringBuilder bldr = new StringBuilder(hostAddress);
        if (isIPv6()) {
            bldr.insert(0, "[").append("]");
        }
        bldr.append(":").append(getPort());
        bldr.append("/").append(getTransport());
        return bldr.toString();
    }

    /**
     * Returns the host address.
     *
     * @return a String part of the address
     */
    public String getHostAddress() {
        InetAddress addr = getAddress();
        String addressStr = addr != null ? addr.getHostAddress() : null;
        if (addr instanceof Inet6Address) {
            addressStr = NetworkUtils.stripScopeID(addressStr);
        }
        return addressStr;
    }

    /**
     * The transport that this transport address is suggesting.
     *
     * @return one of the transport strings (UDP/TCP/...) defined as constants in this class.
     */
    public Transport getTransport() {
        return transport;
    }

    /**
     * Determines whether this TransportAddress is value equal to a specific TransportAddress.
     *
     * @param transportAddress the TransportAddress to test for value equality with this TransportAddress
     * @return true if this TransportAddress is value equal to the specified transportAddress; otherwise, false
     * @see #equalsTransportAddress(Object)
     */
    public boolean equals(TransportAddress transportAddress) {
        return equalsTransportAddress(transportAddress);
    }

    /**
     * Compares this object against the specified object. The result is true if and only if the argument is not null and it
     * represents the same address.
     * <p>
     * Two instances of TransportAddress represent the same address if both the InetAddresses (or hostnames if it is unresolved),
     * port numbers, and Transports are equal.
     *
     * If both addresses are unresolved, then the hostname, the port and the Transport are compared.
     *
     * @param   obj   the object to compare against.
     * @return  true if the objects are the same and false otherwise.
     * @see java.net.InetAddress#equals(java.lang.Object)
     */
    public boolean equalsTransportAddress(Object obj) {
        return super.equals(obj) && (((TransportAddress) obj).getTransport() == getTransport());
    }

    /**
     * Returns true if this is an IPv6 address and false otherwise.
     *
     * @return true if this is an IPv6 address and false otherwise.
     */
    public boolean isIPv6() {
        return getAddress() instanceof Inet6Address;
    }

    /**
     * Determines whether this TransportAddress is theoretically capable of communicating with dst. An address is certain not
     * to be able to communicate with another if they do not have the same Transport or family.
     *
     * @param dst the TransportAddress that we'd like to check for reachability from this one
     * @return true if this {@link TransportAddress} shares the same Transport and family as dst or false otherwise
     */
    public boolean canReach(TransportAddress dst) {
        if (getTransport() != dst.getTransport()) {
            return false;
        }
        if (isIPv6() != dst.isIPv6()) {
            return false;
        }
        if (isIPv6()) {
            Inet6Address srcAddr = (Inet6Address) getAddress();
            Inet6Address dstAddr = (Inet6Address) dst.getAddress();
            if (srcAddr.isLinkLocalAddress() != dstAddr.isLinkLocalAddress()) {
                // this one may actually work if for example we are contacting the public address of someone in our local network. however
                // in most cases we would also be able to reach the same address via a global address of our own and the probability of the
                // opposite is considerably lower than the probability of us trying to reach a distant global address through one of our own.
                // Therefore we would return false here by default.
                return Boolean.getBoolean(StackProperties.ALLOW_LINK_TO_GLOBAL_REACHABILITY);
            }
        }
        // may add more unreachability conditions here in the future
        return true;
    }

}
