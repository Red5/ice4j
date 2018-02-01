package org.ice4j.socket.filter;

/**
 * Represents a filter which accepts or rejects data in a byte array.
 *
 * @author Paul Gregoire
 */
public interface DataFilter {

    /**
     * Determines whether data is accepted by this filter.
     *
     * @param buf the bytes which are checked for acceptance by this filter
     * @return true if this filter accepts the specified data and false otherwise
     */
    public boolean accept(byte[] buf);

}
