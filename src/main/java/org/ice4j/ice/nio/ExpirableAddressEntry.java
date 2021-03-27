package org.ice4j.ice.nio;

import java.util.concurrent.Delayed;
import java.util.concurrent.TimeUnit;

/**
 * Immutable entry for expirable address bindings.
 * 
 * @author Paul Gregoire
 *
 */
public class ExpirableAddressEntry implements Delayed {

    // use the acceptor timeout as our expiration time modifier (multiply by 1k because its in seconds)
    private static final long TIMEOUT = IceTransport.getAcceptorTimeout() * 1000L;
    
    private final String addressKey;

    private final long expirationTime;

    public ExpirableAddressEntry(String addressKey) {
        // represents an address binding
        this.addressKey = addressKey;
        // entries are allowed to exist for up-to 3 seconds
        this.expirationTime = System.currentTimeMillis() + TIMEOUT;
    }

    public boolean isExpired() {
        return expirationTime >= System.currentTimeMillis();
    }

    public String getAddressKey() {
        return addressKey;
    }

    @Override
    public long getDelay(TimeUnit unit) {
        long diff = expirationTime - System.currentTimeMillis();
        return unit.convert(diff, TimeUnit.MILLISECONDS);
    }

    @Override
    public int compareTo(Delayed o) {
        long otherExpirationTime = ((ExpirableAddressEntry) o).expirationTime;
        if (expirationTime != otherExpirationTime) {
            return (int) (expirationTime - otherExpirationTime);
        }
        return 0;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = prime * addressKey.hashCode();
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        ExpirableAddressEntry other = (ExpirableAddressEntry) obj;
        if (addressKey == null) {
            if (other.addressKey != null) {
                return false;
            }
        } else if (!addressKey.equals(other.addressKey)) {
            return false;
        }
        return true;
    }

}
