package org.ice4j.ice.harvest;

import java.net.InetAddress;

/**
 * Model for InetAddress and whether or not its from a virtual interface.
 */
public class AddressRef {

    private InetAddress address;

    private boolean virtual;

    public AddressRef(InetAddress address, boolean virtual) {
        this.address = address;
        this.virtual = virtual;
    }

    public InetAddress getAddress() {
        return address;
    }

    public boolean isVirtual() {
        return virtual;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((address == null) ? 0 : address.hashCode());
        result = prime * result + (virtual ? 1231 : 1237);
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        AddressRef other = (AddressRef) obj;
        if (address == null) {
            if (other.address != null)
                return false;
        } else if (!address.equals(other.address))
            return false;
        if (virtual != other.virtual)
            return false;
        return true;
    }

    @Override
    public String toString() {
        return "AddressRef [address=" + address + ", virtual=" + virtual + "]";
    }

}