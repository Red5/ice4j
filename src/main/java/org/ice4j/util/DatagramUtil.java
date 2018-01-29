package org.ice4j.util;

import java.net.DatagramPacket;
import java.net.InetAddress;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DatagramUtil {

    private static final Logger logger = LoggerFactory.getLogger(DatagramUtil.class);

    /**
     * Initializes a new DatagramPacket instance which is a clone of a specific DatagramPacket i.e. the properties of the clone
     * DatagramPacket are clones of the specified DatagramPacket.
     *
     * @param p the DatagramPacket to clone
     * @param arraycopy true if the actual bytes of the data of p are to be copied into the clone or false if only the
     * capacity of the data of p is to be cloned without copying the actual bytes of the data of p
     * @return a new DatagramPacket instance which is a clone of the specified DatagramPacket
     */
    public static DatagramPacket clone(DatagramPacket p, boolean arraycopy) {
        byte[] data;
        int off;
        int len;
        InetAddress address;
        int port;

        synchronized (p) {
            data = p.getData();
            off = p.getOffset();
            len = p.getLength();

            // Clone the data.
            {
                // The capacity of the specified p is preserved.
                byte[] dataClone = new byte[data.length];

                // However, only copy the range of data starting with off and
                // spanning len number of bytes. Of course, preserve off and len
                // in addition to the capacity.
                if (arraycopy && (len > 0)) {
                    int arraycopyOff, arraycopyLen;

                    // If off and/or len are going to cause an exception though,
                    // copy the whole data.
                    if ((off >= 0) && (off < data.length) && (off + len <= data.length)) {
                        arraycopyOff = off;
                        arraycopyLen = len;
                    } else {
                        arraycopyOff = 0;
                        arraycopyLen = data.length;
                    }
                    System.arraycopy(data, arraycopyOff, dataClone, arraycopyOff, arraycopyLen);
                }
                data = dataClone;
            }

            address = p.getAddress();
            port = p.getPort();
        }

        DatagramPacket c = new DatagramPacket(data, off, len);

        if (address != null)
            c.setAddress(address);
        if (port >= 0)
            c.setPort(port);

        return c;
    }

    /**
     * Copies the properties of a specific DatagramPacket to another DatagramPacket. The property values are not cloned.
     *
     * @param src the DatagramPacket which is to have its properties copied to dest
     * @param dest the DatagramPacket which is to have its properties set to the value of the respective properties of src
     */
    public static void copy(DatagramPacket src, DatagramPacket dest) {
        synchronized (dest) {
            dest.setAddress(src.getAddress());
            dest.setPort(src.getPort());

            byte[] srcData = src.getData();

            if (srcData == null) {
                dest.setLength(0);
            } else {
                byte[] destData = dest.getData();

                if (destData == null) {
                    dest.setLength(0);
                } else {
                    int destOffset = dest.getOffset();
                    int destLength = destData.length - destOffset;
                    int srcLength = src.getLength();

                    if (destLength >= srcLength) {
                        destLength = srcLength;
                    } else if (logger.isWarnEnabled()) {
                        logger.warn("Truncating received DatagramPacket data!");
                    }
                    System.arraycopy(srcData, src.getOffset(), destData, destOffset, destLength);
                    dest.setLength(destLength);
                }
            }
        }
    }

}
