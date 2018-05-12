package org.ice4j.util;

import javax.xml.bind.DatatypeConverter;

public class Utils {

    /**
     * Returns a byte array for the given hex encoded string.
     * 
     * @param s encoded hex string
     * @return byte array
     */
    public final static byte[] hexStringToByteArray(String s) {
        // remove all the whitespace first
        s = s.replaceAll("\\s+", "");
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public final static String byteArrayToHexString(byte[] a) {
        return DatatypeConverter.printHexBinary(a);
    }

}
