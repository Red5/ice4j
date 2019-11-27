package org.ice4j.util;

public class Utils {

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    /**
     * Returns a byte array for the given hex encoded string.
     * 
     * @param hexString encoded hex string
     * @return byte array
     */
    public final static byte[] fromHexString(String hexString) {
        // remove all the whitespace first
        hexString = hexString.replaceAll("\\s+", "");
        int len = hexString.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4) + Character.digit(hexString.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Returns a hex string for a given byte array.
     * 
     * @param bytes
     * @return hex string
     */
    public final static String toHexString(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

}
