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
        if (bytes == null || bytes.length == 0) {
            throw new IllegalArgumentException("bytes empty or null");
        }
        StringBuilder output = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            int b0 = b & 0xFF;
            int b1 = b0 >> 4;
            int b2 = b0 & 0x0F;
            output.append(HEX_ARRAY[b1]).append(HEX_ARRAY[b2]);
        }
        return output.toString();
    }

}
