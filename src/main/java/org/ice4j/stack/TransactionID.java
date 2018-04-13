/* See LICENSE.md for license information */
package org.ice4j.stack;

import java.util.Arrays;
import java.util.Random;

/**
 * This class encapsulates a STUN transaction ID. It is useful for storing
 * transaction IDs in collection objects as it implements the equals method.
 * It also provides a utility for creating unique transaction IDs.
 *
 * @author Emil Ivov
 */
public class TransactionID {
    /**
     * RFC5289 Transaction ID length.
     */
    public static final int RFC5389_TRANSACTION_ID_LENGTH = 12;

    /**
     * RFC3489 Transaction ID length.
     */
    public static final int RFC3489_TRANSACTION_ID_LENGTH = 16;

    private static final char[] hexArray = "0123456789ABCDEF".toCharArray();

    /**
     * Used to randomly generate transaction ids; seeded with current time.
     */
    private static final Random random = new Random(System.currentTimeMillis());

    /**
     * The id itself
     */
    private final byte[] transactionID;

    /**
     * Any object that the application would like to correlate to a transaction.
     */
    private Object applicationData;

    /**
     * A hashcode for hashtable storage.
     */
    private int hashCode = 0;

    /**
     * Limits access to TransactionID instantiation.
     */
    private TransactionID() {
        this(false);
    }

    /**
     * Limits access to TransactionID instantiation.
     *
     * @param rfc3489Compatibility true to create a RFC3489 transaction ID
     */
    private TransactionID(boolean rfc3489Compatibility) {
        transactionID = new byte[rfc3489Compatibility ? RFC3489_TRANSACTION_ID_LENGTH : RFC5389_TRANSACTION_ID_LENGTH];
    }

    /**
     * Creates a transaction id object.The transaction id itself is generated
     * using the following algorithm:
     *
     * The first 6 bytes of the id are given the value of
     * System.currentTimeMillis(). Putting the right most bits first
     * so that we get a more optimized equals() method.
     *
     * @return A TransactionID object with a unique transaction id.
     */
    public static TransactionID createNewTransactionID() {
        TransactionID tid = new TransactionID();
        random.nextBytes(tid.transactionID);
        return tid;
    }

    /**
     * Creates a RFC3489 transaction id object.The transaction id itself is
     * generated using the following algorithm:
     *
     * The first 8 bytes of the id are given the value of
     * System.currentTimeMillis(). Putting the right most bits first
     * so that we get a more optimized equals() method.
     *
     * @return A TransactionID object with a unique transaction id.
     */
    public static TransactionID createNewRFC3489TransactionID() {
        TransactionID tid = new TransactionID(true);
        random.nextBytes(tid.transactionID);
        return tid;
    }

    /**
     * Returns a TransactionID instance for the specified id. If transactionID is the ID of a client or a server transaction
     * already known to the stack, then this method would return a reference to that transaction's instance so that we could use it to for storing
     * application data.
     *
     * @param stunStack the StunStack in the context of which the request to create a TransactionID is being made
     * @param transactionID the value of the ID.
     *
     * @return a reference to the (possibly already existing) TransactionID corresponding to the value of transactionID
     */
    public static TransactionID createTransactionID(StunStack stunStack, byte[] transactionID) {
        TransactionID tid = TransactionID.build(transactionID);
        //first check whether we can find a client or a server tran with the specified id.
        StunClientTransaction cliTran = stunStack.getClientTransaction(tid);
        if (cliTran != null) {
            tid = cliTran.getTransactionID();
        } else {
            StunServerTransaction serTran = stunStack.getServerTransaction(tid);
            if (serTran != null) {
                tid = serTran.getTransactionID();
            }
        }
        return tid;
    }

    /**
     * Create a TransactionID from supplied byte array.
     * 
     * @param transactionID
     * @return tid
     */
    public final static TransactionID build(byte[] transactionID) {
        //seems that the caller really wants a new ID, we flag for RFC3489 but we actually prefer RFC5389
        TransactionID tid = new TransactionID((transactionID.length == RFC3489_TRANSACTION_ID_LENGTH));
        System.arraycopy(transactionID, 0, tid.transactionID, 0, tid.transactionID.length);
        return tid;
    }

    /**
     * Returns the transaction id byte array (length 12 or 16 if RFC3489
     * compatible).
     *
     * @return the transaction ID byte array.
     */
    public byte[] getBytes() {
        return transactionID;
    }

    /**
     * If the transaction is compatible with RFC3489 (16 bytes).
     *
     * @return true if transaction ID is compatible with RFC3489
     */
    public boolean isRFC3489Compatible() {
        return (transactionID.length == 16);
    }

    /**
     * Compares two TransactionID objects.
     * @param obj the object to compare with.
     * @return true if the objects are equal and false otherwise.
     */
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!(obj instanceof TransactionID))
            return false;

        return Arrays.equals(transactionID, ((TransactionID) obj).transactionID);
    }

    /**
     * Compares the specified byte array with this transaction id.
     * @param targetID the id to compare with ours.
     * @return true if targetID matches this transaction id.
     */
    public boolean equals(byte[] targetID) {
        return Arrays.equals(transactionID, targetID);
    }

    /**
     * Returns the first four bytes of the transactionID to ensure proper
     * retrieval from hashtables.
     * @return the hashcode of this object - as advised by the Java Platform
     * Specification
     */
    public int hashCode() {
        if (hashCode == 0) {
            //calculate hashcode for Hashtable storage
            hashCode = (transactionID[3] << 24 & 0xFF000000) | (transactionID[2] << 16 & 0x00FF0000) | (transactionID[1] << 8 & 0x0000FF00) | (transactionID[0] & 0x000000FF);
        }
        return hashCode;
    }

    /**
     * Returns a string representation of the ID
     *
     * @return a hex string representing the id
     */
    public String toString() {
        return TransactionID.toString(transactionID);
    }

    /**
     * Returns a string representation of the ID
     *
     * @param transactionID the transaction ID to convert into String.
     *
     * @return a hex string representing the id
     */
    public static String toString(byte[] transactionID) {
        char[] hexChars = new char[transactionID.length * 2];
        for (int j = 0; j < transactionID.length; j++) {
            int v = transactionID[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * Stores applicationData in this ID so that we can refer back to
     * it if we ever need to at a later stage (e.g. when receiving a response
     * to a {@link StunClientTransaction}).
     *
     * @param applicationData a reference to the {@link Object} that the
     * application would like to correlate to the transaction represented by
     * this ID.
     */
    public void setApplicationData(Object applicationData) {
        this.applicationData = applicationData;
    }

    /**
     * Returns whatever applicationData was previously stored in this
     * ID.
     *
     * @return a reference to the {@link Object} that the application may have
     * stored in this ID's application data field.
     */
    public Object getApplicationData() {
        return applicationData;
    }

}
