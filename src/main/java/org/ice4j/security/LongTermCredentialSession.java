/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal. Copyright @ 2015 Atlassian Pty Ltd Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or
 * agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under the License.
 */
package org.ice4j.security;

import java.lang.reflect.*;
import java.security.*;
import java.util.*;

import org.ice4j.*;
import org.ice4j.message.*;

/**
 * Represents a use of a LongTermCredential and implements CredentialsAuthority for it.
 *
 * @author Lubomir Marinov
 */
public class LongTermCredentialSession implements CredentialsAuthority {

    /**
     * The LongTermCredential a use of which is represented by this instance.
     */
    private final LongTermCredential longTermCredential;

    /**
     * The value of the NONCE attribute currently associated with the use of
     * {@link #longTermCredential} represented by this instance.
     */
    private byte[] nonce;

    /**
     * The realm (i.e. the value of the REALM attribute) in which a use of
     * {@link #longTermCredential} is represented by this instance.
     */
    private final byte[] realm;

    /**
     * Initializes a new LongTermCredentialSession instance which
     * is to represent a use of a specific LongTermCredential in a
     * specific realm.
     *
     * @param longTermCredential the LongTermCredential a use of
     * which is to be represented by the new instance
     * @param realm the realm in which the specified
     * LongTermCredential is to be used
     */
    public LongTermCredentialSession(LongTermCredential longTermCredential, byte[] realm) {
        this.longTermCredential = longTermCredential;
        this.realm = (realm == null) ? null : realm.clone();
    }

    /**
     * Adds the Attributes to a specific Request which support
     * the long-term credential mechanism using the LongTermCredential
     * associated with this instance.
     *
     * @param request the Request in which the Attribute
     * supporting the STUN long-term credential mechanism are to be added
     * @throws StunException if anything goes wrong while adding the
     * Attributes to request which support the STUN long-term
     * credential mechanism
     */
    public void addAttributes(Request request) throws StunException {
        MessageFactory.addLongTermCredentialAttributes(request, getUsername(), getRealm(), getNonce());
    }

    /**
     * Determines whether username is currently known to this authority
     *
     * @param username the user name whose validity we'd like to check
     * @return true if username is known to this
     * CredentialsAuthority; false, otherwise
     * @see CredentialsAuthority#checkLocalUserName(String)
     */
    public boolean checkLocalUserName(String username) {
        /*
         * The value of USERNAME is a variable-length value. It MUST contain a UTF-8 [RFC3629] encoded sequence of less than 513 bytes, and MUST have been processed using SASLprep
         * [RFC4013].
         */
        return usernameEquals(LongTermCredential.getBytes(username));
    }

    /**
     * Returns the key (password) that corresponds to the specified local
     * username or user frag,  an empty array if there was no password for
     * that username or null if the username is not a local user
     * name recognized by this CredentialsAuthority.
     *
     * @param username the local user name or user frag whose credentials
     * we'd like to obtain
     * @return the key (password) that corresponds to the specified local
     * username or user frag,  an empty array if there was no password for
     * that username or null if the username is not a local user
     * name recognized by this CredentialsAuthority
     * @see CredentialsAuthority#getLocalKey(String)
     */
    public byte[] getLocalKey(String username) {
        if (!checkLocalUserName(username))
            return null;

        // MD5(username ":" realm ":" SASLprep(password))
        StringBuilder localKeyBuilder = new StringBuilder();

        if (username != null)
            localKeyBuilder.append(username);
        localKeyBuilder.append(':');

        String realm = LongTermCredential.toString(getRealm());

        if (realm != null)
            localKeyBuilder.append(realm);
        localKeyBuilder.append(':');

        String password = LongTermCredential.toString(getPassword());

        if (password != null) {
            // TODO SASLprep
            localKeyBuilder.append(password);
        }

        MessageDigest md5;

        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException nsaex) {
            throw new UndeclaredThrowableException(nsaex);
        }
        return md5.digest(LongTermCredential.getBytes(localKeyBuilder.toString()));
    }

    /**
     * Gets the value of the NONCE attribute currently associated with the use
     * of the LongTermCredential represented by this instance.
     *
     * @return the value of the NONCE attribute currently associated with the
     * use of the LongTermCredential represented by this instance
     */
    public byte[] getNonce() {
        return (nonce == null) ? null : nonce.clone();
    }

    /**
     * Gets the password of the LongTermCredential used by this
     * instance.
     *
     * @return the password of the LongTermCredential used by this
     * instance
     */
    public byte[] getPassword() {
        return longTermCredential.getPassword();
    }

    /**
     * Gets the realm (i.e. the value of the REALM attribute) in which this
     * instance uses the LongTermCredential associated with it.
     *
     * @return the realm (i.e. the value of the REALM attribute) in which this
     * instance uses the LongTermCredential associated with it
     */
    public byte[] getRealm() {
        return (realm == null) ? null : realm.clone();
    }

    /**
     * Returns the key (password) that corresponds to the specified remote
     * username or user frag,  an empty array if there was no password for
     * that username or null if the username is not a remote user
     * name recognized by this CredentialsAuthority.
     *
     * @param username the remote user name or user frag whose credentials
     * we'd like to obtain
     * @param media not used
     * @return the key (password) that corresponds to the specified remote
     * username or user frag,  an empty array if there was no password for
     * that username or null if the username is not a remote user
     * name recognized by this CredentialsAuthority
     * @see CredentialsAuthority#getRemoteKey(String, String)
     */
    public byte[] getRemoteKey(String username, String media) {
        // The password is the same on the local and the remote sides.
        return getLocalKey(username);
    }

    /**
     * Gets the username of the LongTermCredential used by this
     * instance.
     *
     * @return the username of the LongTermCredential used by this
     * instance
     */
    public byte[] getUsername() {
        return longTermCredential.getUsername();
    }

    /**
     * Determines whether the realm of this LongTermCredentialSession
     * is equal to a specific realm.
     *
     * @param realm the realm to compare for equality to the realm of this
     * LongTermCredentialSession
     * @return true if the specified realm is equal to the
     * realm of this LongTermCredentialSession; otherwise,
     * false
     */
    public boolean realmEquals(byte[] realm) {
        return (realm == null) ? (this.realm == null) : Arrays.equals(realm, this.realm);
    }

    /**
     * Sets the value of the NONCE attribute to be associated with the use of
     * the LongTermCredential represented by this instance.
     *
     * @param nonce the value of the NONCE attribute to be associated with the
     * use of the LongTermCredential represented by this instance
     */
    public void setNonce(byte[] nonce) {
        this.nonce = (nonce == null) ? null : nonce.clone();
    }

    /**
     * Determines whether the username of the LongTermCredential used
     * by this instance is equal to a specific username.
     *
     * @param username the username to compare for equality to the username of
     * the LongTermCredential used by this instance
     * @return true if the specified username is equal to the
     * username of the LongTermCredential used by this instance;
     * otherwise, false
     */
    public boolean usernameEquals(byte[] username) {
        byte[] thisUsername = getUsername();
        return (username == null) ? (thisUsername == null) : Arrays.equals(username, thisUsername);
    }
}
