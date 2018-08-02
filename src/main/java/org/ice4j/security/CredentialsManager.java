/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal. Copyright @ 2015 Atlassian Pty Ltd Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or
 * agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under the License.
 */
package org.ice4j.security;

import java.util.concurrent.CopyOnWriteArraySet;

import org.ice4j.stack.StunStack;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The CredentialsManager allows an application to handle verification
 * of incoming MessageIntegrityAttributes by registering a
 * {@link CredentialsAuthority} implementation. The point of this mechanism
 * is to allow use in both applications that would handle large numbers of
 * possible users (such as STUN/TURN servers) or others that would only work
 * with a few, like for example an ICE implementation.
 *
 * TODO: just throwing a user name at the manager and expecting it to find
 * an authority that knows about it may lead to ambiguities so we may need
 * to add other parameters in here that would allow us to better select an
 * authority.
 *
 * @author Emil Ivov
 * @author Lyubomir Marinov
 */
public class CredentialsManager {

    private final static Logger logger = LoggerFactory.getLogger(CredentialsManager.class);

    /**
     * The list of CredentialsAuthoritys registered with this manager
     * as being able to provide credentials.
     */
    private final CopyOnWriteArraySet<CredentialsAuthority> authorities = new CopyOnWriteArraySet<>();

    /**
     * Verifies whether username is currently known to any of the {@link CredentialsAuthority}s registered with this manager and
     * and returns true if so. Returns false otherwise.
     *
     * @param username the user name whose validity we'd like to check
     * @return true if username is known to any of the CredentialsAuthoritys registered here and false otherwise
     */
    public boolean checkLocalUserName(String username) {
        for (CredentialsAuthority auth : authorities) {
            if (auth.checkLocalUserName(username)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Queries all currently registered {@link CredentialsAuthority}s for a password corresponding to the specified local username or user
     * frag and returns the first non-null one.
     *
     * @param username a local user name or user frag whose credentials we'd like to obtain
     * @return null if username was not a recognized local user name for none of the currently registered CredentialsAuthoritys or
     * a byte array containing the first non-null password that one of them returned
     */
    public byte[] getLocalKey(String username) {
        logger.trace("getLocalKey username: {}", username);
        for (CredentialsAuthority auth : authorities) {
            byte[] passwd = auth.getLocalKey(username);
            if (passwd != null) {
                if (logger.isTraceEnabled()) {
                    logger.trace("Local key: {}", StunStack.toHexString(passwd));
                }
                return passwd;
            }
        }
        return null;
    }

    /**
     * Queries all currently registered {@link CredentialsAuthority}s for a
     * password corresponding to the specified remote username or user
     * frag and returns the first non-null one.
     *
     * @param username a remote user name or user frag whose credentials we'd like to obtain
     * @param media the media name that we want to get remote key
     * @return null if username was not a recognized remote user name for none of the currently registered CredentialsAuthoritys or
     * a byte array containing the first non-null password that one of them returned
     */
    public byte[] getRemoteKey(String username, String media) {
        logger.trace("getRemoteKey username: {} media: {}", username, media);
        for (CredentialsAuthority auth : authorities) {
            byte[] passwd = auth.getRemoteKey(username, media);
            if (passwd != null) {
                if (logger.isTraceEnabled()) {
                    logger.trace("Remote key: {}", StunStack.toHexString(passwd));
                }
                return passwd;
            }
        }
        return null;
    }

    /**
     * Adds authority to the list of {@link CredentialsAuthority}s registered with this manager.
     *
     * @param authority the {@link CredentialsAuthority} to add to this manager
     */
    public void registerAuthority(CredentialsAuthority authority) {
        authorities.add(authority);
    }

    /**
     * Removes authority from the list of {@link CredentialsAuthority}s registered with this manager.
     *
     * @param authority the {@link CredentialsAuthority} to remove from this manager
     */
    public void unregisterAuthority(CredentialsAuthority authority) {
        authorities.remove(authority);
    }
}
