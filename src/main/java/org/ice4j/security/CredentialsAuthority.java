/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Copyright @ 2015 Atlassian Pty Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ice4j.security;

/**
 * The {@link CredentialsAuthority} interface is implemented by applications
 * in order to allow the stack to verify the integrity of incoming messages
 * containing the MessageIntegrityAttribute.
 *
 * @author Emil Ivov
 */
public interface CredentialsAuthority
{
    /**
     * Returns the key (password) that corresponds to the specified local
     * username or user frag,  an empty array if there was no password for that
     * username or null if the username is not a local user name
     * recognized by this CredentialsAuthority.
     *
     * @param username the local user name or user frag whose credentials we'd
     * like to obtain.
     *
     * @return the key (password) that corresponds to the specified local
     * username or user frag,  an empty array if there was no password for that
     * username or null if the username is not a local user name
     * recognized by this CredentialsAuthority.
     */
    public byte[] getLocalKey(String username);

    /**
     * Returns the key (password) that corresponds to the specified remote
     * username or user frag,  an empty array if there was no password for that
     * username or null if the username is not a remote user name
     * recognized by this CredentialsAuthority.
     *
     * @param username the remote user name or user frag whose credentials we'd
     * like to obtain.
     * @param media the media name that we want to get remote key.
     *
     * @return the key (password) that corresponds to the specified remote
     * username or user frag,  an empty array if there was no password for that
     * username or null if the username is not a remote user name
     * recognized by this CredentialsAuthority.
     */
    public byte[] getRemoteKey(String username, String media);

    /**
     * Verifies whether username is currently known to this authority
     * and returns true if so. Returns false otherwise.
     *
     * @param username the user name whose validity we'd like to check.
     *
     * @return true if username is known to this
     * CredentialsAuthority and false otherwise.
     */
    public boolean checkLocalUserName(String username);
}
