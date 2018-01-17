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

import java.io.*;
import java.lang.reflect.*;
import java.util.*;

/**
 * Represents a STUN long-term credential.
 *
 * @author Lubomir Marinov
 * @author Aakash Garg
 */
public class LongTermCredential
{

    /**
     * Encodes a specific String into a sequence of bytes
     * using the UTF-8 charset, storing the result into a new byte
     * array.
     *
     * @param s the String to encode
     * @return a new array of bytes which represents the encoding of
     * the specified String using the UTF-8 charset
     */
    public static byte[] getBytes(String s)
    {
        if (s == null)
            return null;
        else
        {
            try
            {
                return s.getBytes("UTF-8");
            }
            catch (UnsupportedEncodingException ueex)
            {
                throw new UndeclaredThrowableException(ueex);
            }
        }
    }

    /**
     * Constructs a new String by decoding a specific array of
     * bytes using the UTF-8 charset. The length of the new
     * String is a function of the charset, and hence may not be equal
     * to the length of the byte array.
     * 
     * @param bytes the bytes to be decoded into characters
     * @return a new String which has been decoded from the specified
     * array of bytes using the UTF-8 charset
     */
    public static String toString(byte[] bytes)
    {
        if (bytes == null)
            return null;
        else
        {
            try
            {
                return new String(bytes, "UTF-8");
            }
            catch (UnsupportedEncodingException ueex)
            {
                throw new UndeclaredThrowableException(ueex);
            }
        }
    }

    /**
     * The password of this LongTermCredential.
     */
    private final byte[] password;

    /**
     * The username of this LongTermCredential.
     */
    private final byte[] username;

    /**
     * Initializes a new LongTermCredential instance with no username
     * and no password. Extenders should override {@link #getUsername()} and
     * {@link #getPassword()} to provide the username and the password,
     * respectively, when requested.
     */
    protected LongTermCredential()
    {
        this((byte[]) null, (byte[]) null);
    }

    /**
     * Initializes a new LongTermCredential instance with a specific
     * username and a specific password.
     *
     * @param username the username to initialize the new instance with
     * @param password the password to initialize the new instance with
     */
    public LongTermCredential(byte[] username, byte[] password)
    {
        this.username = (username == null) ? null : username.clone();
        this.password = (password == null) ? null : password.clone();
    }

    /**
     * Initializes a new LongTermCredential instance with a specific
     * username and a specific password.
     *
     * @param username the username to initialize the new instance with
     * @param password the password to initialize the new instance with
     */
    public LongTermCredential(String username, String password)
    {
        this(getBytes(username), getBytes(password));
    }

    /**
     * Gets the password of this LongTermCredential.
     *
     * @return an array of bytes which represents the password of this
     * LongTermCredential
     */
    public byte[] getPassword()
    {
        return (password == null) ? null : password.clone();
    }

    /**
     * Gets the username of this LongTermCredential.
     *
     * @return an array of bytes which represents the username of this
     * LongTermCredential
     */
    public byte[] getUsername()
    {
        return (username == null) ? null : username.clone();
    }

    @Override
    public int hashCode()
    {
        final int prime = 31;
        int result = 1;
        result = prime * result + Arrays.hashCode(password);
        result = prime * result + Arrays.hashCode(username);
        return result;
    }

    @Override
    public boolean equals(Object o)
    {
        if (o instanceof LongTermCredential)
        {
            LongTermCredential ltc = (LongTermCredential) o;
            if (Arrays.equals(
                this.username, ltc.username) && Arrays.equals(
                this.password, ltc.password))
            {
                return true;
            }
        }
        return false;
    }
    
}
