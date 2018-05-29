/* See LICENSE.md for license information */
package org.ice4j.ice.harvest;

import org.ice4j.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.*;

/**
 * Uses the Amazon AWS APIs to retrieve the public and private IPv4 addresses for an EC2 instance.
 *
 * @author Emil Ivov
 */
public class AwsCandidateHarvester extends MappingCandidateHarvester {

    private static final Logger logger = LoggerFactory.getLogger(AwsCandidateHarvester.class);

    /**
     * The URL where one obtains AWS public addresses.
     */
    private static final String PUBLIC_IP_URL = "http://169.254.169.254/latest/meta-data/public-ipv4";

    /**
     * The URL where one obtains AWS private/local addresses.
     */
    private static final String LOCAL_IP_URL = "http://169.254.169.254/latest/meta-data/local-ipv4";

    /**
     * The URL to use to test whether we are running on Amazon EC2.
     */
    private static final String EC2_TEST_URL = "http://169.254.169.254/latest/meta-data/";

    /**
     * Whether we are running on Amazon EC2.
     */
    private static Boolean RUNNING_ON_EC2;

    /**
     * The addresses that we will use as a mask
     */
    private static TransportAddress mask;

    /**
     * The addresses that we will be masking
     */
    private static TransportAddress face;

    /**
     * Whether we have already checked and found the mapping addresses.
     */
    private static boolean addressChecked;

    /**
     * Creates an AWS harvester. The actual addresses wil be retrieved later,
     * during the first harvest.
     */
    public AwsCandidateHarvester() {
        super();
    }

    /**
     * Sends HTTP GET queries to
     * http://169.254.169.254/latest/meta-data/local-ipv4 and
     * http://169.254.169.254/latest/meta-data/public-ipv4 to learn the
     * private (face) and public (mask) addresses of this EC2 instance.
     */
    private static synchronized void obtainEC2Addresses() {
        if (addressChecked) {
            return;
        }
        addressChecked = true;

        String localIPStr = null;
        String publicIPStr = null;

        try {
            localIPStr = fetch(LOCAL_IP_URL);
            publicIPStr = fetch(PUBLIC_IP_URL);
            //now let's cross our fingers and hope that what we got above are real IP addresses
            face = new TransportAddress(localIPStr, 9, Transport.UDP);
            mask = new TransportAddress(publicIPStr, 9, Transport.UDP);
            logger.info("Detected AWS IP's local: {} public: {}", face, mask);
        } catch (Exception exc) {
            //whatever happens, we just log and fail
            logger.info("IP Strings for local: {} public: {}", localIPStr, publicIPStr);
            logger.warn("We failed to obtain EC2 instance addresses for the following reason", exc);
        }
    }

    /**
     * Returns the public (mask) address, or null.
     * @return the public (mask) address, or null.
     */
    @Override
    public TransportAddress getMask() {
        if (smellsLikeAnEC2()) {
            obtainEC2Addresses();
            return mask;
        }
        return null;
    }

    /**
     * Returns the local (face) address, or null.
     * @return the local (face) address, or null.
     */
    @Override
    public TransportAddress getFace() {
        if (smellsLikeAnEC2()) {
            obtainEC2Addresses();
            return face;
        }
        return null;
    }

    /**
     * Determines if there is a decent chance for the box executing this
     * application to be an AWS EC2 instance and returns true if so.
     *
     * @return true if there appear to be decent chances for this
     * machine to be an AWS EC2 and false otherwise.
     */
    public synchronized static boolean smellsLikeAnEC2() {
        if (RUNNING_ON_EC2 == null) {
            RUNNING_ON_EC2 = doTestEc2();
        }
        return RUNNING_ON_EC2;
    }

    /**
     * Tries to connect to an Amazon EC2-specific URL in order to determine
     * whether we are running on EC2.
     *
     * @return true if the connection succeeded, false
     * otherwise.
     */
    private static boolean doTestEc2() {
        try {
            URLConnection conn = new URL(EC2_TEST_URL).openConnection();
            conn.setConnectTimeout(500); //don't hang for too long
            conn.getContent();
            return true;
        } catch (Exception exc) {
            //ah! I knew you weren't one of those ...
            return false;
        }
    }

    /**
     * Retrieves the content at the specified url. No more, no less.
     *
     * @param url the URL we'd like to open and query.
     *
     * @return the String we retrieved from the URL.
     *
     * @throws Exception if anything goes wrong.
     */
    private static String fetch(String url) throws Exception {
        URLConnection conn = new URL(url).openConnection();
        BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream(), "UTF-8"));
        String retString = in.readLine();
        in.close();
        return retString;
    }
}
