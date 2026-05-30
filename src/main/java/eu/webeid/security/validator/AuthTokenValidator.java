// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.validator;

import eu.webeid.security.authtoken.WebEidAuthToken;
import eu.webeid.security.certificate.CertificateData;
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.util.Strings;

import java.security.cert.X509Certificate;

/**
 * Parses and validates the provided Web eID authentication token.
 */
public interface AuthTokenValidator {

    String CURRENT_TOKEN_FORMAT_VERSION = "web-eid:1";

    /**
     * Parses the Web eID authentication token signed by the subject.
     *
     * @param authToken the Web eID authentication token string, in Web eID JSON format
     * @return the Web eID authentication token
     * @throws AuthTokenException when parsing fails
     */
    WebEidAuthToken parse(String authToken) throws AuthTokenException;

    /**
     * Validates the Web eID authentication token signed by the subject and returns
     * the subject certificate that can be used for retrieving information about the subject.
     * <p>
     * See {@link CertificateData} and {@link Strings} for convenience methods for retrieving user
     * information from the certificate.
     *
     * @param authToken the Web eID authentication token
     * @param currentChallengeNonce the challenge nonce that is associated with the authentication token
     * @return validated subject certificate
     * @throws AuthTokenException when validation fails
     */
    X509Certificate validate(WebEidAuthToken authToken, String currentChallengeNonce) throws AuthTokenException;

}
