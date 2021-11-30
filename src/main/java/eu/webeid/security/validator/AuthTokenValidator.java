/*
 * Copyright (c) 2020-2021 Estonian Information System Authority
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package eu.webeid.security.validator;

import eu.webeid.security.authtoken.WebEidAuthToken;
import eu.webeid.security.certificate.CertificateData;
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.util.TitleCase;

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
     * See {@link CertificateData} and {@link TitleCase} for convenience methods for retrieving user
     * information from the certificate.
     *
     * @param authToken the Web eID authentication token
     * @param currentChallengeNonce the challenge nonce that is associated with the authentication token
     * @return validated subject certificate
     * @throws AuthTokenException when validation fails
     */
    X509Certificate validate(WebEidAuthToken authToken, String currentChallengeNonce) throws AuthTokenException;

}
