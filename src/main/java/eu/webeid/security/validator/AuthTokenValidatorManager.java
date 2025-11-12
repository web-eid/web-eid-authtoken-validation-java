/*
 * Copyright (c) 2020-2025 Estonian Information System Authority
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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import eu.webeid.security.authtoken.WebEidAuthToken;
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.exceptions.AuthTokenParseException;
import eu.webeid.security.exceptions.JceException;
import eu.webeid.security.validator.ocsp.OcspClient;
import eu.webeid.security.validator.versionvalidators.AuthTokenVersionValidatorFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * Provides the default implementation of {@link AuthTokenValidator}.
 */
final class AuthTokenValidatorManager implements AuthTokenValidator {

    private static final Logger LOG = LoggerFactory.getLogger(AuthTokenValidatorManager.class);

    private final AuthTokenVersionValidatorFactory tokenValidatorFactory;

    // Use human-readable meaningful names for token length limits.
    private static final int TOKEN_MIN_LENGTH = 100;
    private static final int TOKEN_MAX_LENGTH = 10000;

    private static final ObjectReader TOKEN_READER = new ObjectMapper().readerFor(WebEidAuthToken.class);

    AuthTokenValidatorManager(AuthTokenValidationConfiguration configuration, OcspClient ocspClient)
        throws JceException {
        this.tokenValidatorFactory = AuthTokenVersionValidatorFactory.create(configuration, ocspClient);
    }

    @Override
    public WebEidAuthToken parse(String authToken) throws AuthTokenException {
        try {
            LOG.info("Starting token parsing");
            validateTokenLength(authToken);
            return parseToken(authToken);
        } catch (Exception e) {
            // Generally "log and rethrow" is an antipattern, but it fits with the surrounding logging style.
            LOG.warn("Token parsing was interrupted:", e);
            throw e;
        }
    }

    @Override
    public X509Certificate validate(WebEidAuthToken authToken, String currentChallengeNonce) throws AuthTokenException {
        try {
            Objects.requireNonNull(authToken, "authToken must not be null");
            LOG.info("Starting token validation");
            return tokenValidatorFactory
                .getValidatorFor(authToken.getFormat())
                .validate(authToken, currentChallengeNonce);
        } catch (Exception e) {
            // Generally "log and rethrow" is an antipattern, but it fits with the surrounding logging style.
            LOG.warn("Token validation was interrupted:", e);
            throw e;
        }
    }

    private void validateTokenLength(String authToken) throws AuthTokenParseException {
        if (authToken == null || authToken.length() < TOKEN_MIN_LENGTH) {
            throw new AuthTokenParseException("Auth token is null or too short");
        }
        if (authToken.length() > TOKEN_MAX_LENGTH) {
            throw new AuthTokenParseException("Auth token is too long");
        }
    }

    private WebEidAuthToken parseToken(String authToken) throws AuthTokenParseException {
        try {
            final WebEidAuthToken token = TOKEN_READER.readValue(authToken);
            if (token == null) {
                throw new AuthTokenParseException("Web eID authentication token is null");
            }
            return token;
        } catch (IOException e) {
            throw new AuthTokenParseException("Error parsing Web eID authentication token", e);
        }
    }

}
