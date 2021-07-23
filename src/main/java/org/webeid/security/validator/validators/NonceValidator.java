/*
 * Copyright (c) 2020, 2021 The Web eID Project
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

package org.webeid.security.validator.validators;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.webeid.security.exceptions.NonceExpiredException;
import org.webeid.security.exceptions.NonceNotFoundException;
import org.webeid.security.exceptions.TokenParseException;
import org.webeid.security.exceptions.TokenValidationException;
import org.webeid.security.nonce.NonceGenerator;
import org.webeid.security.util.UtcDateTime;
import org.webeid.security.validator.AuthTokenValidatorData;

import javax.cache.Cache;
import java.time.ZonedDateTime;

public final class NonceValidator {

    private static final Logger LOG = LoggerFactory.getLogger(NonceValidator.class);

    private final Cache<String, ZonedDateTime> cache;

    public NonceValidator(Cache<String, ZonedDateTime> cache) {
        this.cache = cache;
    }

    /**
     * Validates that the nonce from the authentication token has the correct
     * length, exists in cache and has not expired.
     *
     * @param actualTokenData authentication token data that contains the nonce
     * @throws TokenValidationException when the nonce in the token does not
     *                                  meet the requirements
     */
    public void validateNonce(AuthTokenValidatorData actualTokenData) throws TokenValidationException {
        final String nonce = actualTokenData.getNonce();
        final ZonedDateTime nonceExpirationTime = cache.getAndRemove(nonce);
        if (nonceExpirationTime == null) {
            throw new NonceNotFoundException();
        }
        if (nonce.length() < NonceGenerator.NONCE_LENGTH) {
            throw new TokenParseException(String.format(
                "Nonce is shorter than the required length of %d.",
                NonceGenerator.NONCE_LENGTH
            ));
        }
        if (nonceExpirationTime.isBefore(UtcDateTime.now())) {
            throw new NonceExpiredException();
        }
        LOG.debug("Nonce was found and has not expired.");
    }
}
