/*
 * Copyright (c) 2020 The Web eID Project
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
import org.webeid.security.exceptions.OriginMismatchException;
import org.webeid.security.exceptions.TokenValidationException;
import org.webeid.security.validator.AuthTokenValidatorData;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;

public final class OriginValidator {

    private static final Logger LOG = LoggerFactory.getLogger(OriginValidator.class);

    private final URI expectedOrigin;

    public OriginValidator(URI expectedOrigin) {
        this.expectedOrigin = expectedOrigin;
    }

    /**
     * Validates that the origin from the authentication token matches with the configured site origin.
     *
     * @param actualTokenData authentication token data that contains the origin from authentication token
     * @throws TokenValidationException when origins don't match
     */
    public void validateOrigin(AuthTokenValidatorData actualTokenData) throws TokenValidationException {
        try {
            final URI originUri = URI.create(actualTokenData.getOrigin());

            validateIsOriginURL(originUri);

            if (!expectedOrigin.equals(originUri)) {
                throw new OriginMismatchException();
            }
            LOG.debug("Origin is equal to expected origin.");

        } catch (IllegalArgumentException e) {
            throw new OriginMismatchException(e);
        }
    }

    /**
     * Validates that the given URI is an origin URL as defined in <a href="https://developer.mozilla.org/en-US/docs/Web/API/Location/origin">MDN</a>,
     * in the form of {@code <scheme> "://" <hostname> [ ":" <port> ]}.
     *
     * @param uri URI with origin URL
     * @throws IllegalArgumentException when the URI is not in the form of origin URL
     */
    public static void validateIsOriginURL(URI uri) throws IllegalArgumentException {
        try {
            // 1. Verify that the URI can be converted to absolute URL.
            uri.toURL();
            // 2. Verify that the URI contains only HTTPS scheme, host and optional port components.
            if (!new URI("https", null, uri.getHost(), uri.getPort(), null, null, null)
                .equals(uri)) {
                throw new IllegalArgumentException("Origin URI must only contain the HTTPS scheme, host and optional port component");
            }
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Provided URI is not a valid URL");
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("An URI syntax exception occurred");
        }
    }
}
