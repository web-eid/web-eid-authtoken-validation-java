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

package org.webeid.security.validator;

import org.junit.jupiter.api.Test;
import org.webeid.security.exceptions.OriginMismatchException;
import org.webeid.security.exceptions.TokenParseException;
import org.webeid.security.testutil.AbstractTestWithMockedDateValidatorAndCorrectNonce;
import org.webeid.security.testutil.Tokens;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.webeid.security.testutil.AuthTokenValidators.getAuthTokenValidator;

class OriginTest extends AbstractTestWithMockedDateValidatorAndCorrectNonce {

    @Test
    void validateOriginMismatchFailure() throws Exception {
        validator = getAuthTokenValidator("https://mismatch.ee", cache);
        assertThatThrownBy(() -> validator.validate(Tokens.SIGNED))
            .isInstanceOf(OriginMismatchException.class);
    }

    @Test
    void testOriginMissing() {
        assertThatThrownBy(() -> validator.validate(Tokens.ORIGIN_MISSING))
            .isInstanceOf(TokenParseException.class)
            .hasMessageStartingWith("aud field must be present in authentication token body and must be an array");
    }

    @Test
    void testOriginEmpty() {
        assertThatThrownBy(() -> validator.validate(Tokens.ORIGIN_EMPTY))
            .isInstanceOf(TokenParseException.class)
            .hasMessageStartingWith("origin from aud field must not be empty");
    }

    @Test
    void testOriginNotString() {
        assertThatThrownBy(() -> validator.validate(Tokens.ORIGIN_NOT_STRING))
            .isInstanceOf(TokenParseException.class)
            .hasMessageStartingWith("aud field in authentication token body must be an array of strings");
    }

    @Test
    void testValidatorOriginNotUrl() {
        assertThatThrownBy(() -> getAuthTokenValidator("not-url", cache))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void testTokenOriginNotUrl() {
        assertThatThrownBy(() -> validator.validate(Tokens.ORIGIN_NOT_URL))
            .isInstanceOf(OriginMismatchException.class);
    }

    @Test
    void testValidatorOriginExcessiveElements() {
        assertThatThrownBy(() -> getAuthTokenValidator("https://ria.ee/excessive-element", cache))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void testTokenOriginExcessiveElements() throws Exception {
        final AuthTokenValidator validator = getAuthTokenValidator("https://ria.ee", cache);
        assertThatThrownBy(() -> validator.validate(Tokens.ORIGIN_URL_WITH_EXCESSIVE_ELEMENTS))
            .isInstanceOf(OriginMismatchException.class);
    }

    @Test
    void testValidatorOriginNotHttps() {
        assertThatThrownBy(() -> getAuthTokenValidator("http://ria.ee", cache))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void testTokenOriginNotHttps() throws Exception {
        final AuthTokenValidator validator = getAuthTokenValidator("https://ria.ee", cache);
        assertThatThrownBy(() -> validator.validate(Tokens.ORIGIN_VALID_URL_NOT_HTTPS))
            .isInstanceOf(OriginMismatchException.class);
    }

    @Test
    void testValidatorOriginNotValidUrl() {
        assertThatThrownBy(() -> getAuthTokenValidator("ria://ria.ee", cache))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageStartingWith("Provided URI is not a valid URL");
    }

    @Test
    void testValidatorOriginNotValidSyntax() {
        assertThatThrownBy(() -> getAuthTokenValidator("https:///ria.ee", cache))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageStartingWith("An URI syntax exception occurred");
    }
}
