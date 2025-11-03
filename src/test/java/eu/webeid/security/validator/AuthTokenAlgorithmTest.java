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

import org.junit.jupiter.api.Test;
import eu.webeid.security.authtoken.WebEidAuthToken;
import eu.webeid.security.exceptions.AuthTokenParseException;
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.testutil.AbstractTestWithValidator;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthTokenAlgorithmTest extends AbstractTestWithValidator {

    @Test
    void whenAlgorithmNone_thenValidationFails() throws AuthTokenException {
        final WebEidAuthToken authToken = replaceTokenField(VALID_AUTH_TOKEN, "ES384", "NONE");
        assertThatThrownBy(() -> validator
            .validate(authToken, VALID_CHALLENGE_NONCE))
            .isInstanceOf(AuthTokenParseException.class)
            .hasMessage("Unsupported signature algorithm");
    }

    @Test
    void whenAlgorithmEmpty_thenParsingFails() throws AuthTokenException {
        final WebEidAuthToken authToken = replaceTokenField(VALID_AUTH_TOKEN, "ES384", "");
        assertThatThrownBy(() -> validator
            .validate(authToken, VALID_CHALLENGE_NONCE))
            .isInstanceOf(AuthTokenParseException.class)
            .hasMessage("'algorithm' is null or empty");
    }

    @Test
    void whenAlgorithmInvalid_thenParsingFails() throws AuthTokenException {
        final WebEidAuthToken authToken = replaceTokenField(VALID_AUTH_TOKEN, "ES384", "\\u0000\\t\\ninvalid");
        assertThatThrownBy(() -> validator
            .validate(authToken, VALID_CHALLENGE_NONCE))
            .isInstanceOf(AuthTokenParseException.class)
            .hasMessage("Unsupported signature algorithm");
    }

}
