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
import org.webeid.security.exceptions.NonceExpiredException;
import org.webeid.security.exceptions.NonceNotFoundException;
import org.webeid.security.exceptions.TokenParseException;
import org.webeid.security.testutil.AbstractTestWithValidator;
import org.webeid.security.testutil.Dates;
import org.webeid.security.testutil.Tokens;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.webeid.security.testutil.Dates.setMockedDefaultJwtParserDate;

class NonceTest extends AbstractTestWithValidator {

    @Test
    void validateIncorrectNonce() {
        putIncorrectNonceToCache();
        assertThatThrownBy(() -> validator.validate(Tokens.SIGNED))
            .isInstanceOf(NonceNotFoundException.class);
    }

    @Test
    void validateExpiredNonce() {
        putExpiredNonceToCache();
        assertThatThrownBy(() -> validator.validate(Tokens.SIGNED))
            .isInstanceOf(NonceExpiredException.class);
    }

    @Test
    void testNonceMissing() throws Exception {
        setMockedDefaultJwtParserDate(Dates.create("2020-04-14T13:00:00Z"));
        assertThatThrownBy(() -> validator.validate(Tokens.NONCE_MISSING))
            .isInstanceOf(TokenParseException.class)
            .hasMessageStartingWith("nonce field must be present and not empty in authentication token body");
    }

    @Test
    void testNonceEmpty() throws Exception {
        setMockedDefaultJwtParserDate(Dates.create("2020-04-14T13:00:00Z"));
        assertThatThrownBy(() -> validator.validate(Tokens.NONCE_EMPTY))
            .isInstanceOf(TokenParseException.class)
            .hasMessageStartingWith("nonce field must be present and not empty in authentication token body");
    }

    @Test
    void testTokenNonceNotString() throws Exception {
        setMockedDefaultJwtParserDate(Dates.create("2020-04-14T13:00:00Z"));
        assertThatThrownBy(() -> validator.validate(Tokens.NONCE_NOT_STRING))
            .isInstanceOf(TokenParseException.class);
    }

    @Test
    void testNonceTooShort() throws Exception {
        setMockedDefaultJwtParserDate(Dates.create("2020-04-14T13:00:00Z"));
        putTooShortNonceToCache();
        assertThatThrownBy(() -> validator.validate(Tokens.NONCE_TOO_SHORT))
            .isInstanceOf(TokenParseException.class);
    }

}
