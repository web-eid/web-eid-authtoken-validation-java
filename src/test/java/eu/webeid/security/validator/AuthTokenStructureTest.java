/*
 * Copyright (c) 2020-2024 Estonian Information System Authority
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
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.exceptions.AuthTokenParseException;
import eu.webeid.security.testutil.AbstractTestWithValidator;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthTokenStructureTest extends AbstractTestWithValidator {

    @Test
    void whenNullToken_thenParsingFails() {
        assertThatThrownBy(() -> validator
            .parse(null))
            .isInstanceOf(AuthTokenParseException.class)
            .hasMessage("Auth token is null or too short");
    }

    @Test
    void whenNullStrToken_thenParsingFails() {
        assertThatThrownBy(() -> validator
            .parse("null"))
            .isInstanceOf(AuthTokenParseException.class)
            .hasMessage("Auth token is null or too short");
    }

    @Test
    void whenTokenTooShort_thenParsingFails() {
        assertThatThrownBy(() -> validator
            .parse(new String(new char[99])))
            .isInstanceOf(AuthTokenParseException.class)
            .hasMessage("Auth token is null or too short");
    }

    @Test
    void whenTokenTooLong_thenParsingFails() {
        assertThatThrownBy(() -> validator
            .parse(new String(new char[10001])))
            .isInstanceOf(AuthTokenParseException.class)
            .hasMessage("Auth token is too long");
    }

    @Test
    void whenUnknownTokenVersion_thenParsingFails() throws AuthTokenException {
        final WebEidAuthToken token = replaceTokenField(VALID_AUTH_TOKEN, "web-eid:1", "invalid");
        assertThatThrownBy(() -> validator
            .validate(token, ""))
            .isInstanceOf(AuthTokenParseException.class)
            .hasMessage("Only token format version 'web-eid:1' is currently supported");
    }
}
