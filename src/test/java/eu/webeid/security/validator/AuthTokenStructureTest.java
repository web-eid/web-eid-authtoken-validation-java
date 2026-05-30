// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

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
