// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

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
