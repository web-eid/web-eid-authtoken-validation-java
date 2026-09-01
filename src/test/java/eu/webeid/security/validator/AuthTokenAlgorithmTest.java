// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.validator;

import eu.webeid.security.authtoken.WebEidAuthToken;
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.exceptions.AuthTokenParseException;
import eu.webeid.security.testutil.AbstractTestWithValidator;
import eu.webeid.security.util.DateAndTime;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import static eu.webeid.security.testutil.DateMocker.mockDate;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mockStatic;

class AuthTokenAlgorithmTest extends AbstractTestWithValidator {
    private MockedStatic<DateAndTime.DefaultClock> mockedClock;

    @Override
    @BeforeEach
    protected void setup() {
        super.setup();
        mockedClock = mockStatic(DateAndTime.DefaultClock.class);
        // Ensure that the certificates do not expire.
        mockDate("2021-07-23", mockedClock);
    }

    @AfterEach
    void tearDown() {
        mockedClock.close();
    }

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
