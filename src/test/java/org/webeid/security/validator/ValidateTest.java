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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.webeid.security.exceptions.TokenParseException;
import org.webeid.security.exceptions.UserCertificateExpiredException;
import org.webeid.security.exceptions.UserCertificateNotYetValidException;
import org.webeid.security.testutil.AbstractTestWithMockedDateValidatorAndCorrectNonce;
import org.webeid.security.testutil.Dates;
import org.webeid.security.testutil.Tokens;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.webeid.security.testutil.Dates.resetMockedFunctionalSubjectCertificateValidatorsDate;
import static org.webeid.security.testutil.Dates.setMockedFunctionalSubjectCertificateValidatorsDate;

class ValidateTest extends AbstractTestWithMockedDateValidatorAndCorrectNonce {

    @Override
    @AfterEach
    public void tearDown() {
        super.tearDown();
        try {
            resetMockedFunctionalSubjectCertificateValidatorsDate();
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void certificateIsNotValidYet() throws Exception {
        final Date certValidFrom = Dates.create("2018-10-17");
        setMockedFunctionalSubjectCertificateValidatorsDate(certValidFrom);

        assertThatThrownBy(() -> validator.validate(Tokens.SIGNED))
            .isInstanceOf(UserCertificateNotYetValidException.class);
    }

    @Test
    void certificateIsNoLongerValid() throws Exception {
        final Date certValidFrom = Dates.create("2023-10-19");
        setMockedFunctionalSubjectCertificateValidatorsDate(certValidFrom);

        assertThatThrownBy(() -> validator.validate(Tokens.SIGNED))
            .isInstanceOf(UserCertificateExpiredException.class);
    }

    @Test
    void testTokenTooShort() {
        assertThatThrownBy(() -> validator.validate(Tokens.TOKEN_TOO_SHORT))
            .isInstanceOf(TokenParseException.class)
            .hasMessageStartingWith("Auth token is null or too short");
    }

    @Test
    void testTokenTooLong() {
        assertThatThrownBy(() -> validator.validate(Tokens.TOKEN_TOO_LONG))
            .isInstanceOf(TokenParseException.class)
            .hasMessageStartingWith("Auth token is too long");
    }

}
