/*
 * Copyright (c) 2020-2021 Estonian Information System Authority
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, mergCertificateExpiryValidatore, publish, distribute, sublicense, and/or sell
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
import org.webeid.security.exceptions.CertificateExpiredException;
import org.webeid.security.exceptions.CertificateNotYetValidException;
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

    // Subject certificate validity:
    // - not before: Thu Oct 18 12:50:47 EEST 2018
    // - not after: Wed Oct 18 00:59:59 EEST 2023
    // Issuer certificate validity:
    // - not before: Thu Sep 06 12:03:52 EEST 2018
    // - not after: Tue Aug 30 15:48:28 EEST 2033

    @Test
    void userCertificateIsNotYetValid() throws Exception {
        final Date certValidFrom = Dates.create("2018-10-17");
        setMockedFunctionalSubjectCertificateValidatorsDate(certValidFrom);

        assertThatThrownBy(() -> validator.validate(Tokens.SIGNED))
            .isInstanceOf(CertificateNotYetValidException.class)
            .hasMessage("User certificate is not yet valid");
    }

    @Test
    void trustedCACertificateIsNotYetValid() throws Exception {
        final Date certValidFrom = Dates.create("2018-08-17");
        setMockedFunctionalSubjectCertificateValidatorsDate(certValidFrom);

        assertThatThrownBy(() -> validator.validate(Tokens.SIGNED))
            .isInstanceOf(CertificateNotYetValidException.class)
            .hasMessage("Trusted CA certificate is not yet valid");
    }

    @Test
    void userCertificateIsNoLongerValid() throws Exception {
        final Date certValidFrom = Dates.create("2023-10-19");
        setMockedFunctionalSubjectCertificateValidatorsDate(certValidFrom);

        assertThatThrownBy(() -> validator.validate(Tokens.SIGNED))
            .isInstanceOf(CertificateExpiredException.class)
            .hasMessage("User certificate has expired");
    }

    @Test
    void trustedCACertificateIsNoLongerValid() throws Exception {
        final Date certValidFrom = Dates.create("2033-10-19");
        setMockedFunctionalSubjectCertificateValidatorsDate(certValidFrom);

        assertThatThrownBy(() -> validator.validate(Tokens.SIGNED))
            .isInstanceOf(CertificateExpiredException.class)
            .hasMessage("Trusted CA certificate has expired");
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
