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
import org.webeid.security.exceptions.TokenParseException;
import org.webeid.security.exceptions.TokenSignatureValidationException;
import org.webeid.security.testutil.AbstractTestWithMockedDateValidatorAndCorrectNonce;
import org.webeid.security.testutil.Tokens;
import org.webeid.security.util.CertUtil;

import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.webeid.security.testutil.Tokens.getUnsignedTokenString;
import static org.webeid.security.util.TitleCase.toTitleCase;

class ParseTest extends AbstractTestWithMockedDateValidatorAndCorrectNonce {

    /**
     * Validates the happy path:
     * - valid user certificate with trusted issuer signature
     * - token signature is correct
     * - correct origin
     * - nonce exists in the cache and has not expired
     */
    @Test
    void parseSignedToken() throws Exception {
        final X509Certificate result = validator.validate(Tokens.SIGNED);
        assertThat(CertUtil.getSubjectCN(result))
            .isEqualTo("JÕEORG\\,JAAK-KRISTJAN\\,38001085718");
        assertThat(toTitleCase(CertUtil.getSubjectGivenName(result)))
            .isEqualTo("Jaak-Kristjan");
        assertThat(toTitleCase(CertUtil.getSubjectSurname(result)))
            .isEqualTo("Jõeorg");
        assertThat(CertUtil.getSubjectIdCode(result))
            .isEqualTo("PNOEE-38001085718");
        assertThat(CertUtil.getSubjectCountryCode(result))
            .isEqualTo("EE");
    }

    @Test
    void detectUnsignedToken() {
        assertThatThrownBy(() -> validator.validate(getUnsignedTokenString()))
            .isInstanceOf(TokenSignatureValidationException.class);
    }

    @Test
    void detectCorruptedToken() {
        assertThatThrownBy(() -> validator.validate(Tokens.CORRUPTED))
            .isInstanceOf(TokenParseException.class);
    }
}
