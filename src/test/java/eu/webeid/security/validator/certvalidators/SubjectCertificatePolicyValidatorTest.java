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

package eu.webeid.security.validator.certvalidators;

import eu.webeid.security.exceptions.UserCertificateDisallowedPolicyException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.junit.jupiter.api.Test;

import java.util.List;

import static eu.webeid.security.testutil.Certificates.getCertificateWithoutCertificatePolicies;
import static eu.webeid.security.testutil.Certificates.getJaakKristjanEsteid2018Cert;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class SubjectCertificatePolicyValidatorTest {

    private static final ASN1ObjectIdentifier ESTEID2018_POLICY = new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.2.1");
    private static final ASN1ObjectIdentifier UNRELATED_POLICY = new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.2.2");

    @Test
    void whenCertificateContainsDisallowedPolicy_thenValidationFails() throws Exception {
        final SubjectCertificatePolicyValidator validator = new SubjectCertificatePolicyValidator(List.of(ESTEID2018_POLICY));
        assertThatExceptionOfType(UserCertificateDisallowedPolicyException.class)
            .isThrownBy(() -> validator.validateCertificatePolicies(getJaakKristjanEsteid2018Cert()));
    }

    @Test
    void whenCertificateDoesNotContainDisallowedPolicies_thenValidationSucceeds() throws Exception {
        final SubjectCertificatePolicyValidator validator = new SubjectCertificatePolicyValidator(List.of(UNRELATED_POLICY));
        assertThatCode(() -> validator.validateCertificatePolicies(getJaakKristjanEsteid2018Cert()))
            .doesNotThrowAnyException();
    }

    @Test
    void whenCertificateDoesNotContainCertificatePoliciesExtension_thenValidationSucceeds() throws Exception {
        final SubjectCertificatePolicyValidator validator = new SubjectCertificatePolicyValidator(List.of(ESTEID2018_POLICY));
        assertThatCode(() -> validator.validateCertificatePolicies(getCertificateWithoutCertificatePolicies()))
            .doesNotThrowAnyException();
    }

}
