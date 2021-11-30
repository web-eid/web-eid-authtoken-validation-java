/*
 * Copyright (c) 2020-2021 Estonian Information System Authority
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

import eu.webeid.security.exceptions.AuthTokenException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import eu.webeid.security.exceptions.UserCertificateDisallowedPolicyException;
import eu.webeid.security.exceptions.UserCertificateParseException;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;

public final class SubjectCertificatePolicyValidator {

    private final Collection<ASN1ObjectIdentifier> disallowedSubjectCertificatePolicies;

    public SubjectCertificatePolicyValidator(Collection<ASN1ObjectIdentifier> disallowedSubjectCertificatePolicies) {
        this.disallowedSubjectCertificatePolicies = disallowedSubjectCertificatePolicies;
    }

    /**
     * Validates that the user certificate policies match the configured policies.
     *
     * @param subjectCertificate user certificate to be validated
     * @throws UserCertificateDisallowedPolicyException when user certificate policy does not match the configured policies.
     * @throws UserCertificateParseException when user certificate policy is invalid.
     */
    public void validateCertificatePolicies(X509Certificate subjectCertificate) throws AuthTokenException {
        final byte[] extensionValue = subjectCertificate.getExtensionValue(Extension.certificatePolicies.getId());
        try {
            final CertificatePolicies policies = CertificatePolicies.getInstance(
                JcaX509ExtensionUtils.parseExtensionValue(extensionValue)
            );
            final Optional<PolicyInformation> disallowedPolicy = Arrays.stream(policies.getPolicyInformation())
                .filter(policyInformation ->
                    disallowedSubjectCertificatePolicies.contains(policyInformation.getPolicyIdentifier()))
                .findFirst();
            if (disallowedPolicy.isPresent()) {
                throw new UserCertificateDisallowedPolicyException();
            }
        } catch (IOException e) {
            throw new UserCertificateParseException(e);
        }
    }
}
