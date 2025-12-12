// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.validator.certvalidators;

import eu.webeid.security.exceptions.AuthTokenException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import eu.webeid.security.exceptions.UserCertificateDisallowedPolicyException;
import eu.webeid.security.exceptions.UserCertificateParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;

public final class SubjectCertificatePolicyValidator {

    private static final Logger LOG = LoggerFactory.getLogger(SubjectCertificatePolicyValidator.class);

    private final Collection<ASN1ObjectIdentifier> disallowedSubjectCertificatePolicies;

    public SubjectCertificatePolicyValidator(Collection<ASN1ObjectIdentifier> disallowedSubjectCertificatePolicies) {
        this.disallowedSubjectCertificatePolicies = disallowedSubjectCertificatePolicies;
    }

    /**
     * Rejects any configured disallowed policy present in the certificate policies extension.
     * A certificate without the certificate policies extension does not contain disallowed policies and passes validation.
     *
     * @param subjectCertificate user certificate to be validated
     * @throws UserCertificateDisallowedPolicyException when a disallowed policy is present.
     * @throws UserCertificateParseException when the certificate policies extension is invalid.
     */
    public void validateCertificatePolicies(X509Certificate subjectCertificate) throws AuthTokenException {
        final byte[] extensionValue = subjectCertificate.getExtensionValue(Extension.certificatePolicies.getId());
        if (extensionValue == null) {
            LOG.debug("User certificate does not contain the certificate policies extension, hence it does not contain disallowed policies.");
            return;
        }
        try {
            final CertificatePolicies policies = CertificatePolicies.getInstance(
                JcaX509ExtensionUtils.parseExtensionValue(extensionValue)
            );
            if (policies == null) {
                throw new IllegalArgumentException("Certificate policies extension is empty");
            }
            if (Arrays.stream(policies.getPolicyInformation())
                    .anyMatch(policyInformation ->
                            disallowedSubjectCertificatePolicies.contains(policyInformation.getPolicyIdentifier()))) {
                throw new UserCertificateDisallowedPolicyException();
            }
        } catch (IOException | IllegalArgumentException e) {
            throw new UserCertificateParseException(e);
        }
        LOG.debug("User certificate does not contain disallowed policies.");
    }
}
