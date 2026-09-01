// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.validator.certvalidators;

import eu.webeid.security.exceptions.AuthTokenException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import eu.webeid.security.exceptions.UserCertificateDisallowedPolicyException;
import eu.webeid.security.exceptions.UserCertificateParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;

public final class SubjectCertificatePolicyValidator {

    private static final Logger LOG = LoggerFactory.getLogger(SubjectCertificatePolicyValidator.class);

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
        LOG.debug("User certificate does not contain disallowed policies.");
    }
}
