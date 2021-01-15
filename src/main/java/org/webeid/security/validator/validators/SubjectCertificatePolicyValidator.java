package org.webeid.security.validator.validators;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.webeid.security.exceptions.TokenValidationException;
import org.webeid.security.exceptions.UserCertificateDisallowedPolicyException;
import org.webeid.security.exceptions.UserCertificateInvalidPolicyException;
import org.webeid.security.validator.AuthTokenValidatorData;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;

public class SubjectCertificatePolicyValidator {

    private final Collection<ASN1ObjectIdentifier> disallowedSubjectCertificatePolicies;

    public SubjectCertificatePolicyValidator(Collection<ASN1ObjectIdentifier> disallowedSubjectCertificatePolicies) {
        this.disallowedSubjectCertificatePolicies = disallowedSubjectCertificatePolicies;
    }

    /**
     * Validates that the user certificate policies match the configured policies.
     *
     * @param actualTokenData authentication token data that contains the user certificate.
     * @throws UserCertificateDisallowedPolicyException when user certificate policy does not match the configured policies.
     * @throws UserCertificateInvalidPolicyException when user certificate policy is invalid.
     */
    public void validateCertificatePolicies(AuthTokenValidatorData actualTokenData) throws TokenValidationException {
        final X509Certificate certificate = actualTokenData.getSubjectCertificate();
        final byte[] extensionValue = certificate.getExtensionValue(Extension.certificatePolicies.getId());
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
            throw new UserCertificateInvalidPolicyException();
        }
    }
}
