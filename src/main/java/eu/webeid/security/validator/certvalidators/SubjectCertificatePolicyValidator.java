// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.validator.certvalidators;

import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.exceptions.UserCertificateDisallowedPolicyException;
import eu.webeid.security.exceptions.UserCertificateParseException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public final class SubjectCertificatePolicyValidator {

    private static final Logger LOG = LoggerFactory.getLogger(SubjectCertificatePolicyValidator.class);

    private final Map<X500Principal, Set<ASN1ObjectIdentifier>> allowedSubjectCertificatePolicies;
    private final Collection<ASN1ObjectIdentifier> disallowedSubjectCertificatePolicies;

    /**
     * @deprecated Configure both allowed and fallback disallowed policies with
     * {@link #SubjectCertificatePolicyValidator(Map, Collection)}.
     */
    @Deprecated(since = "4.0.0")
    public SubjectCertificatePolicyValidator(Collection<ASN1ObjectIdentifier> disallowedSubjectCertificatePolicies) {
        this(Map.of(), disallowedSubjectCertificatePolicies);
    }

    public SubjectCertificatePolicyValidator(
            Map<X500Principal, ? extends Collection<ASN1ObjectIdentifier>> allowedSubjectCertificatePolicies,
            Collection<ASN1ObjectIdentifier> disallowedSubjectCertificatePolicies) {
        this.allowedSubjectCertificatePolicies = copyAllowedSubjectCertificatePolicies(allowedSubjectCertificatePolicies);
        this.disallowedSubjectCertificatePolicies = Set.copyOf(disallowedSubjectCertificatePolicies);
    }

    /**
     * Requires a configured allowed policy when the certificate issuer has an allow-list entry.
     * Otherwise, rejects any configured disallowed policy present in the certificate policies extension.
     * A certificate without the certificate policies extension passes only when its issuer has no allow-list entry.
     *
     * @param subjectCertificate user certificate to be validated
     * @throws UserCertificateDisallowedPolicyException when no allowed policy is present or a disallowed policy is present.
     * @throws UserCertificateParseException when the certificate policies extension is invalid.
     */
    public void validateCertificatePolicies(X509Certificate subjectCertificate) throws AuthTokenException {
        final X500Principal issuer = subjectCertificate.getIssuerX500Principal();
        final byte[] extensionValue = subjectCertificate.getExtensionValue(Extension.certificatePolicies.getId());
        final Collection<ASN1ObjectIdentifier> issuerAllowedPolicies = allowedSubjectCertificatePolicies.getOrDefault(issuer, Set.of());

        if (extensionValue == null) {
            if (!issuerAllowedPolicies.isEmpty()) {
                LOG.debug("User certificate does not contain the certificate policies extension, hence it does not contain an allowed policy.");
                throw new UserCertificateDisallowedPolicyException();
            }
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
            if (!issuerAllowedPolicies.isEmpty()) {
                if (Arrays.stream(policies.getPolicyInformation())
                        .noneMatch(policyInformation ->
                            issuerAllowedPolicies.contains(policyInformation.getPolicyIdentifier()))) {
                    throw new UserCertificateDisallowedPolicyException();
                }
                LOG.debug("User certificate contains a policy allowed for issuer '{}'.", issuer);
                return;
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

    private static Map<X500Principal, Set<ASN1ObjectIdentifier>> copyAllowedSubjectCertificatePolicies(
            Map<X500Principal, ? extends Collection<ASN1ObjectIdentifier>> policiesByIssuer) {
        final Map<X500Principal, Set<ASN1ObjectIdentifier>> copy = new HashMap<>();
        policiesByIssuer.forEach((issuer, policies) -> copy.put(
            Objects.requireNonNull(issuer, "Issuer must not be null"),
            Set.copyOf(Objects.requireNonNull(policies, "Allowed certificate policies must not be null"))
        ));
        return Map.copyOf(copy);
    }
}
