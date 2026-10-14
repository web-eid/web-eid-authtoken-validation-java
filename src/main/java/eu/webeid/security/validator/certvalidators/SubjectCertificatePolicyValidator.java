// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.validator.certvalidators;

import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.exceptions.UserCertificateDisallowedPolicyException;
import eu.webeid.security.exceptions.UserCertificateParseException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;
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
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public final class SubjectCertificatePolicyValidator {

    private static final Logger LOG = LoggerFactory.getLogger(SubjectCertificatePolicyValidator.class);

    private final Map<X500Principal, Set<ASN1ObjectIdentifier>> allowedSubjectCertificatePolicies;
    private final Collection<ASN1ObjectIdentifier> disallowedSubjectCertificatePolicies;
    private final boolean allowUnlistedIssuers;

    /**
     * @deprecated Configure both allowed and fallback disallowed policies with
     * {@link #SubjectCertificatePolicyValidator(Map, Collection)}.
     */
    @Deprecated(since = "4.0.0")
    public SubjectCertificatePolicyValidator(Collection<ASN1ObjectIdentifier> disallowedSubjectCertificatePolicies) {
        this(Map.of(), disallowedSubjectCertificatePolicies, false);
    }

    /**
     * Creates a validator with strict allow-list validation enabled.
     *
     * @param allowedSubjectCertificatePolicies allowed policies grouped by exact certificate issuer
     * @param disallowedSubjectCertificatePolicies fallback disallowed policies
     * @throws IllegalArgumentException if a listed issuer has no allowed policies
     */
    public SubjectCertificatePolicyValidator(
            Map<X500Principal, ? extends Collection<ASN1ObjectIdentifier>> allowedSubjectCertificatePolicies,
            Collection<ASN1ObjectIdentifier> disallowedSubjectCertificatePolicies) {
        this(allowedSubjectCertificatePolicies, disallowedSubjectCertificatePolicies, false);
    }

    /**
     * @param allowedSubjectCertificatePolicies allowed policies grouped by exact certificate issuer
     * @param disallowedSubjectCertificatePolicies fallback disallowed policies
     * @param allowUnlistedIssuers whether an active allow-list accepts unlisted issuers
     * @throws IllegalArgumentException if a listed issuer has no allowed policies
     */
    public SubjectCertificatePolicyValidator(
            Map<X500Principal, ? extends Collection<ASN1ObjectIdentifier>> allowedSubjectCertificatePolicies,
            Collection<ASN1ObjectIdentifier> disallowedSubjectCertificatePolicies,
            boolean allowUnlistedIssuers) {
        this.allowedSubjectCertificatePolicies = copyAllowedSubjectCertificatePolicies(allowedSubjectCertificatePolicies);
        this.disallowedSubjectCertificatePolicies = Set.copyOf(disallowedSubjectCertificatePolicies);
        this.allowUnlistedIssuers = allowUnlistedIssuers;
    }

    /**
     * Requires a configured allowed policy when the certificate issuer has an allow-list entry. In strict mode,
     * a certificate is also rejected when an allow-list exists but its issuer has no entry.
     * Otherwise, rejects any configured disallowed policy present in the certificate policies extension.
     * A certificate without the certificate policies extension passes only when its issuer is not subject to
     * allow-list validation.
     *
     * @param subjectCertificate user certificate to be validated
     * @throws UserCertificateDisallowedPolicyException when no allowed policy is present or a disallowed policy is present.
     * @throws UserCertificateParseException when the certificate policies extension is invalid.
     */
    public void validateCertificatePolicies(X509Certificate subjectCertificate) throws AuthTokenException {
        final X500Principal issuer = subjectCertificate.getIssuerX500Principal();
        final Optional<Set<ASN1ObjectIdentifier>> issuerAllowedPolicies =
            Optional.ofNullable(allowedSubjectCertificatePolicies.get(issuer));
        if (!allowUnlistedIssuers
                && !allowedSubjectCertificatePolicies.isEmpty()
                && issuerAllowedPolicies.isEmpty()) {
            LOG.debug("User certificate issuer '{}' does not have an allow-list entry.", issuer);
            throw new UserCertificateDisallowedPolicyException(issuer, Set.of());
        }
        final byte[] extensionValue = subjectCertificate.getExtensionValue(Extension.certificatePolicies.getId());

        if (extensionValue == null) {
            if (issuerAllowedPolicies.isPresent()) {
                LOG.debug("User certificate does not contain the certificate policies extension, hence it does not contain an allowed policy.");
                throw new UserCertificateDisallowedPolicyException(issuer, Set.of());
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
            if (issuerAllowedPolicies.isPresent()) {
                final Set<ASN1ObjectIdentifier> allowedPolicies = issuerAllowedPolicies.get();
                if (Arrays.stream(policies.getPolicyInformation())
                        .noneMatch(policyInformation ->
                            allowedPolicies.contains(policyInformation.getPolicyIdentifier()))) {
                    throw new UserCertificateDisallowedPolicyException(
                        issuer,
                        Arrays.stream(policies.getPolicyInformation())
                            .map(PolicyInformation::getPolicyIdentifier)
                            .collect(Collectors.toUnmodifiableSet())
                    );
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
        policiesByIssuer.forEach((issuer, policies) -> {
            Objects.requireNonNull(issuer, "Issuer must not be null");
            final Set<ASN1ObjectIdentifier> allowedPolicies = Set.copyOf(
                Objects.requireNonNull(policies, "Allowed certificate policies must not be null")
            );
            if (allowedPolicies.isEmpty()) {
                throw new IllegalArgumentException(
                    "At least one allowed certificate policy is required for issuer " + issuer.getName()
                );
            }
            copy.put(issuer, allowedPolicies);
        });
        return Map.copyOf(copy);
    }
}
