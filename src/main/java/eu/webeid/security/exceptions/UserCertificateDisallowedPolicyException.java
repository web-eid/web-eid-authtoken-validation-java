// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.exceptions;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import javax.security.auth.x500.X500Principal;
import java.util.Collection;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Thrown when the user certificate does not satisfy the configured allowed or disallowed policy restrictions.
 */
public class UserCertificateDisallowedPolicyException extends AuthTokenException {

    private final transient X500Principal certificateIssuer;
    private final transient Set<ASN1ObjectIdentifier> certificatePolicies;

    /**
     * Creates an exception without allow-list configuration details.
     */
    public UserCertificateDisallowedPolicyException() {
        super("Disallowed user certificate policy");
        certificateIssuer = null;
        certificatePolicies = Set.of();
    }

    /**
     * Creates an exception with the certificate details that failed allow-list validation.
     *
     * @param certificateIssuer certificate issuer
     * @param certificatePolicies policies presented by the certificate
     */
    public UserCertificateDisallowedPolicyException(
            X500Principal certificateIssuer,
            Collection<ASN1ObjectIdentifier> certificatePolicies) {
        super("Disallowed user certificate policy");
        this.certificateIssuer = Objects.requireNonNull(certificateIssuer);
        this.certificatePolicies = Set.copyOf(Objects.requireNonNull(certificatePolicies));
    }

    /**
     * Returns the certificate issuer for an allow-list validation failure.
     *
     * @return certificate issuer, or empty when no allow-list details are available
     */
    public Optional<X500Principal> getCertificateIssuer() {
        return Optional.ofNullable(certificateIssuer);
    }

    /**
     * Returns the policies presented by the certificate during an allow-list validation failure.
     *
     * @return immutable set of certificate policies, possibly empty
     */
    public Set<ASN1ObjectIdentifier> getCertificatePolicies() {
        return certificatePolicies;
    }
}
