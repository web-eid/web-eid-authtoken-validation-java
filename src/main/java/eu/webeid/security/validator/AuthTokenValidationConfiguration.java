// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.validator;

import eu.webeid.security.validator.revocationcheck.CertificateRevocationChecker;
import eu.webeid.security.validator.revocationcheck.RevocationMode;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import javax.security.auth.x500.X500Principal;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Stores configuration parameters for {@link AuthTokenValidatorImpl}.
 */
public final class AuthTokenValidationConfiguration {

    private URI siteOrigin;
    private Collection<X509Certificate> trustedCACertificates = new HashSet<>();
    private Map<X500Principal, Set<ASN1ObjectIdentifier>> allowedSubjectCertificatePolicies = new HashMap<>();
    @Deprecated(since = "4.0.0")
    private Collection<ASN1ObjectIdentifier> disallowedSubjectCertificatePolicies = new HashSet<>();
    private boolean isUserCertificateRevocationCheckEnabled = true;
    private boolean platformOcspNonceEnabled = true;
    private CertificateRevocationChecker certificateRevocationChecker;
    private PKIXRevocationChecker pkixRevocationChecker;
    private RevocationMode revocationMode = RevocationMode.PLATFORM_OCSP;

    AuthTokenValidationConfiguration() {
    }

    private AuthTokenValidationConfiguration(AuthTokenValidationConfiguration other) {
        this.siteOrigin = other.siteOrigin;
        this.trustedCACertificates = Set.copyOf(other.trustedCACertificates);
        this.allowedSubjectCertificatePolicies =
            copyAllowedSubjectCertificatePolicies(other.allowedSubjectCertificatePolicies);
        this.disallowedSubjectCertificatePolicies = Set.copyOf(other.disallowedSubjectCertificatePolicies);
        this.isUserCertificateRevocationCheckEnabled = other.isUserCertificateRevocationCheckEnabled;
        this.platformOcspNonceEnabled = other.platformOcspNonceEnabled;
        this.certificateRevocationChecker = other.certificateRevocationChecker;
        this.pkixRevocationChecker = other.pkixRevocationChecker;
        this.revocationMode = other.revocationMode;
    }

    void setSiteOrigin(URI siteOrigin) {
        this.siteOrigin = siteOrigin;
    }

    URI getSiteOrigin() {
        return siteOrigin;
    }

    Collection<X509Certificate> getTrustedCACertificates() {
        return trustedCACertificates;
    }

    public Map<X500Principal, Set<ASN1ObjectIdentifier>> getAllowedSubjectCertificatePolicies() {
        return allowedSubjectCertificatePolicies;
    }

    void setAllowedSubjectCertificatePolicies(
            X500Principal issuer, Collection<ASN1ObjectIdentifier> allowedSubjectCertificatePolicies) {
        Objects.requireNonNull(issuer, "Issuer must not be null");
        final Set<ASN1ObjectIdentifier> policies = Set.copyOf(Objects.requireNonNull(
            allowedSubjectCertificatePolicies,
            "Allowed certificate policies must not be null"
        ));
        if (policies.isEmpty()) {
            this.allowedSubjectCertificatePolicies.remove(issuer);
        } else {
            this.allowedSubjectCertificatePolicies.put(issuer, policies);
        }
    }

    /**
     * @deprecated Configure allowed certificate policies instead.
     */
    @Deprecated(since = "4.0.0")
    public Collection<ASN1ObjectIdentifier> getDisallowedSubjectCertificatePolicies() {
        return disallowedSubjectCertificatePolicies;
    }

    boolean isUserCertificateRevocationCheckEnabled() {
        return isUserCertificateRevocationCheckEnabled;
    }

    void setUserCertificateRevocationCheckDisabled() {
        isUserCertificateRevocationCheckEnabled = false;
    }

    boolean isPlatformOcspNonceEnabled() {
        return platformOcspNonceEnabled;
    }

    void setPlatformOcspNonceEnabled(boolean enabled) {
        platformOcspNonceEnabled = enabled;
    }

    public void setCertificateRevocationChecker(CertificateRevocationChecker certificateRevocationChecker) {
        this.certificateRevocationChecker = certificateRevocationChecker;
    }

    public CertificateRevocationChecker getCertificateRevocationChecker() {
        return certificateRevocationChecker;
    }

    public void setPkixRevocationChecker(PKIXRevocationChecker pkixRevocationChecker) {
        this.pkixRevocationChecker = pkixRevocationChecker;
    }

    public PKIXRevocationChecker getPkixRevocationChecker() {
        return pkixRevocationChecker;
    }

    public RevocationMode getRevocationMode() {
        return revocationMode;
    }

    /**
     * Checks that the configuration parameters are valid.
     *
     * @throws IllegalArgumentException when any parameter is invalid
     */
    void validate() {
        validateIsOriginURL(siteOrigin);
        if (trustedCACertificates.isEmpty()) {
            throw new IllegalArgumentException("At least one trusted certificate authority must be provided");
        }
        validateRevocationConfiguration();
    }

    AuthTokenValidationConfiguration copy() {
        return new AuthTokenValidationConfiguration(this);
    }

    private static Map<X500Principal, Set<ASN1ObjectIdentifier>> copyAllowedSubjectCertificatePolicies(
            Map<X500Principal, ? extends Collection<ASN1ObjectIdentifier>> policiesByIssuer) {
        final Map<X500Principal, Set<ASN1ObjectIdentifier>> copy = new HashMap<>();
        policiesByIssuer.forEach((issuer, policies) -> copy.put(
            Objects.requireNonNull(issuer, "Issuer must not be null"),
            Set.copyOf(Objects.requireNonNull(policies, "Allowed certificate policies must not be null"))
        ));
        return copy;
    }

    /**
     * Validates that the given URI is an origin URL as defined in <a href="https://developer.mozilla.org/en-US/docs/Web/API/Location/origin">MDN</a>,
     * in the form of {@code <scheme> "://" <hostname> [ ":" <port> ]}.
     *
     * @param uri URI with origin URL
     * @throws IllegalArgumentException when the URI is not in the form of origin URL
     */
    public static void validateIsOriginURL(URI uri) throws IllegalArgumentException {
        try {
            if (uri == null) {
                throw new IllegalArgumentException("Origin URI must not be null");
            }
            // 1. Verify that the URI can be converted to absolute URL.
            uri.toURL();
            // 2. Verify that the URI contains only HTTPS scheme, host and optional port components.
            if (!new URI("https", null, uri.getHost(), uri.getPort(), null, null, null)
                .equals(uri)) {
                throw new IllegalArgumentException("Origin URI must only contain the HTTPS scheme, host and optional port component");
            }
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Provided URI is not a valid URL");
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("An URI syntax exception occurred");
        }
    }

    /**
     * Validates that the revocation check configuration is consistent and derives the {@link RevocationMode} from it.
     * <p>
     * Configuration is inconsistent if revocation checking is disabled but a checker is configured or if both
     * checkers are configured simultaneously.
     *
     * @throws IllegalArgumentException if configuration is inconsistent
     */
    private void validateRevocationConfiguration() {
        final boolean hasCustomChecker = certificateRevocationChecker != null;
        final boolean hasPkixChecker = pkixRevocationChecker != null;

        if (!isUserCertificateRevocationCheckEnabled) {
            if (hasCustomChecker || hasPkixChecker) {
                throw new IllegalArgumentException(
                        "User certificate revocation check is disabled, but a revocation checker was configured. " +
                                "Do not combine withoutUserCertificateRevocationCheck() with withCertificateRevocationChecker(...) " +
                                "or withPKIXRevocationChecker(...)."
                );
            }
            revocationMode = RevocationMode.DISABLED;
        } else {
            // Revocation check enabled, at most one checker allowed, if no checker provided, use default PKIX revocation checker in OCSP mode.
            if (hasCustomChecker && hasPkixChecker) {
                throw new IllegalArgumentException(
                        "Do not combine withCertificateRevocationChecker(...) with withPKIXRevocationChecker(...)."
                );
            }
            if (hasCustomChecker) {
                revocationMode = RevocationMode.CUSTOM_CHECKER;
            } else if (hasPkixChecker) {
                revocationMode = RevocationMode.CUSTOM_PKIX;
            } else {
                revocationMode = RevocationMode.PLATFORM_OCSP;
            }
        }
    }
}
