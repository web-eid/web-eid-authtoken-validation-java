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

package eu.webeid.security.validator;

import eu.webeid.security.certificate.SubjectCertificatePolicies;
import eu.webeid.security.validator.revocationcheck.CertificateRevocationChecker;
import eu.webeid.security.validator.revocationcheck.RevocationMode;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Stores configuration parameters for {@link AuthTokenValidatorImpl}.
 */
public final class AuthTokenValidationConfiguration {

    private URI siteOrigin;
    private Collection<X509Certificate> trustedCACertificates = new HashSet<>();
    // Don't allow Estonian Mobile-ID policy by default.
    private Collection<ASN1ObjectIdentifier> disallowedSubjectCertificatePolicies = new HashSet<>(Set.of(
        SubjectCertificatePolicies.ESTEID_SK_2015_MOBILE_ID_POLICY_V1,
        SubjectCertificatePolicies.ESTEID_SK_2015_MOBILE_ID_POLICY_V2,
        SubjectCertificatePolicies.ESTEID_SK_2015_MOBILE_ID_POLICY_V3,
        SubjectCertificatePolicies.ESTEID_SK_2015_MOBILE_ID_POLICY
    ));
    private boolean isUserCertificateRevocationCheckEnabled = true;
    private CertificateRevocationChecker certificateRevocationChecker;
    private PKIXRevocationChecker pkixRevocationChecker;
    private RevocationMode revocationMode = RevocationMode.PLATFORM_OCSP;

    AuthTokenValidationConfiguration() {
    }

    private AuthTokenValidationConfiguration(AuthTokenValidationConfiguration other) {
        this.siteOrigin = other.siteOrigin;
        this.trustedCACertificates = Set.copyOf(other.trustedCACertificates);
        this.disallowedSubjectCertificatePolicies = Set.copyOf(other.disallowedSubjectCertificatePolicies);
        this.isUserCertificateRevocationCheckEnabled = other.isUserCertificateRevocationCheckEnabled;
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

    public Collection<ASN1ObjectIdentifier> getDisallowedSubjectCertificatePolicies() {
        return disallowedSubjectCertificatePolicies;
    }

    boolean isUserCertificateRevocationCheckEnabled() {
        return isUserCertificateRevocationCheckEnabled;
    }

    void setUserCertificateRevocationCheckDisabled() {
        isUserCertificateRevocationCheckEnabled = false;
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
                                "Do not combine withoutUserCertificateRevocationCheck() with withOcspCertificateRevocationChecker(...) " +
                                "or withPKIXRevocationChecker(...)."
                );
            }
            revocationMode = RevocationMode.DISABLED;
        } else {
            // Revocation check enabled, at most one checker allowed, if no checker provided, use default PKIX revocation checker in OCSP mode.
            if (hasCustomChecker && hasPkixChecker) {
                throw new IllegalArgumentException(
                        "Only one of OcspCertificateRevocationChecker or PKIXRevocationChecker may be configured. " +
                                "Do not combine withOcspCertificateRevocationChecker(...) with withPKIXRevocationChecker(...)."
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
