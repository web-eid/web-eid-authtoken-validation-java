/*
 * Copyright (c) 2020, 2021 The Web eID Project
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

package org.webeid.security.validator;

import com.google.common.collect.Sets;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.webeid.security.validator.ocsp.service.AiaOcspServiceConfiguration;
import org.webeid.security.validator.ocsp.service.DesignatedOcspServiceConfiguration;
import org.webeid.security.validator.validators.OriginValidator;

import javax.cache.Cache;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.Collection;
import java.util.HashSet;
import java.util.Objects;

import static org.webeid.security.nonce.NonceGeneratorBuilder.requirePositiveDuration;
import static org.webeid.security.util.SubjectCertificatePolicies.ESTEID_SK_2015_MOBILE_ID_POLICY;
import static org.webeid.security.util.SubjectCertificatePolicies.ESTEID_SK_2015_MOBILE_ID_POLICY_V1;
import static org.webeid.security.util.SubjectCertificatePolicies.ESTEID_SK_2015_MOBILE_ID_POLICY_V2;
import static org.webeid.security.util.SubjectCertificatePolicies.ESTEID_SK_2015_MOBILE_ID_POLICY_V3;

/**
 * Stores configuration parameters for {@link AuthTokenValidatorImpl}.
 */
final class AuthTokenValidationConfiguration {

    private URI siteOrigin;
    private Cache<String, ZonedDateTime> nonceCache;
    private Collection<X509Certificate> trustedCACertificates = new HashSet<>();
    private boolean isUserCertificateRevocationCheckWithOcspEnabled = true;
    private Duration ocspRequestTimeout = Duration.ofSeconds(5);
    private Duration allowedClientClockSkew = Duration.ofMinutes(3);
    private AiaOcspServiceConfiguration aiaOcspServiceConfiguration;
    private DesignatedOcspServiceConfiguration designatedOcspServiceConfiguration;
    private boolean isSiteCertificateFingerprintValidationEnabled = false;
    private String siteCertificateSha256Fingerprint;
    // Don't allow Estonian Mobile-ID policy by default.
    private Collection<ASN1ObjectIdentifier> disallowedSubjectCertificatePolicies = Sets.newHashSet(
        ESTEID_SK_2015_MOBILE_ID_POLICY_V1,
        ESTEID_SK_2015_MOBILE_ID_POLICY_V2,
        ESTEID_SK_2015_MOBILE_ID_POLICY_V3,
        ESTEID_SK_2015_MOBILE_ID_POLICY
    );

    AuthTokenValidationConfiguration() {
    }

    private AuthTokenValidationConfiguration(AuthTokenValidationConfiguration other) {
        this.siteOrigin = other.siteOrigin;
        this.nonceCache = other.nonceCache;
        this.trustedCACertificates = new HashSet<>(other.trustedCACertificates);
        this.isUserCertificateRevocationCheckWithOcspEnabled = other.isUserCertificateRevocationCheckWithOcspEnabled;
        this.ocspRequestTimeout = other.ocspRequestTimeout;
        this.allowedClientClockSkew = other.allowedClientClockSkew;
        this.aiaOcspServiceConfiguration = other.aiaOcspServiceConfiguration;
        this.designatedOcspServiceConfiguration = other.designatedOcspServiceConfiguration;
        this.isSiteCertificateFingerprintValidationEnabled = other.isSiteCertificateFingerprintValidationEnabled;
        this.siteCertificateSha256Fingerprint = other.siteCertificateSha256Fingerprint;
        this.disallowedSubjectCertificatePolicies = new HashSet<>(other.disallowedSubjectCertificatePolicies);
    }

    void setSiteOrigin(URI siteOrigin) {
        this.siteOrigin = siteOrigin;
    }

    URI getSiteOrigin() {
        return siteOrigin;
    }

    void setNonceCache(Cache<String, ZonedDateTime> nonceCache) {
        this.nonceCache = nonceCache;
    }

    Cache<String, ZonedDateTime> getNonceCache() {
        return nonceCache;
    }

    Collection<X509Certificate> getTrustedCACertificates() {
        return trustedCACertificates;
    }

    boolean isUserCertificateRevocationCheckWithOcspEnabled() {
        return isUserCertificateRevocationCheckWithOcspEnabled;
    }

    void setUserCertificateRevocationCheckWithOcspDisabled() {
        isUserCertificateRevocationCheckWithOcspEnabled = false;
    }

    public Duration getOcspRequestTimeout() {
        return ocspRequestTimeout;
    }

    void setOcspRequestTimeout(Duration ocspRequestTimeout) {
        this.ocspRequestTimeout = ocspRequestTimeout;
    }

    void setAllowedClientClockSkew(Duration allowedClientClockSkew) {
        this.allowedClientClockSkew = allowedClientClockSkew;
    }

    Duration getAllowedClientClockSkew() {
        return allowedClientClockSkew;
    }

    public AiaOcspServiceConfiguration getAiaOcspServiceConfiguration() {
        return aiaOcspServiceConfiguration;
    }

    public void setAiaOcspServiceConfiguration(AiaOcspServiceConfiguration aiaOcspServiceConfiguration) {
        this.aiaOcspServiceConfiguration = aiaOcspServiceConfiguration;
    }

    public DesignatedOcspServiceConfiguration getDesignatedOcspServiceConfiguration() {
        return designatedOcspServiceConfiguration;
    }

    public void setDesignatedOcspServiceConfiguration(DesignatedOcspServiceConfiguration designatedOcspServiceConfiguration) {
        this.designatedOcspServiceConfiguration = designatedOcspServiceConfiguration;
    }

    boolean isSiteCertificateFingerprintValidationEnabled() {
        return isSiteCertificateFingerprintValidationEnabled;
    }

    public void setSiteCertificateSha256Fingerprint(String siteCertificateSha256Fingerprint) {
        isSiteCertificateFingerprintValidationEnabled = true;
        this.siteCertificateSha256Fingerprint = siteCertificateSha256Fingerprint;
    }

    public String getSiteCertificateSha256Fingerprint() {
        return siteCertificateSha256Fingerprint;
    }

    public Collection<ASN1ObjectIdentifier> getDisallowedSubjectCertificatePolicies() {
        return disallowedSubjectCertificatePolicies;
    }

    /**
     * Checks that the configuration parameters are valid.
     *
     * @throws NullPointerException     when required parameters are null
     * @throws IllegalArgumentException when any parameter is invalid
     */
    void validate() {
        Objects.requireNonNull(siteOrigin, "Origin URI must not be null");
        OriginValidator.validateIsOriginURL(siteOrigin);
        Objects.requireNonNull(nonceCache, "Nonce cache must not be null");
        if (trustedCACertificates.isEmpty()) {
            throw new IllegalArgumentException("At least one trusted certificate authority must be provided");
        }
        if (isUserCertificateRevocationCheckWithOcspEnabled) {
            if (aiaOcspServiceConfiguration == null && designatedOcspServiceConfiguration == null) {
                throw new IllegalArgumentException("Either AIA or designated OCSP service configuration must be provided");
            }
            if (aiaOcspServiceConfiguration != null && designatedOcspServiceConfiguration != null) {
                throw new IllegalArgumentException("AIA and designated OCSP service configuration cannot provided together, " +
                    "please provide either one or the other");
            }
        } else if (aiaOcspServiceConfiguration != null || designatedOcspServiceConfiguration != null) {
            throw new IllegalArgumentException("When user certificate OCSP check is disabled, " +
                "AIA or designated OCSP service configuration should not be provided");
        }
        requirePositiveDuration(ocspRequestTimeout, "OCSP request timeout");
        requirePositiveDuration(allowedClientClockSkew, "Allowed client clock skew");
        if (isSiteCertificateFingerprintValidationEnabled) {
            Objects.requireNonNull(siteCertificateSha256Fingerprint, "Certificate fingerprint must not be null "
                + "when site certificate fingerprint validation is enabled");
        }
    }

    AuthTokenValidationConfiguration copy() {
        return new AuthTokenValidationConfiguration(this);
    }

}
