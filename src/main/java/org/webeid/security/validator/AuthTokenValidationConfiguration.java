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
import org.webeid.security.validator.ocsp.service.DesignatedOcspServiceConfiguration;
import org.webeid.security.validator.validators.OriginValidator;

import javax.cache.Cache;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;

import static org.webeid.security.nonce.NonceGeneratorBuilder.requirePositiveDuration;
import static org.webeid.security.validator.ocsp.OcspUrl.AIA_ESTEID_2015;
import static org.webeid.security.util.SubjectCertificatePolicies.*;

/**
 * Stores configuration parameters for {@link AuthTokenValidatorImpl}.
 */
public final class AuthTokenValidationConfiguration {

    private URI siteOrigin;
    private Cache<String, ZonedDateTime> nonceCache;
    private Collection<X509Certificate> trustedCACertificates = new HashSet<>();
    private boolean isUserCertificateRevocationCheckWithOcspEnabled = true;
    private Duration ocspRequestTimeout = Duration.ofSeconds(5);
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
    // Disable OCSP nonce extension for EstEID 2015 cards by default.
    private Collection<URI> nonceDisabledOcspUrls = Sets.newHashSet(AIA_ESTEID_2015);

    AuthTokenValidationConfiguration() {
    }

    private AuthTokenValidationConfiguration(AuthTokenValidationConfiguration other) {
        this.siteOrigin = other.siteOrigin;
        this.nonceCache = other.nonceCache;
        this.trustedCACertificates = Collections.unmodifiableSet(new HashSet<>(other.trustedCACertificates));
        this.isUserCertificateRevocationCheckWithOcspEnabled = other.isUserCertificateRevocationCheckWithOcspEnabled;
        this.ocspRequestTimeout = other.ocspRequestTimeout;
        this.designatedOcspServiceConfiguration = other.designatedOcspServiceConfiguration;
        this.isSiteCertificateFingerprintValidationEnabled = other.isSiteCertificateFingerprintValidationEnabled;
        this.siteCertificateSha256Fingerprint = other.siteCertificateSha256Fingerprint;
        this.disallowedSubjectCertificatePolicies = Collections.unmodifiableSet(new HashSet<>(other.disallowedSubjectCertificatePolicies));
        this.nonceDisabledOcspUrls = Collections.unmodifiableSet(new HashSet<>(other.nonceDisabledOcspUrls));
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

    public Collection<URI> getNonceDisabledOcspUrls() {
        return nonceDisabledOcspUrls;
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
        requirePositiveDuration(ocspRequestTimeout, "OCSP request timeout");
        if (isSiteCertificateFingerprintValidationEnabled) {
            Objects.requireNonNull(siteCertificateSha256Fingerprint, "Certificate fingerprint must not be null "
                + "when site certificate fingerprint validation is enabled");
        }
    }

    AuthTokenValidationConfiguration copy() {
        return new AuthTokenValidationConfiguration(this);
    }

}
