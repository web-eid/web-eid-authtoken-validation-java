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

package eu.webeid.security.validator;

import com.google.common.collect.Sets;
import eu.webeid.security.util.SubjectCertificatePolicies;
import eu.webeid.security.validator.ocsp.service.DesignatedOcspServiceConfiguration;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;

import static eu.webeid.security.util.DateAndTime.requirePositiveDuration;
import static eu.webeid.security.validator.ocsp.OcspUrl.AIA_ESTEID_2015;

/**
 * Stores configuration parameters for {@link AuthTokenValidatorImpl}.
 */
public final class AuthTokenValidationConfiguration {

    private URI siteOrigin;
    private Collection<X509Certificate> trustedCACertificates = new HashSet<>();
    private boolean isUserCertificateRevocationCheckWithOcspEnabled = true;
    private Duration ocspRequestTimeout = Duration.ofSeconds(5);
    private DesignatedOcspServiceConfiguration designatedOcspServiceConfiguration;
    // Don't allow Estonian Mobile-ID policy by default.
    private Collection<ASN1ObjectIdentifier> disallowedSubjectCertificatePolicies = Sets.newHashSet(
        SubjectCertificatePolicies.ESTEID_SK_2015_MOBILE_ID_POLICY_V1,
        SubjectCertificatePolicies.ESTEID_SK_2015_MOBILE_ID_POLICY_V2,
        SubjectCertificatePolicies.ESTEID_SK_2015_MOBILE_ID_POLICY_V3,
        SubjectCertificatePolicies.ESTEID_SK_2015_MOBILE_ID_POLICY
    );
    // Disable OCSP nonce extension for EstEID 2015 cards by default.
    private Collection<URI> nonceDisabledOcspUrls = Sets.newHashSet(AIA_ESTEID_2015);

    AuthTokenValidationConfiguration() {
    }

    private AuthTokenValidationConfiguration(AuthTokenValidationConfiguration other) {
        this.siteOrigin = other.siteOrigin;
        this.trustedCACertificates = Collections.unmodifiableSet(new HashSet<>(other.trustedCACertificates));
        this.isUserCertificateRevocationCheckWithOcspEnabled = other.isUserCertificateRevocationCheckWithOcspEnabled;
        this.ocspRequestTimeout = other.ocspRequestTimeout;
        this.designatedOcspServiceConfiguration = other.designatedOcspServiceConfiguration;
        this.disallowedSubjectCertificatePolicies = Collections.unmodifiableSet(new HashSet<>(other.disallowedSubjectCertificatePolicies));
        this.nonceDisabledOcspUrls = Collections.unmodifiableSet(new HashSet<>(other.nonceDisabledOcspUrls));
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
        validateIsOriginURL(siteOrigin);
        if (trustedCACertificates.isEmpty()) {
            throw new IllegalArgumentException("At least one trusted certificate authority must be provided");
        }
        requirePositiveDuration(ocspRequestTimeout, "OCSP request timeout");
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
}
