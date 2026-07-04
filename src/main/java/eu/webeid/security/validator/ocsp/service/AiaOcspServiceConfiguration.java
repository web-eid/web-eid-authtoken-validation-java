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

package eu.webeid.security.validator.ocsp.service;

import java.net.URI;
import java.security.cert.CertStore;
import java.security.cert.TrustAnchor;
import java.util.Collection;
import java.util.Objects;
import java.util.Set;

public class AiaOcspServiceConfiguration {

    /**
     * Determines how the issuer authorizing an AIA OCSP responder is matched against the subject certificate's
     * issuer.
     */
    public enum ResponderIssuerMatchingPolicy {
        /** Requires the same encoded X.509 certificate. */
        EXACT_CERTIFICATE,
        /**
         * Accepts different certificates that contain the same subject and public key. Non-anchor intermediate
         * certificates in the responder's certification path are checked for revocation.
         */
        SUBJECT_AND_PUBLIC_KEY
    }

    private final Collection<URI> nonceDisabledOcspUrls;
    private final Set<TrustAnchor> trustedCACertificateAnchors;
    private final CertStore trustedCACertificateCertStore;
    private final ResponderIssuerMatchingPolicy responderIssuerMatchingPolicy;

    public AiaOcspServiceConfiguration(Collection<URI> nonceDisabledOcspUrls, Set<TrustAnchor> trustedCACertificateAnchors, CertStore trustedCACertificateCertStore) {
        this(nonceDisabledOcspUrls, trustedCACertificateAnchors, trustedCACertificateCertStore,
            ResponderIssuerMatchingPolicy.EXACT_CERTIFICATE);
    }

    public AiaOcspServiceConfiguration(Collection<URI> nonceDisabledOcspUrls,
                                       Set<TrustAnchor> trustedCACertificateAnchors,
                                       CertStore trustedCACertificateCertStore,
                                       ResponderIssuerMatchingPolicy responderIssuerMatchingPolicy) {
        this.nonceDisabledOcspUrls = Objects.requireNonNull(nonceDisabledOcspUrls);
        this.trustedCACertificateAnchors = Objects.requireNonNull(trustedCACertificateAnchors);
        this.trustedCACertificateCertStore = Objects.requireNonNull(trustedCACertificateCertStore);
        this.responderIssuerMatchingPolicy = Objects.requireNonNull(responderIssuerMatchingPolicy);
    }

    public Collection<URI> getNonceDisabledOcspUrls() {
        return nonceDisabledOcspUrls;
    }

    public Set<TrustAnchor> getTrustedCACertificateAnchors() {
        return trustedCACertificateAnchors;
    }

    public CertStore getTrustedCACertificateCertStore() {
        return trustedCACertificateCertStore;
    }

    public ResponderIssuerMatchingPolicy getResponderIssuerMatchingPolicy() {
        return responderIssuerMatchingPolicy;
    }

}
