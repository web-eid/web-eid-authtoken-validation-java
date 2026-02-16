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

package eu.webeid.ocsp.service;

import java.security.cert.CertStore;
import java.security.cert.TrustAnchor;
import java.util.Collection;
import java.util.Objects;
import java.util.Set;

public class AiaOcspServiceConfiguration {

    private final Collection<String> nonceDisabledIssuerCNs;
    private final Set<TrustAnchor> trustedCACertificateAnchors;
    private final CertStore trustedCACertificateCertStore;

    public AiaOcspServiceConfiguration(Collection<String> nonceDisabledIssuerCNs, Set<TrustAnchor> trustedCACertificateAnchors, CertStore trustedCACertificateCertStore) {
        this.nonceDisabledIssuerCNs = Objects.requireNonNull(nonceDisabledIssuerCNs);
        this.trustedCACertificateAnchors = Objects.requireNonNull(trustedCACertificateAnchors);
        this.trustedCACertificateCertStore = Objects.requireNonNull(trustedCACertificateCertStore);
    }

    public Collection<String> getNonceDisabledIssuerCNs() {
        return nonceDisabledIssuerCNs;
    }

    public Set<TrustAnchor> getTrustedCACertificateAnchors() {
        return trustedCACertificateAnchors;
    }

    public CertStore getTrustedCACertificateCertStore() {
        return trustedCACertificateCertStore;
    }

}
