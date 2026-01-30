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

import eu.webeid.ocsp.exceptions.OCSPCertificateException;
import eu.webeid.ocsp.protocol.OcspResponseValidator;
import eu.webeid.security.certificate.CertificateValidator;
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.validator.revocationcheck.RevocationMode;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

import java.net.URI;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;


import static eu.webeid.security.certificate.CertificateValidator.requireCertificateIsValidOnDate;

public class FallbackOcspService implements OcspService {

    private final JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
    private final URI url;
    private final boolean supportsNonce;
    private final X509Certificate trustedResponderCertificate;
    private final FallbackOcspService nextFallback;
    private final Set<TrustAnchor> trustedCACertificateAnchors;
    private final CertStore trustedCACertificateCertStore;

    public FallbackOcspService(FallbackOcspServiceConfiguration configuration) {
        this.url = configuration.getAccessLocation();
        this.supportsNonce = configuration.doesSupportNonce();
        this.trustedResponderCertificate = configuration.getResponderCertificate();
        this.nextFallback = configuration.getNextFallbackConfiguration() != null
            ? new FallbackOcspService(configuration.getNextFallbackConfiguration())
            : null;
        this.trustedCACertificateAnchors = configuration.getTrustedCACertificateAnchors();
        this.trustedCACertificateCertStore = configuration.getTrustedCACertificateCertStore();
    }

    @Override
    public boolean doesSupportNonce() {
        return supportsNonce;
    }

    @Override
    public URI getAccessLocation() {
        return url;
    }

    @Override
    public void validateResponderCertificate(X509CertificateHolder cert, Date now) throws AuthTokenException {
        try {
            final X509Certificate responderCertificate = certificateConverter.getCertificate(cert);
            requireCertificateIsValidOnDate(responderCertificate, now, "Fallback OCSP responder");
            if (trustedResponderCertificate != null) {
                validatePinnedResponderCertificate(responderCertificate);
            } else {
                validateResponderCertificateAgainstTrustedCa(responderCertificate, now);
            }
        } catch (CertificateException e) {
            throw new OCSPCertificateException("X509CertificateHolder conversion to X509Certificate failed", e);
        }
    }

    private void validatePinnedResponderCertificate(X509Certificate responderCertificate) throws OCSPCertificateException {
        // Certificate pinning is implemented simply by comparing the certificates or their public keys,
        // see https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning.
        if (!trustedResponderCertificate.equals(responderCertificate)) {
            throw new OCSPCertificateException("Responder certificate from the OCSP response is not equal to " +
                "the configured fallback OCSP responder certificate");
        }
    }

    private void validateResponderCertificateAgainstTrustedCa(X509Certificate responderCertificate, Date now) throws AuthTokenException {
        OcspResponseValidator.validateHasSigningExtension(responderCertificate);
        CertificateValidator.validateCertificateTrustAndRevocation(
            responderCertificate,
            trustedCACertificateAnchors,
            trustedCACertificateCertStore,
            now,
            RevocationMode.DISABLED,
            null,
            null
        );
    }

    public FallbackOcspService getNextFallback() {
        return nextFallback;
    }
}
