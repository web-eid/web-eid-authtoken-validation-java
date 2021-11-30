/*
 * Copyright (c) 2020-2021 Estonian Information System Authority
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

import eu.webeid.security.certificate.CertificateValidator;
import eu.webeid.security.exceptions.OCSPCertificateException;
import eu.webeid.security.validator.ocsp.OcspResponseValidator;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.exceptions.UserCertificateOCSPCheckFailedException;

import java.net.URI;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Objects;
import java.util.Set;

import static eu.webeid.security.validator.ocsp.OcspUrl.getOcspUri;

/**
 * An OCSP service that uses the responders from the Certificates' Authority Information Access (AIA) extension.
 */
public class AiaOcspService implements OcspService {

    private final JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
    private final Set<TrustAnchor> trustedCACertificateAnchors;
    private final CertStore trustedCACertificateCertStore;
    private final URI url;
    private final boolean supportsNonce;

    public AiaOcspService(AiaOcspServiceConfiguration configuration, X509Certificate certificate) throws AuthTokenException {
        Objects.requireNonNull(configuration);
        this.trustedCACertificateAnchors = configuration.getTrustedCACertificateAnchors();
        this.trustedCACertificateCertStore = configuration.getTrustedCACertificateCertStore();
        this.url = getOcspAiaUrlFromCertificate(Objects.requireNonNull(certificate));
        this.supportsNonce = !configuration.getNonceDisabledOcspUrls().contains(this.url);
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
    public void validateResponderCertificate(X509CertificateHolder cert, Date producedAt) throws AuthTokenException {
        try {
            final X509Certificate certificate = certificateConverter.getCertificate(cert);
            CertificateValidator.certificateIsValidOnDate(certificate, producedAt, "AIA OCSP responder");
            // Trusted certificates' validity has been already verified in validateCertificateExpiry().
            OcspResponseValidator.validateHasSigningExtension(certificate);
            CertificateValidator.validateIsSignedByTrustedCA(certificate, trustedCACertificateAnchors, trustedCACertificateCertStore, producedAt);
        } catch (CertificateException e) {
            throw new OCSPCertificateException("Invalid responder certificate", e);
        }
    }

    private static URI getOcspAiaUrlFromCertificate(X509Certificate certificate) throws AuthTokenException {
        final URI uri = getOcspUri(certificate);
        if (uri == null) {
            throw new UserCertificateOCSPCheckFailedException("Getting the AIA OCSP responder field from the certificate failed");
        }
        return uri;
    }

}
