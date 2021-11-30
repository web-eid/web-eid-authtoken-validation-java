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

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import eu.webeid.security.exceptions.OCSPCertificateException;
import eu.webeid.security.exceptions.AuthTokenException;

import java.net.URI;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Objects;

import static eu.webeid.security.certificate.CertificateValidator.certificateIsValidOnDate;

/**
 * An OCSP service that uses a single designated OCSP responder.
 */
public class DesignatedOcspService implements OcspService {

    private final JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
    private final DesignatedOcspServiceConfiguration configuration;

    public DesignatedOcspService(DesignatedOcspServiceConfiguration configuration) {
        this.configuration = Objects.requireNonNull(configuration, "configuration");
    }

    @Override
    public boolean doesSupportNonce() {
        return configuration.doesSupportNonce();
    }

    @Override
    public URI getAccessLocation() {
        return configuration.getOcspServiceAccessLocation();
    }

    @Override
    public void validateResponderCertificate(X509CertificateHolder cert, Date producedAt) throws AuthTokenException {
        try {
            final X509Certificate responderCertificate = certificateConverter.getCertificate(cert);
            // Certificate pinning is implemented simply by comparing the certificates or their public keys,
            // see https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning.
            if (!configuration.getResponderCertificate().equals(responderCertificate)) {
                throw new OCSPCertificateException("Responder certificate from the OCSP response is not equal to " +
                    "the configured designated OCSP responder certificate");
            }
            certificateIsValidOnDate(responderCertificate, producedAt, "Designated OCSP responder");
        } catch (CertificateException e) {
            throw new OCSPCertificateException("X509CertificateHolder conversion to X509Certificate failed");
        }
    }

    public boolean supportsIssuerOf(X509Certificate certificate) throws CertificateEncodingException {
        return configuration.supportsIssuerOf(certificate);
    }

}
