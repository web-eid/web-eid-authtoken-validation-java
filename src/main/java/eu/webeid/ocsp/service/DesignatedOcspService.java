// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.ocsp.service;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import eu.webeid.ocsp.exceptions.OCSPCertificateException;
import eu.webeid.security.exceptions.AuthTokenException;

import java.net.URI;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Date;
import java.util.Objects;

import static eu.webeid.security.certificate.CertificateValidator.requireCertificateIsValidOnDate;

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
    public Duration getMaxThisUpdateAge() {
        return configuration.getMaxThisUpdateAge();
    }

    @Override
    public Duration getMaxNextUpdateAge() {
        return configuration.getMaxNextUpdateAge();
    }

    @Override
    public void validateResponderCertificate(X509CertificateHolder cert, X509Certificate issuerCertificate, Date now) throws AuthTokenException {
        try {
            final X509Certificate responderCertificate = certificateConverter.getCertificate(cert);
            // Certificate extensions (Basic Constraints, Key Usage, Extended Key Usage) are validated at
            // configuration time in DesignatedOcspServiceConfiguration. Since equals() compares the full DER
            // encoding, a matching certificate is guaranteed to have the same validated extensions.
            // Certificate pinning is implemented simply by comparing the certificates or their public keys,
            // see https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning.
            if (!configuration.getResponderCertificate().equals(responderCertificate)) {
                throw new OCSPCertificateException("Responder certificate from the OCSP response is not equal to " +
                    "the configured designated OCSP responder certificate");
            }
            requireCertificateIsValidOnDate(responderCertificate, now, "Designated OCSP responder");
        } catch (CertificateException e) {
            throw new OCSPCertificateException("X509CertificateHolder conversion to X509Certificate failed", e);
        }
    }

    public boolean supportsIssuer(X509Certificate issuerCertificate) {
        return configuration.supportsIssuer(issuerCertificate);
    }

}
