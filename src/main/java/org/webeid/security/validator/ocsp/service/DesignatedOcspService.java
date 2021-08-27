package org.webeid.security.validator.ocsp.service;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.webeid.security.exceptions.OCSPCertificateException;
import org.webeid.security.exceptions.TokenValidationException;

import java.net.URI;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Objects;

import static org.webeid.security.certificate.CertificateValidator.certificateIsValidOnDate;

/**
 * An OCSP service that uses a single designated OCSP responder.
 */
public class DesignatedOcspService implements OcspService {

    private final DesignatedOcspServiceConfiguration designatedOcspServiceConfiguration;
    private final JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();

    public DesignatedOcspService(DesignatedOcspServiceConfiguration designatedOcspServiceConfiguration) {
        this.designatedOcspServiceConfiguration = Objects.requireNonNull(designatedOcspServiceConfiguration, "designatedOcspServiceConfiguration");
    }

    @Override
    public boolean doesSupportNonce() {
        return designatedOcspServiceConfiguration.doesSupportNonce();
    }

    @Override
    public URI getUrl() {
        return designatedOcspServiceConfiguration.getOcspServiceUrl();
    }

    @Override
    public void validateResponderCertificate(X509CertificateHolder cert, Date producedAt) throws TokenValidationException {
        try {
            final X509Certificate responderCertificate = certificateConverter.getCertificate(cert);
            // Certificate pinning is implemented simply by comparing the certificates or their public keys,
            // see https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning.
            if (!designatedOcspServiceConfiguration.getResponderCertificate().equals(responderCertificate)) {
                throw new OCSPCertificateException("Responder certificate from the OCSP response is not equal to " +
                    "the configured designated OCSP responder certificate");
            }
            certificateIsValidOnDate(responderCertificate, producedAt);
        } catch (CertificateException e) {
            throw new OCSPCertificateException("X509CertificateHolder conversion to X509Certificate failed");
        }
    }
}
