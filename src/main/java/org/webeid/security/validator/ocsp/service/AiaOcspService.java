package org.webeid.security.validator.ocsp.service;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.webeid.security.exceptions.OCSPCertificateException;
import org.webeid.security.exceptions.TokenValidationException;
import org.webeid.security.exceptions.UserCertificateOCSPCheckFailedException;
import org.webeid.security.validator.ocsp.OcspUtils;

import java.net.URI;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Objects;

import static org.webeid.security.certificate.CertificateValidator.certificateIsValidOnDate;
import static org.webeid.security.certificate.CertificateValidator.validateIsSignedByTrustedCA;
import static org.webeid.security.validator.ocsp.OcspUtils.validateHasSigningExtension;

/**
 * An OCSP service that uses the responders from the Certificates' Authority Information Access (AIA) extension.
 */
public class AiaOcspService implements OcspService {

    private final JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();

    private final URI url;
    private final AiaOcspResponderConfiguration configuration;

    public AiaOcspService(AiaOcspServiceConfiguration aiaOcspServiceConfiguration, X509Certificate certificate) throws TokenValidationException {
        this.url = getOcspAiaUrlFromCertificate(certificate);
        Objects.requireNonNull(aiaOcspServiceConfiguration, "aiaOcspServiceConfiguration");
        this.configuration = aiaOcspServiceConfiguration.getResponderConfigurationForUrl(this.url);
    }

    @Override
    public boolean doesSupportNonce() {
        return configuration.doesSupportNonce();
    }

    @Override
    public URI getUrl() {
        return url;
    }

    @Override
    public void validateResponderCertificate(X509CertificateHolder cert, Date producedAt) throws TokenValidationException {
        try {
            final X509Certificate certificate = certificateConverter.getCertificate(cert);
            certificateIsValidOnDate(certificate, producedAt);
            validateHasSigningExtension(certificate);
            validateIsSignedByTrustedCA(
                certificate,
                configuration.getTrustedCACertificateAnchors(),
                configuration.getTrustedCACertificateCertStore()
            );
        } catch (CertificateException e) {
            throw new OCSPCertificateException("Invalid certificate", e);
        }
    }

    private static URI getOcspAiaUrlFromCertificate(X509Certificate certificate) throws TokenValidationException {
        final URI uri = OcspUtils.ocspUri(Objects.requireNonNull(certificate, "certificate"));
        if (uri == null) {
            throw new UserCertificateOCSPCheckFailedException("Getting the AIA OCSP responder field from the certificate failed");
        }
        return uri;
    }

}
