package org.webeid.security.validator.ocsp.service;

import org.bouncycastle.cert.X509CertificateHolder;
import org.webeid.security.exceptions.TokenValidationException;

import java.net.URI;
import java.util.Date;

public interface OcspService {

    boolean doesSupportNonce();

    URI getUrl();

    void validateResponderCertificate(X509CertificateHolder cert, Date date) throws TokenValidationException;

}
