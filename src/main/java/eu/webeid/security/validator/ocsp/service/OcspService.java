// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.validator.ocsp.service;

import org.bouncycastle.cert.X509CertificateHolder;
import eu.webeid.security.exceptions.AuthTokenException;

import java.net.URI;
import java.util.Date;

public interface OcspService {

    boolean doesSupportNonce();

    URI getAccessLocation();

    void validateResponderCertificate(X509CertificateHolder cert, Date now) throws AuthTokenException;

}
