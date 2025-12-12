// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT
package eu.webeid.security.validator.revocationcheck;

import eu.webeid.security.exceptions.AuthTokenException;

import java.security.cert.X509Certificate;
import java.util.List;

public interface CertificateRevocationChecker {

    List<RevocationInfo> validateCertificateNotRevoked(X509Certificate subjectCertificate,
                                                       X509Certificate issuerCertificate) throws AuthTokenException;

}