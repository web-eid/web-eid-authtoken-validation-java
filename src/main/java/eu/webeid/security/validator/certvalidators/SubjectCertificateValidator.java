// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.validator.certvalidators;

import eu.webeid.security.exceptions.AuthTokenException;

import java.security.cert.X509Certificate;

/**
 * Validators perform the actual user certificate validation actions.
 * <p>
 * They are used by AuthTokenValidatorImpl and are not part of the public API.
 */
@FunctionalInterface
public interface SubjectCertificateValidator {
    void validate(X509Certificate subjectCertificate) throws AuthTokenException;
}
