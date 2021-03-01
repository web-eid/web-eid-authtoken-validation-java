/*
 * Copyright (c) 2020 The Web eID Project
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

package org.webeid.security.validator.validators;

import okhttp3.OkHttpClient;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.cert.ocsp.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.webeid.security.exceptions.TokenValidationException;
import org.webeid.security.exceptions.UserCertificateRevocationCheckFailedException;
import org.webeid.security.exceptions.UserCertificateRevokedException;
import org.webeid.security.validator.AuthTokenValidatorData;
import org.webeid.security.validator.ocsp.OcspRequestBuilder;
import org.webeid.security.validator.ocsp.OcspUtils;

import java.io.IOException;
import java.net.URI;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Objects;

public final class SubjectCertificateNotRevokedValidator {

    private static final Logger LOG = LoggerFactory.getLogger(SubjectCertificateNotRevokedValidator.class);

    private final SubjectCertificateTrustedValidator trustValidator;
    private final OkHttpClient httpClient;
    private final Collection<URI> nonceDisabledOcspUrls;

    public SubjectCertificateNotRevokedValidator(SubjectCertificateTrustedValidator trustValidator, OkHttpClient httpClient, Collection<URI> nonceDisabledOcspUrls) {
        this.trustValidator = trustValidator;
        this.httpClient = httpClient;
        this.nonceDisabledOcspUrls = nonceDisabledOcspUrls;
    }

    /**
     * Validates that the user certificate from the authentication token is not revoked with OCSP.
     *
     * @param actualTokenData authentication token data that contains the user certificate.
     * @throws TokenValidationException when user certificate is revoked.
     */
    public void validateCertificateNotRevoked(AuthTokenValidatorData actualTokenData) throws TokenValidationException {
        try {
            final X509Certificate certificate = actualTokenData.getSubjectCertificate();
            final URI uri = OcspUtils.ocspUri(certificate);

            if (uri == null) {
                throw new UserCertificateRevocationCheckFailedException("The CA/certificate doesn't have an OCSP responder");
            }
            final boolean ocspNonceDisabled = nonceDisabledOcspUrls.contains(uri);
            if (ocspNonceDisabled) {
                LOG.debug("Disabling OCSP nonce extension");
            }

            final OCSPReq request = new OcspRequestBuilder()
                .certificate(certificate)
                .enableOcspNonce(!ocspNonceDisabled)
                .issuer(Objects.requireNonNull(trustValidator.getSubjectCertificateIssuerCertificate()))
                .build();

            LOG.debug("Sending OCSP request");
            final OCSPResp response = OcspUtils.request(uri, request, httpClient);
            if (response.getStatus() != OCSPResponseStatus.SUCCESSFUL) {
                throw new UserCertificateRevocationCheckFailedException("Response status: " + response.getStatus());
            }

            final BasicOCSPResp basicResponse = (BasicOCSPResp) response.getResponseObject();
            final SingleResp first = basicResponse.getResponses()[0];

            final CertificateStatus status = first.getCertStatus();

            if (status instanceof RevokedStatus) {
                RevokedStatus revokedStatus = (RevokedStatus) status;
                throw (revokedStatus.hasRevocationReason() ?
                    new UserCertificateRevokedException("Revocation reason: " + revokedStatus.getRevocationReason()) :
                    new UserCertificateRevokedException());
            } else if (status instanceof UnknownStatus) {
                throw new UserCertificateRevokedException("Unknown status");
            } else if (status == null) {
                LOG.debug("OCSP check result is GOOD");
            } else {
                throw new UserCertificateRevokedException("Status is neither good, revoked nor unknown");
            }
        } catch (CertificateEncodingException | OCSPException | IOException e) {
            throw new UserCertificateRevocationCheckFailedException(e);
        }
    }
}
