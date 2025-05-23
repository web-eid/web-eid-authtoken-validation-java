/*
 * Copyright (c) 2020-2025 Estonian Information System Authority
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

package eu.webeid.security.validator.certvalidators;

import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.exceptions.UserCertificateOCSPCheckFailedException;
import eu.webeid.security.util.DateAndTime;
import eu.webeid.security.validator.ocsp.DigestCalculatorImpl;
import eu.webeid.security.validator.ocsp.OcspClient;
import eu.webeid.security.validator.ocsp.OcspRequestBuilder;
import eu.webeid.security.validator.ocsp.OcspResponseValidator;
import eu.webeid.security.validator.ocsp.OcspServiceProvider;
import eu.webeid.security.validator.ocsp.service.OcspService;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Date;
import java.util.Objects;

public final class SubjectCertificateNotRevokedValidator {

    private static final Logger LOG = LoggerFactory.getLogger(SubjectCertificateNotRevokedValidator.class);

    private final SubjectCertificateTrustedValidator trustValidator;
    private final OcspClient ocspClient;
    private final OcspServiceProvider ocspServiceProvider;
    private final Duration allowedOcspResponseTimeSkew;
    private final Duration maxOcspResponseThisUpdateAge;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public SubjectCertificateNotRevokedValidator(SubjectCertificateTrustedValidator trustValidator,
                                                 OcspClient ocspClient,
                                                 OcspServiceProvider ocspServiceProvider,
                                                 Duration allowedOcspResponseTimeSkew,
                                                 Duration maxOcspResponseThisUpdateAge) {
        this.trustValidator = trustValidator;
        this.ocspClient = ocspClient;
        this.ocspServiceProvider = ocspServiceProvider;
        this.allowedOcspResponseTimeSkew = allowedOcspResponseTimeSkew;
        this.maxOcspResponseThisUpdateAge = maxOcspResponseThisUpdateAge;
    }

    /**
     * Validates that the user certificate from the authentication token is not revoked with OCSP.
     *
     * @param subjectCertificate user certificate to be validated
     * @throws AuthTokenException when user certificate is revoked or revocation check fails.
     */
    public void validateCertificateNotRevoked(X509Certificate subjectCertificate) throws AuthTokenException {
        try {
            OcspService ocspService = ocspServiceProvider.getService(subjectCertificate);

            final CertificateID certificateId = getCertificateId(subjectCertificate,
                Objects.requireNonNull(trustValidator.getSubjectCertificateIssuerCertificate()));

            final OCSPReq request = new OcspRequestBuilder()
                .withCertificateId(certificateId)
                .enableOcspNonce(ocspService.doesSupportNonce())
                .build();

            if (!ocspService.doesSupportNonce()) {
                LOG.debug("Disabling OCSP nonce extension");
            }

            LOG.debug("Sending OCSP request");
            final OCSPResp response = Objects.requireNonNull(ocspClient.request(ocspService.getAccessLocation(), request));
            if (response.getStatus() != OCSPResponseStatus.SUCCESSFUL) {
                throw new UserCertificateOCSPCheckFailedException("Response status: " + ocspStatusToString(response.getStatus()));
            }

            final BasicOCSPResp basicResponse = (BasicOCSPResp) response.getResponseObject();
            if (basicResponse == null) {
                throw new UserCertificateOCSPCheckFailedException("Missing Basic OCSP Response");
            }
            verifyOcspResponse(basicResponse, ocspService, certificateId);
            if (ocspService.doesSupportNonce()) {
                checkNonce(request, basicResponse);
            }
        } catch (OCSPException | CertificateException | OperatorCreationException | IOException e) {
            throw new UserCertificateOCSPCheckFailedException(e);
        }
    }

    private void verifyOcspResponse(BasicOCSPResp basicResponse, OcspService ocspService, CertificateID requestCertificateId) throws AuthTokenException, OCSPException, CertificateException, OperatorCreationException {
        // The verification algorithm follows RFC 2560, https://www.ietf.org/rfc/rfc2560.txt.
        //
        // 3.2.  Signed Response Acceptance Requirements
        //   Prior to accepting a signed response for a particular certificate as
        //   valid, OCSP clients SHALL confirm that:
        //
        //   1. The certificate identified in a received response corresponds to
        //      the certificate that was identified in the corresponding request.

        // As we sent the request for only a single certificate, we expect only a single response.
        if (basicResponse.getResponses().length != 1) {
            throw new UserCertificateOCSPCheckFailedException("OCSP response must contain one response, "
                + "received " + basicResponse.getResponses().length + " responses instead");
        }
        final SingleResp certStatusResponse = basicResponse.getResponses()[0];
        if (!requestCertificateId.equals(certStatusResponse.getCertID())) {
            throw new UserCertificateOCSPCheckFailedException("OCSP responded with certificate ID that differs from the requested ID");
        }

        //   2. The signature on the response is valid.

        // We assume that the responder includes its certificate in the certs field of the response
        // that helps us to verify it. According to RFC 2560 this field is optional, but including it
        // is standard practice.
        if (basicResponse.getCerts().length < 1) {
            throw new UserCertificateOCSPCheckFailedException("OCSP response must contain the responder certificate, "
                + "but none was provided");
        }
        // The first certificate is the responder certificate, other certificates, if given, are the certificate's chain.
        final X509CertificateHolder responderCert = basicResponse.getCerts()[0];
        OcspResponseValidator.validateResponseSignature(basicResponse, responderCert);

        //   3. The identity of the signer matches the intended recipient of the
        //      request.
        //
        //   4. The signer is currently authorized to provide a response for the
        //      certificate in question.

        // Use the clock instance so that the date can be mocked in tests.
        final Date now = DateAndTime.DefaultClock.getInstance().now();
        ocspService.validateResponderCertificate(responderCert, now);

        //   5. The time at which the status being indicated is known to be
        //      correct (thisUpdate) is sufficiently recent.
        //
        //   6. When available, the time at or before which newer information will
        //      be available about the status of the certificate (nextUpdate) is
        //      greater than the current time.

        OcspResponseValidator.validateCertificateStatusUpdateTime(certStatusResponse, allowedOcspResponseTimeSkew, maxOcspResponseThisUpdateAge);

        // Now we can accept the signed response as valid and validate the certificate status.
        OcspResponseValidator.validateSubjectCertificateStatus(certStatusResponse);
        LOG.debug("OCSP check result is GOOD");
    }

    private static void checkNonce(OCSPReq request, BasicOCSPResp response) throws UserCertificateOCSPCheckFailedException {
        final Extension requestNonce = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        final Extension responseNonce = response.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (requestNonce == null || responseNonce == null) {
            throw new UserCertificateOCSPCheckFailedException("OCSP request or response nonce extension missing, " +
                "possible replay attack");
        }
        if (!requestNonce.equals(responseNonce)) {
            throw new UserCertificateOCSPCheckFailedException("OCSP request and response nonces differ, " +
                "possible replay attack");
        }
    }

    private static CertificateID getCertificateId(X509Certificate subjectCertificate, X509Certificate issuerCertificate) throws CertificateEncodingException, IOException, OCSPException {
        final BigInteger serial = subjectCertificate.getSerialNumber();
        final DigestCalculator digestCalculator = DigestCalculatorImpl.sha1();
        return new CertificateID(digestCalculator,
            new X509CertificateHolder(issuerCertificate.getEncoded()), serial);
    }

    private static String ocspStatusToString(int status) {
        switch (status) {
            case OCSPResp.MALFORMED_REQUEST:
                return "malformed request";
            case OCSPResp.INTERNAL_ERROR:
                return "internal error";
            case OCSPResp.TRY_LATER:
                return "service unavailable";
            case OCSPResp.SIG_REQUIRED:
                return "request signature missing";
            case OCSPResp.UNAUTHORIZED:
                return "unauthorized";
            default:
                return "unknown";
        }
    }

}
