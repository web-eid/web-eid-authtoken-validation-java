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

package eu.webeid.security.validator.ocsp;

import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.exceptions.OCSPCertificateException;
import eu.webeid.security.exceptions.UserCertificateOCSPCheckFailedException;
import eu.webeid.security.exceptions.UserCertificateRevokedException;
import eu.webeid.security.exceptions.UserCertificateUnknownException;
import eu.webeid.security.util.DateAndTime;
import eu.webeid.security.validator.ocsp.service.OcspService;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Objects;

public final class OcspResponseValidator {

    public static OcspValidationInfo validateOcspResponse(OCSPResp ocspResp, OcspService ocspService, Extension requestNonce,
                                                          X509Certificate subjectCertificate, X509Certificate issuerCertificate,
                                                          Duration allowedOcspResponseTimeSkew, Duration maxOcspResponseThisUpdateAge,
                                                          boolean rejectUnknownOcspResponseStatus) throws AuthTokenException, OCSPException, CertificateException, OperatorCreationException {
        final OcspValidationInfo ocspValidationInfo = new OcspValidationInfo(subjectCertificate, ocspService.getAccessLocation(), ocspResp);
        final BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResp.getResponseObject();
        if (basicResponse == null) {
            throw new UserCertificateOCSPCheckFailedException("Missing Basic OCSP Response", ocspValidationInfo);
        }

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
                + "received " + basicResponse.getResponses().length + " responses instead", ocspValidationInfo);
        }
        final CertificateID requestCertificateId = getCertificateId(subjectCertificate, issuerCertificate, ocspService, ocspResp);
        final SingleResp certStatusResponse = basicResponse.getResponses()[0];
        if (!requestCertificateId.equals(certStatusResponse.getCertID())) {
            throw new UserCertificateOCSPCheckFailedException("OCSP responded with certificate ID that differs from the requested ID", ocspValidationInfo);
        }

        //   2. The signature on the response is valid.

        // We assume that the responder includes its certificate in the certs field of the response
        // that helps us to verify it. According to RFC 2560 this field is optional, but including it
        // is standard practice.
        if (basicResponse.getCerts().length < 1) {
            throw new UserCertificateOCSPCheckFailedException("OCSP response must contain the responder certificate, "
                + "but none was provided", ocspValidationInfo);
        }
        // The first certificate is the responder certificate, other certificates, if given, are the certificate's chain.
        final X509CertificateHolder responderCert = basicResponse.getCerts()[0];
        OcspResponseValidator.validateResponseSignature(basicResponse, responderCert, ocspValidationInfo);

        //   3. The identity of the signer matches the intended recipient of the
        //      request.
        //
        //   4. The signer is currently authorized to provide a response for the
        //      certificate in question.

        // Use the clock instance so that the date can be mocked in tests.
        final Date now = DateAndTime.DefaultClock.getInstance().now();
        try {
            ocspService.validateResponderCertificate(responderCert, now);
        } catch (AuthTokenException e) {
            throw new UserCertificateOCSPCheckFailedException(e, ocspValidationInfo);
        }

        //   5. The time at which the status being indicated is known to be
        //      correct (thisUpdate) is sufficiently recent.
        //
        //   6. When available, the time at or before which newer information will
        //      be available about the status of the certificate (nextUpdate) is
        //      greater than the current time.

        OcspResponseValidator.validateCertificateStatusUpdateTime(certStatusResponse, allowedOcspResponseTimeSkew, maxOcspResponseThisUpdateAge, ocspValidationInfo);

        // Now we can accept the signed response as valid and validate the certificate status.
        OcspResponseValidator.validateSubjectCertificateStatus(certStatusResponse, rejectUnknownOcspResponseStatus, ocspValidationInfo);

        if (ocspService.doesSupportNonce()) {
            OcspResponseValidator.validateNonce(requestNonce, ocspResp, ocspValidationInfo);
        }

        return ocspValidationInfo;
    }

    private static CertificateID getCertificateId(X509Certificate subjectCertificate, X509Certificate issuerCertificate, OcspService ocspService, OCSPResp ocspResp) throws AuthTokenException {
        try {
            return getCertificateId(subjectCertificate, issuerCertificate);
        } catch (CertificateEncodingException | IOException | OCSPException e) {
            throw new UserCertificateOCSPCheckFailedException(e, new OcspValidationInfo(subjectCertificate, ocspService.getAccessLocation(), ocspResp));
        }
    }

    public static CertificateID getCertificateId(X509Certificate subjectCertificate, X509Certificate issuerCertificate) throws CertificateEncodingException, IOException, OCSPException {
        final BigInteger serial = subjectCertificate.getSerialNumber();
        final DigestCalculator digestCalculator = DigestCalculatorImpl.sha1();
        return new CertificateID(digestCalculator,
            new X509CertificateHolder(issuerCertificate.getEncoded()), serial);
    }

    /**
     * Indicates that a X.509 Certificates corresponding private key may be used by an authority to sign OCSP responses.
     * <p>
     * https://oidref.com/1.3.6.1.5.5.7.3.9
     */
    private static final String OID_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9";
    private static final String ERROR_PREFIX = "Certificate status update time check failed: ";

    public static void validateHasSigningExtension(X509Certificate certificate) throws OCSPCertificateException {
        Objects.requireNonNull(certificate, "certificate");
        try {
            if (certificate.getExtendedKeyUsage() == null || !certificate.getExtendedKeyUsage().contains(OID_OCSP_SIGNING)) {
                throw new OCSPCertificateException("Certificate " + certificate.getSubjectX500Principal() +
                    " does not contain the key usage extension for OCSP response signing");
            }
        } catch (CertificateParsingException e) {
            throw new OCSPCertificateException("Certificate parsing failed:", e);
        }
    }

    private static void validateResponseSignature(BasicOCSPResp basicResponse, X509CertificateHolder responderCert, OcspValidationInfo ocspValidationInfo) throws CertificateException, OperatorCreationException, OCSPException, UserCertificateOCSPCheckFailedException {
        final ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder()
            .setProvider("BC")
            .build(responderCert);
        if (!basicResponse.isSignatureValid(verifierProvider)) {
            throw new UserCertificateOCSPCheckFailedException("OCSP response signature is invalid", ocspValidationInfo);
        }
    }

    static void validateCertificateStatusUpdateTime(SingleResp certStatusResponse, Duration allowedTimeSkew, Duration maxThisUpdateAge, OcspValidationInfo ocspValidationInfo) throws UserCertificateOCSPCheckFailedException {
        // From RFC 2560, https://www.ietf.org/rfc/rfc2560.txt:
        // 4.2.2.  Notes on OCSP Responses
        // 4.2.2.1.  Time
        //   Responses whose nextUpdate value is earlier than
        //   the local system time value SHOULD be considered unreliable.
        //   Responses whose thisUpdate time is later than the local system time
        //   SHOULD be considered unreliable.
        //   If nextUpdate is not set, the responder is indicating that newer
        //   revocation information is available all the time.
        final Instant now = DateAndTime.DefaultClock.getInstance().now().toInstant();
        final Instant earliestAcceptableTimeSkew = now.minus(allowedTimeSkew);
        final Instant latestAcceptableTimeSkew = now.plus(allowedTimeSkew);
        final Instant minimumValidThisUpdateTime = now.minus(maxThisUpdateAge);

        final Instant thisUpdate = certStatusResponse.getThisUpdate().toInstant();
        if (thisUpdate.isAfter(latestAcceptableTimeSkew)) {
            throw new UserCertificateOCSPCheckFailedException(ERROR_PREFIX +
                "thisUpdate '" + thisUpdate + "' is too far in the future, " +
                "latest allowed: '" + latestAcceptableTimeSkew + "'", ocspValidationInfo);
        }
        if (thisUpdate.isBefore(minimumValidThisUpdateTime)) {
            throw new UserCertificateOCSPCheckFailedException(ERROR_PREFIX +
                "thisUpdate '" + thisUpdate + "' is too old, " +
                "minimum time allowed: '" + minimumValidThisUpdateTime + "'", ocspValidationInfo);
        }

        if (certStatusResponse.getNextUpdate() == null) {
            return;
        }
        final Instant nextUpdate = certStatusResponse.getNextUpdate().toInstant();
        if (nextUpdate.isBefore(earliestAcceptableTimeSkew)) {
            throw new UserCertificateOCSPCheckFailedException(ERROR_PREFIX +
                "nextUpdate '" + nextUpdate + "' is in the past", ocspValidationInfo);
        }
        if (nextUpdate.isBefore(thisUpdate)) {
            throw new UserCertificateOCSPCheckFailedException(ERROR_PREFIX +
                "nextUpdate '" + nextUpdate + "' is before thisUpdate '" + thisUpdate + "'", ocspValidationInfo);
        }
    }

    private static void validateSubjectCertificateStatus(SingleResp certStatusResponse, boolean rejectUnknownOcspResponseStatus, OcspValidationInfo ocspValidationInfo) throws AuthTokenException {
        final CertificateStatus status = certStatusResponse.getCertStatus();
        if (status == null) {
            return;
        }
        if (status instanceof RevokedStatus) {
            RevokedStatus revokedStatus = (RevokedStatus) status;
            throw (revokedStatus.hasRevocationReason() ?
                new UserCertificateRevokedException("Revocation reason: " + revokedStatus.getRevocationReason(), ocspValidationInfo) :
                new UserCertificateRevokedException(ocspValidationInfo));
        } else if (status instanceof UnknownStatus) {
            throw rejectUnknownOcspResponseStatus ? new UserCertificateUnknownException("Unknown status", ocspValidationInfo)
                : new UserCertificateRevokedException("Unknown status", ocspValidationInfo);
        } else {
            throw rejectUnknownOcspResponseStatus ? new UserCertificateUnknownException("Status is neither good, revoked nor unknown", ocspValidationInfo)
                : new UserCertificateRevokedException("Status is neither good, revoked nor unknown", ocspValidationInfo);
        }
    }

    private static void validateNonce(Extension requestNonce, OCSPResp ocspResp, OcspValidationInfo ocspValidationInfo) throws UserCertificateOCSPCheckFailedException, OCSPException {
        final BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResp.getResponseObject();
        if (basicResponse == null) {
            throw new UserCertificateOCSPCheckFailedException("Missing Basic OCSP Response", ocspValidationInfo);
        }
        final Extension responseNonce = basicResponse.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (requestNonce == null || responseNonce == null) {
            throw new UserCertificateOCSPCheckFailedException("OCSP request or response nonce extension missing, " +
                "possible replay attack", ocspValidationInfo);
        }
        if (!requestNonce.equals(responseNonce)) {
            throw new UserCertificateOCSPCheckFailedException("OCSP request and response nonces differ, " +
                "possible replay attack", ocspValidationInfo);
        }
    }

    public static String ocspStatusToString(int status) {
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

    private OcspResponseValidator() {
        throw new IllegalStateException("Utility class");
    }
}
