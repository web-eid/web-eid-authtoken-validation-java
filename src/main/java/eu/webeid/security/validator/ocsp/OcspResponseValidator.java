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

import eu.webeid.security.exceptions.OCSPCertificateException;
import eu.webeid.security.exceptions.UserCertificateOCSPCheckFailedException;
import eu.webeid.security.exceptions.UserCertificateRevokedException;
import eu.webeid.security.util.DateAndTime;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

public final class OcspResponseValidator {

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

    public static void validateResponseSignature(BasicOCSPResp basicResponse, X509CertificateHolder responderCert) throws CertificateException, OperatorCreationException, OCSPException, UserCertificateOCSPCheckFailedException {
        final ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder()
            .setProvider("BC")
            .build(responderCert);
        if (!basicResponse.isSignatureValid(verifierProvider)) {
            throw new UserCertificateOCSPCheckFailedException("OCSP response signature is invalid");
        }
    }

    public static void validateCertificateStatusUpdateTime(SingleResp certStatusResponse, Duration allowedTimeSkew, Duration maxThisupdateAge) throws UserCertificateOCSPCheckFailedException {
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
        final Instant minimumValidThisUpdateTime = now.minus(maxThisupdateAge);

        final Instant thisUpdate = certStatusResponse.getThisUpdate().toInstant();
        if (thisUpdate.isAfter(latestAcceptableTimeSkew)) {
            throw new UserCertificateOCSPCheckFailedException(ERROR_PREFIX +
                "thisUpdate '" + thisUpdate + "' is too far in the future, " +
                "latest allowed: '" + latestAcceptableTimeSkew + "'");
        }
        if (thisUpdate.isBefore(minimumValidThisUpdateTime)) {
            throw new UserCertificateOCSPCheckFailedException(ERROR_PREFIX +
                "thisUpdate '" + thisUpdate + "' is too old, " +
                "minimum time allowed: '" + minimumValidThisUpdateTime + "'");
        }

        if (certStatusResponse.getNextUpdate() == null) {
            return;
        }
        final Instant nextUpdate = certStatusResponse.getNextUpdate().toInstant();
        if (nextUpdate.isBefore(earliestAcceptableTimeSkew)) {
            throw new UserCertificateOCSPCheckFailedException(ERROR_PREFIX +
                "nextUpdate '" + nextUpdate + "' is in the past");
        }
        if (nextUpdate.isBefore(thisUpdate)) {
            throw new UserCertificateOCSPCheckFailedException(ERROR_PREFIX +
                "nextUpdate '" + nextUpdate + "' is before thisUpdate '" + thisUpdate + "'");
        }
    }

    public static void validateSubjectCertificateStatus(SingleResp certStatusResponse) throws UserCertificateRevokedException {
        final CertificateStatus status = certStatusResponse.getCertStatus();
        if (status == null) {
            return;
        }
        if (status instanceof RevokedStatus) {
            RevokedStatus revokedStatus = (RevokedStatus) status;
            throw (revokedStatus.hasRevocationReason() ?
                new UserCertificateRevokedException("Revocation reason: " + revokedStatus.getRevocationReason()) :
                new UserCertificateRevokedException());
        } else if (status instanceof UnknownStatus) {
            throw new UserCertificateRevokedException("Unknown status");
        } else {
            throw new UserCertificateRevokedException("Status is neither good, revoked nor unknown");
        }
    }

    private OcspResponseValidator() {
        throw new IllegalStateException("Utility class");
    }
}
