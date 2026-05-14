// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.ocsp.protocol;

import eu.webeid.ocsp.OcspCertificateRevocationChecker;
import eu.webeid.ocsp.exceptions.OCSPCertificateException;
import eu.webeid.ocsp.exceptions.UserCertificateOCSPCheckFailedException;
import eu.webeid.ocsp.exceptions.UserCertificateRevokedException;
import org.bouncycastle.asn1.DLBitString;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static eu.webeid.ocsp.protocol.OcspResponseValidator.validateBasicConstraintsNotCA;
import static eu.webeid.security.testutil.ResourceUtil.bytesFromResource;
import static eu.webeid.ocsp.protocol.OcspResponseValidator.validateCertificateStatusUpdateTime;
import static eu.webeid.ocsp.protocol.OcspResponseValidator.validateExtendedKeyUsageOcspSigning;
import static eu.webeid.ocsp.protocol.OcspResponseValidator.validateKeyUsageDigitalSignature;
import static eu.webeid.ocsp.protocol.OcspResponseValidator.validateKeyUsageNotCertificateSigning;
import static eu.webeid.ocsp.protocol.OcspResponseValidator.validateSubjectCertificateStatus;
import static eu.webeid.security.testutil.TestCertificateBuilder.buildCertificate;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OcspResponseValidatorTest {

    private static final Duration TIME_SKEW = OcspCertificateRevocationChecker.DEFAULT_TIME_SKEW;
    private static final Duration THIS_UPDATE_AGE = OcspCertificateRevocationChecker.DEFAULT_THIS_UPDATE_AGE;
    private static final Duration NEXT_UPDATE_AGE = OcspCertificateRevocationChecker.DEFAULT_NEXT_UPDATE_AGE;
    private static final Duration LONG_THIS_UPDATE_AGE = Duration.ofDays(365);
    private static final Duration LONG_NEXT_UPDATE_AGE = Duration.ofDays(365);
    /** Shorter than {@link #TIME_SKEW}, to show that the nextUpdate age check is independent of the time skew. */
    private static final Duration SHORT_NEXT_UPDATE_AGE = Duration.ofMinutes(2);
    private static final URI OCSP_URL = URI.create("https://example.org");

    @Test
    void whenThisAndNextUpdateWithinAgeLimits_thenValidationSucceeds() {
        final SingleResp mockResponse = mock(SingleResp.class);
        var now = Instant.now();
        var thisUpdateWithinAgeLimit = getThisUpdateWithinAgeLimit(now);
        var nextUpdateWithinAgeLimit = Date.from(now.minus(THIS_UPDATE_AGE.minusSeconds(2)));
        when(mockResponse.getThisUpdate()).thenReturn(thisUpdateWithinAgeLimit);
        when(mockResponse.getNextUpdate()).thenReturn(nextUpdateWithinAgeLimit);
        assertThatCode(() -> validateCertificateStatusUpdateTime(mockResponse, TIME_SKEW, THIS_UPDATE_AGE, NEXT_UPDATE_AGE, OCSP_URL))
            .doesNotThrowAnyException();
    }

    @Test
    void whenNextUpdateBeforeThisUpdate_thenThrows() {
        final SingleResp mockResponse = mock(SingleResp.class);
        var now = Instant.now();
        var thisUpdateWithinAgeLimit = getThisUpdateWithinAgeLimit(now);
        var beforeThisUpdate = new Date(thisUpdateWithinAgeLimit.getTime() - 1000);
        when(mockResponse.getThisUpdate()).thenReturn(thisUpdateWithinAgeLimit);
        when(mockResponse.getNextUpdate()).thenReturn(beforeThisUpdate);
        assertThatExceptionOfType(UserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() ->
                validateCertificateStatusUpdateTime(mockResponse, TIME_SKEW, THIS_UPDATE_AGE, LONG_NEXT_UPDATE_AGE, OCSP_URL))
            .withMessageStartingWith("User certificate revocation check has failed: "
                + "Certificate status update time check failed: "
                + "nextUpdate '" + beforeThisUpdate.toInstant() + "' is before thisUpdate '" + thisUpdateWithinAgeLimit.toInstant() + "'");
    }

    @Test
    void whenThisUpdateHalfHourBeforeNow_thenThrows() {
        final SingleResp mockResponse = mock(SingleResp.class);
        var now = Instant.now();
        var halfHourBeforeNow = Date.from(now.minus(30, ChronoUnit.MINUTES));
        when(mockResponse.getThisUpdate()).thenReturn(halfHourBeforeNow);
        assertThatExceptionOfType(UserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() ->
                validateCertificateStatusUpdateTime(mockResponse, TIME_SKEW, THIS_UPDATE_AGE, NEXT_UPDATE_AGE, OCSP_URL))
            .withMessageStartingWith("User certificate revocation check has failed: "
                + "Certificate status update time check failed: "
                + "thisUpdate '" + halfHourBeforeNow.toInstant() + "' is too old, minimum time allowed: ");
    }

    @Test
    void whenThisUpdateHalfHourAfterNow_thenThrows() {
        final SingleResp mockResponse = mock(SingleResp.class);
        var now = Instant.now();
        var halfHourAfterNow = Date.from(now.plus(30, ChronoUnit.MINUTES));
        when(mockResponse.getThisUpdate()).thenReturn(halfHourAfterNow);
        assertThatExceptionOfType(UserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() ->
                validateCertificateStatusUpdateTime(mockResponse, TIME_SKEW, THIS_UPDATE_AGE, NEXT_UPDATE_AGE, OCSP_URL))
            .withMessageStartingWith("User certificate revocation check has failed: "
                + "Certificate status update time check failed: "
                + "thisUpdate '" + halfHourAfterNow.toInstant() + "' is too far in the future, latest allowed: ");
    }

    @Test
    void whenNextUpdateIsNull_thenValidationSucceeds() {
        final SingleResp mockResponse = mock(SingleResp.class);
        var now = Instant.now();
        when(mockResponse.getThisUpdate()).thenReturn(getThisUpdateWithinAgeLimit(now));
        when(mockResponse.getNextUpdate()).thenReturn(null);
        assertThatCode(() -> validateCertificateStatusUpdateTime(mockResponse, TIME_SKEW, THIS_UPDATE_AGE, NEXT_UPDATE_AGE, OCSP_URL))
            .doesNotThrowAnyException();
    }

    @Test
    void whenNextUpdateHalfHourBeforeNow_thenThrows() {
        final SingleResp mockResponse = mock(SingleResp.class);
        var now = Instant.now();
        var thisUpdateWithinAgeLimit = getThisUpdateWithinAgeLimit(now);
        var halfHourBeforeNow = Date.from(now.minus(30, ChronoUnit.MINUTES));
        when(mockResponse.getThisUpdate()).thenReturn(thisUpdateWithinAgeLimit);
        when(mockResponse.getNextUpdate()).thenReturn(halfHourBeforeNow);
        assertThatExceptionOfType(UserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() ->
                validateCertificateStatusUpdateTime(mockResponse, TIME_SKEW, THIS_UPDATE_AGE, NEXT_UPDATE_AGE, OCSP_URL))
            .withMessageStartingWith("User certificate revocation check has failed: "
                + "Certificate status update time check failed: "
                + "nextUpdate '" + halfHourBeforeNow.toInstant() + "' is too old, minimum time allowed: '");
    }

    @Test
    void whenNextUpdateOlderThanMaxNextUpdateAgeButWithinTimeSkew_thenThrows() {
        final SingleResp mockResponse = mock(SingleResp.class);
        var now = Instant.now();
        var thisUpdateBeforeNextUpdate = Date.from(now.minus(14, ChronoUnit.MINUTES));
        var nextUpdateWithinTimeSkewButTooOld = Date.from(now.minus(10, ChronoUnit.MINUTES));
        when(mockResponse.getThisUpdate()).thenReturn(thisUpdateBeforeNextUpdate);
        when(mockResponse.getNextUpdate()).thenReturn(nextUpdateWithinTimeSkewButTooOld);
        assertThatExceptionOfType(UserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() ->
                validateCertificateStatusUpdateTime(mockResponse, TIME_SKEW, TIME_SKEW, SHORT_NEXT_UPDATE_AGE, OCSP_URL))
            .withMessageStartingWith("User certificate revocation check has failed: "
                + "Certificate status update time check failed: "
                + "nextUpdate '" + nextUpdateWithinTimeSkewButTooOld.toInstant() + "' is too old, minimum time allowed: '");
    }

    @Test
    void whenNextUpdateOlderThanTimeSkewButWithinMaxNextUpdateAge_thenValidationSucceeds() {
        final SingleResp mockResponse = mock(SingleResp.class);
        var now = Instant.now();
        var thisUpdateOlderThanTimeSkew = Date.from(now.minus(25, ChronoUnit.MINUTES));
        var nextUpdateOlderThanTimeSkew = Date.from(now.minus(20, ChronoUnit.MINUTES));
        when(mockResponse.getThisUpdate()).thenReturn(thisUpdateOlderThanTimeSkew);
        when(mockResponse.getNextUpdate()).thenReturn(nextUpdateOlderThanTimeSkew);
        assertThatCode(() ->
            validateCertificateStatusUpdateTime(mockResponse, TIME_SKEW, LONG_THIS_UPDATE_AGE, LONG_NEXT_UPDATE_AGE, OCSP_URL))
            .doesNotThrowAnyException();
    }

    @Test
    void whenOcspResponseStatusIsUnknown_ThenThrowsUserCertificateOCSPCheckFailedException() throws Exception {
        SingleResp unknownCertStatus = getUnknownCertStatusResponse();
        assertThatExceptionOfType(UserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() ->
                validateSubjectCertificateStatus(unknownCertStatus, OCSP_URL))
            .withMessage("User certificate revocation check has failed: Unknown status (OCSP responder: https://example.org)");
    }

    @Test
    void whenCertIsNotCA_thenBasicConstraintsValidationSucceeds() throws Exception {
        final X509Certificate cert = buildCertificate(
            new Extension(Extension.basicConstraints, true, new BasicConstraints(false).getEncoded()));
        assertThatCode(() -> validateBasicConstraintsNotCA(cert)).doesNotThrowAnyException();
    }

    @Test
    void whenBasicConstraintsExtensionAbsent_thenBasicConstraintsValidationSucceeds() throws Exception {
        final X509Certificate cert = buildCertificate();
        assertThatCode(() -> validateBasicConstraintsNotCA(cert)).doesNotThrowAnyException();
    }

    @Test
    void whenCertIsCA_thenBasicConstraintsValidationThrows() throws Exception {
        final X509Certificate cert = buildCertificate(
            new Extension(Extension.basicConstraints, true, new BasicConstraints(0).getEncoded()));
        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() -> validateBasicConstraintsNotCA(cert))
            .withMessage("Certificate " + cert.getSubjectX500Principal() +
                " must not be a CA certificate (Basic Constraints CA:TRUE is not allowed for OCSP responder)");
    }

    @Test
    void whenCertIsNull_thenBasicConstraintsValidationThrowsNullPointerException() {
        assertThatNullPointerException().isThrownBy(() -> validateBasicConstraintsNotCA(null))
            .withMessage("certificate");
    }

    @Test
    void whenCertHasKeyUsageDigitalSignature_thenKeyUsageValidationSucceeds() throws Exception {
        final X509Certificate cert = buildCertificate(
            new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature).getEncoded()));
        assertThatCode(() -> validateKeyUsageDigitalSignature(cert)).doesNotThrowAnyException();
    }

    @Test
    void whenKeyUsageExtensionAbsent_thenKeyUsageValidationThrows() throws Exception {
        final X509Certificate cert = buildCertificate();
        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() -> validateKeyUsageDigitalSignature(cert))
            .withMessage("Certificate " + cert.getSubjectX500Principal() +
                " does not contain the Key Usage extension required for OCSP response signing");
    }

    @Test
    void whenCertMissingKeyUsageDigitalSignature_thenKeyUsageValidationThrows() throws Exception {
        final X509Certificate cert = buildCertificate(
            new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.nonRepudiation).getEncoded()));
        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() -> validateKeyUsageDigitalSignature(cert))
            .withMessage("Certificate " + cert.getSubjectX500Principal() +
                " Key Usage extension does not contain Digital Signature, which is required for OCSP response signing");
    }

    @Test
    void whenCertKeyUsageBitStringEmpty_thenKeyUsageValidationThrows() throws Exception {
        final X509Certificate cert = buildCertificate(
            new Extension(Extension.keyUsage, true, new DLBitString(new byte[0]).getEncoded()));
        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() -> validateKeyUsageDigitalSignature(cert))
            .withMessage("Certificate " + cert.getSubjectX500Principal() +
                " Key Usage extension does not contain Digital Signature, which is required for OCSP response signing");
    }

    @Test
    void whenCertIsNull_thenKeyUsageValidationThrowsNullPointerException() {
        assertThatNullPointerException().isThrownBy(() -> validateKeyUsageDigitalSignature(null))
            .withMessage("certificate");
    }

    @Test
    void whenCertHasNoKeyUsageKeyCertSign_thenKeyCertSignValidationSucceeds() throws Exception {
        final X509Certificate cert = buildCertificate(
            new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature).getEncoded()));
        assertThatCode(() -> validateKeyUsageNotCertificateSigning(cert)).doesNotThrowAnyException();
    }

    @Test
    void whenKeyUsageExtensionAbsent_thenKeyCertSignValidationSucceeds() throws Exception {
        final X509Certificate cert = buildCertificate();
        assertThatCode(() -> validateKeyUsageNotCertificateSigning(cert)).doesNotThrowAnyException();
    }

    @Test
    void whenCertKeyUsageBitStringEmpty_thenKeyCertSignValidationSucceeds() throws Exception {
        final X509Certificate cert = buildCertificate(
            new Extension(Extension.keyUsage, true, new DLBitString(new byte[0]).getEncoded()));
        assertThatCode(() -> validateKeyUsageNotCertificateSigning(cert)).doesNotThrowAnyException();
    }

    @Test
    void whenCertHasKeyUsageKeyCertSign_thenKeyCertSignValidationThrows() throws Exception {
        final X509Certificate cert = buildCertificate(
            new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign).getEncoded()));
        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() -> validateKeyUsageNotCertificateSigning(cert))
            .withMessage("Certificate " + cert.getSubjectX500Principal() +
                " Key Usage extension contains Certificate Signing, which is not allowed for OCSP responder");
    }

    @Test
    void whenCertHasKeyUsageKeyCertSignCombinedWithDigitalSignature_thenKeyCertSignValidationThrows() throws Exception {
        final X509Certificate cert = buildCertificate(
            new Extension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign).getEncoded()));
        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() -> validateKeyUsageNotCertificateSigning(cert))
            .withMessage("Certificate " + cert.getSubjectX500Principal() +
                " Key Usage extension contains Certificate Signing, which is not allowed for OCSP responder");
    }

    @Test
    void whenCertIsNull_thenKeyCertSignValidationThrowsNullPointerException() {
        assertThatNullPointerException().isThrownBy(() -> validateKeyUsageNotCertificateSigning(null))
            .withMessage("certificate");
    }

    @Test
    void whenCertHasOcspSigningEku_thenExtendedKeyUsageValidationSucceeds() throws Exception {
        final X509Certificate cert = buildCertificate(
            new Extension(Extension.extendedKeyUsage, true,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning).getEncoded()));
        assertThatCode(() -> validateExtendedKeyUsageOcspSigning(cert)).doesNotThrowAnyException();
    }

    @Test
    void whenExtendedKeyUsageExtensionAbsent_thenExtendedKeyUsageValidationThrows() throws Exception {
        final X509Certificate cert = buildCertificate();
        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() -> validateExtendedKeyUsageOcspSigning(cert))
            .withMessage("Certificate " + cert.getSubjectX500Principal() +
                " does not contain the Extended Key Usage extension required for OCSP response signing");
    }

    @Test
    void whenCertMissingOcspSigningEku_thenExtendedKeyUsageValidationThrows() throws Exception {
        final X509Certificate cert = buildCertificate(
            new Extension(Extension.extendedKeyUsage, true,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth).getEncoded()));
        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() -> validateExtendedKeyUsageOcspSigning(cert))
            .withMessage("Certificate " + cert.getSubjectX500Principal() +
                " Extended Key Usage extension does not contain OCSP Signing, which is required for OCSP response signing");
    }

    @Test
    void whenCertIsNull_thenExtendedKeyUsageValidationThrowsNullPointerException() {
        assertThatNullPointerException().isThrownBy(() -> validateExtendedKeyUsageOcspSigning(null))
            .withMessage("certificate");
    }

    @Test
    void whenRevokedStatusHasNoReason_thenThrows() {
        final SingleResp mockResponse = mock(SingleResp.class);
        when(mockResponse.getCertStatus()).thenReturn(new RevokedStatus(new Date()));
        assertThatExceptionOfType(UserCertificateRevokedException.class)
            .isThrownBy(() ->
                validateSubjectCertificateStatus(mockResponse, OCSP_URL))
            .withMessage("User certificate has been revoked (OCSP responder: https://example.org)");
    }

    @Test
    void whenStatusIsNeitherGoodRevokedNorUnknown_thenThrowsUserCertificateOCSPCheckFailedException() {
        final SingleResp mockResponse = mock(SingleResp.class);
        when(mockResponse.getCertStatus()).thenReturn(new UnexpectedCertificateStatus());
        assertThatExceptionOfType(UserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() ->
                validateSubjectCertificateStatus(mockResponse, OCSP_URL))
            .withMessage("User certificate revocation check has failed: Status is neither good, revoked nor unknown (OCSP responder: https://example.org)");
    }

    private static Date getThisUpdateWithinAgeLimit(Instant now) {
        return Date.from(now.minus(THIS_UPDATE_AGE.minusSeconds(1)));
    }

    private static SingleResp getUnknownCertStatusResponse() throws Exception {
        final OCSPResp ocspRespUnknown = new OCSPResp(bytesFromResource("ocsp_response_unknown.der"));
        final BasicOCSPResp basicResponse = (BasicOCSPResp) ocspRespUnknown.getResponseObject();
        return basicResponse.getResponses()[0];
    }

    private static class UnexpectedCertificateStatus implements CertificateStatus {
    }

}
