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

import eu.webeid.security.exceptions.CertificateExpiredException;
import eu.webeid.security.exceptions.CertificateNotTrustedException;
import eu.webeid.security.exceptions.JceException;
import eu.webeid.security.exceptions.UserCertificateOCSPCheckFailedException;
import eu.webeid.security.exceptions.UserCertificateRevokedException;
import eu.webeid.security.util.DateAndTime;
import eu.webeid.security.validator.ocsp.OcspClient;
import eu.webeid.security.validator.ocsp.OcspClientImpl;
import eu.webeid.security.validator.ocsp.OcspServiceProvider;
import eu.webeid.security.validator.ocsp.ResilientOcspService;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.net.ConnectException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpHeaders;
import java.net.http.HttpResponse;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static eu.webeid.security.testutil.Certificates.getJaakKristjanEsteid2018Cert;
import static eu.webeid.security.testutil.Certificates.getTestEsteid2018CA;
import static eu.webeid.security.testutil.DateMocker.mockDate;
import static eu.webeid.security.testutil.OcspServiceMaker.getAiaOcspServiceProvider;
import static eu.webeid.security.testutil.OcspServiceMaker.getDesignatedOcspServiceProvider;
import static eu.webeid.security.validator.AuthTokenValidatorBuilderTest.CONFIGURATION;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

class SubjectCertificateNotRevokedValidatorTest {

    private final OcspClient ocspClient = OcspClientImpl.build(Duration.ofSeconds(5));
    private SubjectCertificateTrustedValidator trustedValidator;
    private X509Certificate estEid2018Cert;

    @BeforeEach
    void setUp() throws Exception {
        trustedValidator = new SubjectCertificateTrustedValidator(null, null);
        setSubjectCertificateIssuerCertificate(trustedValidator);
        estEid2018Cert = getJaakKristjanEsteid2018Cert();
    }

    @Test
    void whenValidAiaOcspResponderConfiguration_thenSucceeds() throws Exception {
        final SubjectCertificateNotRevokedValidator validator = getSubjectCertificateNotRevokedValidator(ocspClient, getAiaOcspServiceProvider());
        assertThatCode(() ->
            validator.validateCertificateNotRevoked(estEid2018Cert))
            .doesNotThrowAnyException();
    }

    @Test
    @Disabled("As new designated test OCSP responder certificates are issued more frequently now, it is no longer feasible to keep the certificates up to date")
    void whenValidDesignatedOcspResponderConfiguration_thenSucceeds() throws Exception {
        final OcspServiceProvider ocspServiceProvider = getDesignatedOcspServiceProvider();
        final SubjectCertificateNotRevokedValidator validator = getSubjectCertificateNotRevokedValidator(ocspServiceProvider);
        assertThatCode(() ->
            validator.validateCertificateNotRevoked(estEid2018Cert))
            .doesNotThrowAnyException();
    }

    @Test
    @Disabled("As new designated test OCSP responder certificates are issued more frequently now, it is no longer feasible to keep the certificates up to date")
    void whenValidOcspNonceDisabledConfiguration_thenSucceeds() throws Exception {
        final OcspServiceProvider ocspServiceProvider = getDesignatedOcspServiceProvider(false);
        final SubjectCertificateNotRevokedValidator validator = getSubjectCertificateNotRevokedValidator(ocspServiceProvider);
        assertThatCode(() ->
            validator.validateCertificateNotRevoked(estEid2018Cert))
            .doesNotThrowAnyException();
    }

    @Test
    void whenOcspUrlIsInvalid_thenThrows() throws Exception {
        final OcspServiceProvider ocspServiceProvider = getDesignatedOcspServiceProvider("http://invalid.invalid");
        final SubjectCertificateNotRevokedValidator validator = getSubjectCertificateNotRevokedValidator(ocspServiceProvider);
        assertThatCode(() ->
            validator.validateCertificateNotRevoked(estEid2018Cert))
            .isInstanceOf(UserCertificateOCSPCheckFailedException.class)
            .cause()
            .isInstanceOf(ConnectException.class);
    }

    @Test
    void whenOcspRequestFails_thenThrows() throws Exception {
        final OcspServiceProvider ocspServiceProvider = getDesignatedOcspServiceProvider("http://demo.sk.ee/ocsps");
        final SubjectCertificateNotRevokedValidator validator = getSubjectCertificateNotRevokedValidator(ocspServiceProvider);
        assertThatCode(() ->
            validator.validateCertificateNotRevoked(estEid2018Cert))
            .isInstanceOf(UserCertificateOCSPCheckFailedException.class)
            .cause()
            .isInstanceOf(IOException.class)
            .hasMessageStartingWith("OCSP request was not successful, response: (POST http://demo.sk.ee/ocsps) 404");
    }

    @Test
    void whenOcspRequestHasInvalidBody_thenThrows() throws Exception {
        final SubjectCertificateNotRevokedValidator validator = getSubjectCertificateNotRevokedValidatorWithAiaOcsp(
            getMockedResponse("invalid".getBytes())
        );
        assertThatCode(() ->
            validator.validateCertificateNotRevoked(estEid2018Cert))
            .isInstanceOf(UserCertificateOCSPCheckFailedException.class)
            .cause()
            .isInstanceOf(IOException.class)
            .hasMessage("DEF length 110 object truncated by 105");
    }

    @Test
    void whenOcspResponseIsNotSuccessful_thenThrows() throws Exception {
        final SubjectCertificateNotRevokedValidator validator = getSubjectCertificateNotRevokedValidatorWithAiaOcsp(
            getMockedResponse(buildOcspResponseBodyWithInternalErrorStatus())
        );
        assertThatExceptionOfType(UserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() ->
                validator.validateCertificateNotRevoked(estEid2018Cert))
            .withMessage("User certificate revocation check has failed: Response status: internal error");
    }

    @Test
    void whenOcspResponseHasInvalidCertificateId_thenThrows() throws Exception {
        final SubjectCertificateNotRevokedValidator validator = getSubjectCertificateNotRevokedValidatorWithAiaOcsp(
            getMockedResponse(buildOcspResponseBodyWithInvalidCertificateId())
        );
        assertThatExceptionOfType(UserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() ->
                validator.validateCertificateNotRevoked(estEid2018Cert))
            .withMessage("User certificate revocation check has failed: OCSP responded with certificate ID that differs from the requested ID");
    }

    @Test
    void whenOcspResponseHasInvalidSignature_thenThrows() throws Exception {
        final SubjectCertificateNotRevokedValidator validator = getSubjectCertificateNotRevokedValidatorWithAiaOcsp(
            getMockedResponse(buildOcspResponseBodyWithInvalidSignature())
        );
        assertThatExceptionOfType(UserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() ->
                validator.validateCertificateNotRevoked(estEid2018Cert))
            .withMessage("User certificate revocation check has failed: OCSP response signature is invalid");
    }

    @Test
    void whenOcspResponseHasInvalidResponderCert_thenThrows() throws Exception {
        final SubjectCertificateNotRevokedValidator validator = getSubjectCertificateNotRevokedValidatorWithAiaOcsp(
            getMockedResponse(buildOcspResponseBodyWithInvalidResponderCert())
        );
        assertThatCode(() ->
            validator.validateCertificateNotRevoked(estEid2018Cert))
            .isInstanceOf(UserCertificateOCSPCheckFailedException.class)
            .cause()
            .isInstanceOf(OCSPException.class)
            .hasMessage("exception processing sig: java.lang.IllegalArgumentException: invalid info structure in RSA public key");
    }

    @Test
    void whenOcspResponseHasInvalidTag_thenThrows() throws Exception {
        final SubjectCertificateNotRevokedValidator validator = getSubjectCertificateNotRevokedValidatorWithAiaOcsp(
            getMockedResponse(buildOcspResponseBodyWithInvalidTag())
        );
        assertThatCode(() ->
            validator.validateCertificateNotRevoked(estEid2018Cert))
            .isInstanceOf(UserCertificateOCSPCheckFailedException.class)
            .cause()
            .isInstanceOf(OCSPException.class)
            .hasMessage("problem decoding object: java.io.IOException: unknown tag 23 encountered");
    }

    @Test
    void whenOcspResponseHas2CertResponses_thenThrows() throws Exception {
        final SubjectCertificateNotRevokedValidator validator = getSubjectCertificateNotRevokedValidatorWithAiaOcsp(
            getMockedResponse(getOcspResponseBytesFromResources("ocsp_response_with_2_responses.der"))
        );
        assertThatExceptionOfType(UserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() ->
                validator.validateCertificateNotRevoked(estEid2018Cert))
            .withMessage("User certificate revocation check has failed: OCSP response must contain one response, received 2 responses instead");
    }

    @Disabled("It is difficult to make Python and Java CertId equal, needs more work")
    void whenOcspResponseHas2ResponderCerts_thenThrows() throws Exception {
        final SubjectCertificateNotRevokedValidator validator = getSubjectCertificateNotRevokedValidatorWithAiaOcsp(
            getMockedResponse(getOcspResponseBytesFromResources("ocsp_response_with_2_responder_certs.der"))
        );
        assertThatExceptionOfType(UserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() ->
                validator.validateCertificateNotRevoked(estEid2018Cert))
            .withMessage("User certificate revocation check has failed: OCSP response must contain one responder certificate, received 2 certificates instead");
    }

    @Test
    void whenOcspResponseRevoked_thenThrows() throws Exception {
        final SubjectCertificateNotRevokedValidator validator = getSubjectCertificateNotRevokedValidatorWithAiaOcsp(
            getMockedResponse(getOcspResponseBytesFromResources("ocsp_response_revoked.der"))
        );
        try (var mockedClock = mockStatic(DateAndTime.DefaultClock.class)) {
            mockDate("2021-09-18", mockedClock);
            assertThatExceptionOfType(UserCertificateRevokedException.class)
                .isThrownBy(() ->
                    validator.validateCertificateNotRevoked(estEid2018Cert))
                .withMessage("User certificate has been revoked: Revocation reason: 0");
        }
    }

    @Test
    void whenOcspResponseUnknown_thenThrows() throws Exception {
        final OcspServiceProvider ocspServiceProvider = getDesignatedOcspServiceProvider("https://web-eid-test.free.beeceptor.com");
        final HttpResponse<byte[]> response = getMockedResponse(getOcspResponseBytesFromResources("ocsp_response_unknown.der"));
        final SubjectCertificateNotRevokedValidator validator = getSubjectCertificateNotRevokedValidator(getMockClient(response), ocspServiceProvider);
        try (var mockedClock = mockStatic(DateAndTime.DefaultClock.class)) {
            mockDate("2021-09-18T00:16:25", mockedClock);
            assertThatExceptionOfType(UserCertificateRevokedException.class)
                .isThrownBy(() ->
                    validator.validateCertificateNotRevoked(estEid2018Cert))
                .withMessage("User certificate has been revoked: Unknown status");
        }
    }

    @Test
    void whenOcspResponseCACertNotTrusted_thenThrows() throws Exception {
        final SubjectCertificateNotRevokedValidator validator = getSubjectCertificateNotRevokedValidatorWithAiaOcsp(
            getMockedResponse(getOcspResponseBytesFromResources("ocsp_response_unknown.der"))
        );
        try (var mockedClock = mockStatic(DateAndTime.DefaultClock.class)) {
            mockDate("2021-09-18T00:16:25", mockedClock);
            assertThatExceptionOfType(CertificateNotTrustedException.class)
                .isThrownBy(() ->
                    validator.validateCertificateNotRevoked(estEid2018Cert))
                .withMessage("Certificate EMAILADDRESS=pki@sk.ee, CN=TEST of SK OCSP RESPONDER 2020, OU=OCSP, O=AS Sertifitseerimiskeskus, C=EE is not trusted");
        }
    }

    @Test
    void whenOcspResponseCACertExpired_thenThrows() throws Exception {
        final SubjectCertificateNotRevokedValidator validator = getSubjectCertificateNotRevokedValidatorWithAiaOcsp(
            getMockedResponse(getOcspResponseBytesFromResources("ocsp_response_unknown.der"))
        );
        assertThatExceptionOfType(CertificateExpiredException.class)
            .isThrownBy(() ->
                validator.validateCertificateNotRevoked(estEid2018Cert))
            .withMessage("AIA OCSP responder certificate has expired");
    }

    @Test
    void whenNonceDiffers_thenThrows() throws Exception {
        final SubjectCertificateNotRevokedValidator validator = getSubjectCertificateNotRevokedValidatorWithAiaOcsp(
            getMockedResponse(getOcspResponseBytesFromResources())
        );
        try (var mockedClock = mockStatic(DateAndTime.DefaultClock.class)) {
            mockDate("2021-09-17T18:25:24", mockedClock);
            assertThatExceptionOfType(UserCertificateOCSPCheckFailedException.class)
                .isThrownBy(() ->
                    validator.validateCertificateNotRevoked(estEid2018Cert))
                .withMessage("User certificate revocation check has failed: OCSP request and response nonces differ, possible replay attack");
        }
    }

    private static byte[] buildOcspResponseBodyWithInternalErrorStatus() throws IOException {
        final byte[] ocspResponseBytes = getOcspResponseBytesFromResources();
        final int STATUS_OFFSET = 6;
        ocspResponseBytes[STATUS_OFFSET] = OCSPResponseStatus.INTERNAL_ERROR;
        return ocspResponseBytes;
    }

    private static byte[] buildOcspResponseBodyWithInvalidCertificateId() throws IOException {
        final byte[] ocspResponseBytes = getOcspResponseBytesFromResources();
        final int CERTIFICATE_ID_OFFSET = 234;
        ocspResponseBytes[CERTIFICATE_ID_OFFSET + 3] = 0x42;
        return ocspResponseBytes;
    }

    private byte[] buildOcspResponseBodyWithInvalidSignature() throws IOException {
        final byte[] ocspResponseBytes = getOcspResponseBytesFromResources();
        final int SIGNATURE_OFFSET = 349;
        ocspResponseBytes[SIGNATURE_OFFSET + 5] = 0x01;
        return ocspResponseBytes;
    }

    private byte[] buildOcspResponseBodyWithInvalidResponderCert() throws IOException {
        final byte[] ocspResponseBytes = getOcspResponseBytesFromResources();
        final int CERTIFICATE_OFFSET = 935;
        ocspResponseBytes[CERTIFICATE_OFFSET + 3] = 0x42;
        return ocspResponseBytes;
    }

    private byte[] buildOcspResponseBodyWithInvalidTag() throws IOException {
        final byte[] ocspResponseBytes = getOcspResponseBytesFromResources();
        final int TAG_OFFSET = 352;
        ocspResponseBytes[TAG_OFFSET] = 0x42;
        return ocspResponseBytes;
    }

    // Either write the bytes of a real OCSP response to a file or use Python and asn1crypto.ocsp
    // to create a mock response, see OCSPBuilder in https://github.com/wbond/ocspbuilder/blob/master/ocspbuilder/__init__.py
    // and https://gist.github.com/mrts/bb0dcf93a2b9d2458eab1f9642ee97b2.
    private static byte[] getOcspResponseBytesFromResources() throws IOException {
        return getOcspResponseBytesFromResources("ocsp_response.der");
    }

    private static byte[] getOcspResponseBytesFromResources(String resource) throws IOException {
        try (final InputStream resourceAsStream = ClassLoader.getSystemResourceAsStream(resource)) {
            return toByteArray(resourceAsStream);
        }
    }

    private SubjectCertificateNotRevokedValidator getSubjectCertificateNotRevokedValidatorWithAiaOcsp(HttpResponse<byte[]> response) throws JceException {
        return getSubjectCertificateNotRevokedValidator(getMockClient(response), getAiaOcspServiceProvider());
    }

    private SubjectCertificateNotRevokedValidator getSubjectCertificateNotRevokedValidator(OcspServiceProvider ocspServiceProvider) {
        return getSubjectCertificateNotRevokedValidator(ocspClient, ocspServiceProvider);
    }

    private SubjectCertificateNotRevokedValidator getSubjectCertificateNotRevokedValidator(OcspClient client, OcspServiceProvider ocspServiceProvider) {
        ResilientOcspService resilientOcspService = new ResilientOcspService(client, ocspServiceProvider, null, CONFIGURATION.getAllowedOcspResponseTimeSkew(), CONFIGURATION.getMaxOcspResponseThisUpdateAge());
        return new SubjectCertificateNotRevokedValidator(resilientOcspService, trustedValidator);
    }

    private static void setSubjectCertificateIssuerCertificate(SubjectCertificateTrustedValidator trustedValidator) throws NoSuchFieldException, IllegalAccessException, CertificateException, IOException {
        final Field field = trustedValidator.getClass().getDeclaredField("subjectCertificateIssuerCertificate");
        field.setAccessible(true);
        field.set(trustedValidator, getTestEsteid2018CA());
    }

    private HttpResponse<byte[]> getMockedResponse(byte[] bodyContent) throws URISyntaxException {
        @SuppressWarnings("unchecked")
        final HttpResponse<byte[]> mockResponse = mock(HttpResponse.class);

        final HttpHeaders headers = HttpHeaders.of(
            Map.of("Content-Type", List.of("application/ocsp-response")),
            (k, v) -> true
        );

        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn(bodyContent);
        when(mockResponse.uri()).thenReturn(new URI("http://testing"));
        when(mockResponse.headers()).thenReturn(headers);

        return mockResponse;
    }

    private OcspClient getMockClient(HttpResponse<byte[]> response) {
        return (url, request) -> new OCSPResp(Objects.requireNonNull(response.body()));
    }

    private static byte[] toByteArray(InputStream resourceAsStream) throws IOException {
        Objects.requireNonNull(resourceAsStream);
        int bytesAvailable = resourceAsStream.available();
        byte[] result = new byte[bytesAvailable];
        int bytesRead = resourceAsStream.read(result);
        if (bytesRead != bytesAvailable) {
            throw new RuntimeException("Short read while loading resources");
        }
        return result;
    }

}
