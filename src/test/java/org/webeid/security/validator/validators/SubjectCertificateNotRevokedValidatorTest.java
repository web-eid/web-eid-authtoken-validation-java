package org.webeid.security.validator.validators;

import com.google.common.io.ByteStreams;
import okhttp3.*;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.webeid.security.exceptions.*;
import org.webeid.security.validator.AuthTokenValidatorData;
import org.webeid.security.validator.ocsp.OcspClient;
import org.webeid.security.validator.ocsp.OcspClientImpl;
import org.webeid.security.validator.ocsp.OcspServiceProvider;
import org.webeid.security.validator.ocsp.service.AiaOcspResponderConfiguration;
import org.webeid.security.validator.ocsp.service.AiaOcspServiceConfiguration;
import org.webeid.security.validator.ocsp.service.DesignatedOcspServiceConfiguration;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.time.Duration;
import java.util.Objects;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.webeid.security.testutil.Certificates.*;

class SubjectCertificateNotRevokedValidatorTest {

    private static final MediaType OCSP_RESPONSE = MediaType.get("application/ocsp-response");

    private final OcspClient ocspClient = OcspClientImpl.build(Duration.ofSeconds(5));
    private SubjectCertificateTrustedValidator trustedValidator;
    private AuthTokenValidatorData authTokenValidatorWithEsteid2018Cert;

    @BeforeEach
    void setUp() throws Exception {
        trustedValidator = new SubjectCertificateTrustedValidator(null, null);
        setSubjectCertificateIssuerCertificate(trustedValidator);
        authTokenValidatorWithEsteid2018Cert = new AuthTokenValidatorData(getJaakKristjanEsteid2018Cert());
    }

    @Test
    void whenValidAiaOcspResponderConfiguration_thenSucceeds() throws Exception {
        final SubjectCertificateNotRevokedValidator validator = getSubjectCertificateNotRevokedValidatorWithAiaOcsp(ocspClient);
        assertThatCode(() ->
            validator.validateCertificateNotRevoked(authTokenValidatorWithEsteid2018Cert))
            .doesNotThrowAnyException();
    }

    @Test
    void whenValidDesignatedOcspResponderConfiguration_thenSucceeds() throws Exception {
        final OcspServiceProvider ocspServiceProvider = new OcspServiceProvider(
            new DesignatedOcspServiceConfiguration(new URI("http://demo.sk.ee/ocsp"), getTestSkOcspResponder2020()));
        final SubjectCertificateNotRevokedValidator validator = new SubjectCertificateNotRevokedValidator(trustedValidator, ocspClient, ocspServiceProvider);
        assertThatCode(() ->
            validator.validateCertificateNotRevoked(authTokenValidatorWithEsteid2018Cert))
            .doesNotThrowAnyException();
    }

    @Test
    void whenValidOcspNonceDisabledConfiguration_thenSucceeds() throws Exception {
        final OcspServiceProvider ocspServiceProvider = new OcspServiceProvider(
            new DesignatedOcspServiceConfiguration(new URI("http://demo.sk.ee/ocsp"), getTestSkOcspResponder2020(), false));
        final SubjectCertificateNotRevokedValidator validator = new SubjectCertificateNotRevokedValidator(trustedValidator, ocspClient, ocspServiceProvider);
        assertThatCode(() ->
            validator.validateCertificateNotRevoked(authTokenValidatorWithEsteid2018Cert))
            .doesNotThrowAnyException();
    }

    @Test
    void whenOcspUrlIsInvalid_thenThrows() throws Exception {
        final OcspServiceProvider ocspServiceProvider = new OcspServiceProvider(
            new DesignatedOcspServiceConfiguration(new URI("http://invalid.invalid-tld"), getTestSkOcspResponder2020()));
        final SubjectCertificateNotRevokedValidator validator = new SubjectCertificateNotRevokedValidator(trustedValidator, ocspClient, ocspServiceProvider);
        assertThatCode(() ->
            validator.validateCertificateNotRevoked(authTokenValidatorWithEsteid2018Cert))
            .isInstanceOf(UserCertificateOCSPCheckFailedException.class)
            .getCause()
            .isInstanceOf(IOException.class)
            .hasMessage("invalid.invalid-tld: Name or service not known");
    }

    @Test
    void whenOcspRequestFails_thenThrows() throws Exception {
        final OcspServiceProvider ocspServiceProvider = new OcspServiceProvider(
            new DesignatedOcspServiceConfiguration(new URI("https://web-eid-test.free.beeceptor.com"), getTestSkOcspResponder2020()));
        final SubjectCertificateNotRevokedValidator validator = new SubjectCertificateNotRevokedValidator(trustedValidator, ocspClient, ocspServiceProvider);
        assertThatCode(() ->
            validator.validateCertificateNotRevoked(authTokenValidatorWithEsteid2018Cert))
            .isInstanceOf(UserCertificateOCSPCheckFailedException.class)
            .getCause()
            .isInstanceOf(IOException.class)
            .hasMessageStartingWith("OCSP request was not successful, response: Response{");
    }

    @Test
    void whenOcspRequestHasInvalidBody_thenThrows() throws Exception {
        final SubjectCertificateNotRevokedValidator validator = getSubjectCertificateNotRevokedValidatorWithAiaOcsp(
            getResponseBuilder()
                .body(ResponseBody.create("invalid", OCSP_RESPONSE))
                .build());
        assertThatCode(() ->
            validator.validateCertificateNotRevoked(authTokenValidatorWithEsteid2018Cert))
            .isInstanceOf(UserCertificateOCSPCheckFailedException.class)
            .getCause()
            .isInstanceOf(IOException.class)
            .hasMessage("corrupted stream - out of bounds length found: 110 >= 7");
    }

    @Test
    void whenOcspResponseIsNotSuccessful_thenThrows() throws Exception {
        final SubjectCertificateNotRevokedValidator validator = getSubjectCertificateNotRevokedValidatorWithAiaOcsp(
            getResponseBuilder()
                .body(ResponseBody.create(buildOcspResponseBodyWithInternalErrorStatus(), OCSP_RESPONSE))
                .build());
        assertThatExceptionOfType(UserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() ->
                validator.validateCertificateNotRevoked(authTokenValidatorWithEsteid2018Cert))
            .withMessage("User certificate revocation check has failed: Response status: internal error");
    }

    @Test
    void whenOcspResponseHasInvalidCertificateId_thenThrows() throws Exception {
        final SubjectCertificateNotRevokedValidator validator = getSubjectCertificateNotRevokedValidatorWithAiaOcsp(
            getResponseBuilder()
                .body(ResponseBody.create(buildOcspResponseBodyWithInvalidCertificateId(), OCSP_RESPONSE))
                .build());
        assertThatExceptionOfType(UserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() ->
                validator.validateCertificateNotRevoked(authTokenValidatorWithEsteid2018Cert))
            .withMessage("User certificate revocation check has failed: OCSP responded with certificate ID that differs from the requested ID");
    }

    @Test
    void whenOcspResponseHasInvalidSignature_thenThrows() throws Exception {
        final SubjectCertificateNotRevokedValidator validator = getSubjectCertificateNotRevokedValidatorWithAiaOcsp(
            getResponseBuilder()
                .body(ResponseBody.create(buildOcspResponseBodyWithInvalidSignature(), OCSP_RESPONSE))
                .build());
        assertThatExceptionOfType(UserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() ->
                validator.validateCertificateNotRevoked(authTokenValidatorWithEsteid2018Cert))
            .withMessage("User certificate revocation check has failed: OCSP response signature is invalid");
    }

    @Test
    void whenOcspResponseHasInvalidResponderCert_thenThrows() throws Exception {
        final SubjectCertificateNotRevokedValidator validator = getSubjectCertificateNotRevokedValidatorWithAiaOcsp(
            getResponseBuilder()
                .body(ResponseBody.create(buildOcspResponseBodyWithInvalidResponderCert(), OCSP_RESPONSE))
                .build());
        assertThatCode(() ->
            validator.validateCertificateNotRevoked(authTokenValidatorWithEsteid2018Cert))
            .isInstanceOf(OCSPCertificateException.class)
            .getCause()
            .isInstanceOf(CertificateParsingException.class)
            .hasMessage("java.io.IOException: subject key, java.security.InvalidKeyException: Invalid RSA public key");
    }

    @Test
    void whenOcspResponseHasInvalidTag_thenThrows() throws Exception {
        final SubjectCertificateNotRevokedValidator validator = getSubjectCertificateNotRevokedValidatorWithAiaOcsp(
            getResponseBuilder()
                .body(ResponseBody.create(buildOcspResponseBodyWithInvalidTag(), OCSP_RESPONSE))
                .build());
        assertThatCode(() ->
            validator.validateCertificateNotRevoked(authTokenValidatorWithEsteid2018Cert))
            .isInstanceOf(UserCertificateOCSPCheckFailedException.class)
            .getCause()
            .isInstanceOf(OCSPException.class)
            .hasMessage("problem decoding object: java.io.IOException: unknown tag 23 encountered");
    }

    @Test
    void whenOcspResponseHas2CertResponses_thenThrows() throws Exception {
        final SubjectCertificateNotRevokedValidator validator = getSubjectCertificateNotRevokedValidatorWithAiaOcsp(
            getResponseBuilder()
                .body(ResponseBody.create(getOcspResponseBytesFromResources("ocsp_response_with_2_responses.der"), OCSP_RESPONSE))
                .build());
        assertThatExceptionOfType(UserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() ->
                validator.validateCertificateNotRevoked(authTokenValidatorWithEsteid2018Cert))
            .withMessage("User certificate revocation check has failed: OCSP response must contain one response, received 2 responses instead");
    }

    @Test
    void whenOcspResponseHas2ResponderCerts_thenThrows() throws Exception {
        final SubjectCertificateNotRevokedValidator validator = getSubjectCertificateNotRevokedValidatorWithAiaOcsp(
            getResponseBuilder()
                .body(ResponseBody.create(getOcspResponseBytesFromResources("ocsp_response_with_2_responder_certs.der"), OCSP_RESPONSE))
                .build());
        assertThatExceptionOfType(UserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() ->
                validator.validateCertificateNotRevoked(authTokenValidatorWithEsteid2018Cert))
            .withMessage("User certificate revocation check has failed: OCSP response must contain one responder certificate, received 2 certificates instead");
    }

    @Test
    void whenOcspResponseRevoked_thenThrows() throws Exception {
        final SubjectCertificateNotRevokedValidator validator = getSubjectCertificateNotRevokedValidatorWithAiaOcsp(
            getResponseBuilder()
                .body(ResponseBody.create(getOcspResponseBytesFromResources("ocsp_response_revoked.der"), OCSP_RESPONSE))
                .build());
        assertThatExceptionOfType(UserCertificateRevokedException.class)
            .isThrownBy(() ->
                validator.validateCertificateNotRevoked(authTokenValidatorWithEsteid2018Cert))
            .withMessage("User certificate has been revoked: Revocation reason: 0");
    }

    @Test
    void whenOcspResponseUnknown_thenThrows() throws Exception {
        final OcspServiceProvider ocspServiceProvider = new OcspServiceProvider(
            new DesignatedOcspServiceConfiguration(new URI("http://demo.sk.ee/ocsp"), getTestSkOcspResponder2020()));
        final Response response = getResponseBuilder()
            .body(ResponseBody.create(getOcspResponseBytesFromResources("ocsp_response_unknown.der"), OCSP_RESPONSE))
            .build();
        final OcspClient client = (url, request) -> new OCSPResp(Objects.requireNonNull(response.body()).bytes());
        final SubjectCertificateNotRevokedValidator validator = new SubjectCertificateNotRevokedValidator(trustedValidator, client, ocspServiceProvider);
        assertThatExceptionOfType(UserCertificateRevokedException.class)
            .isThrownBy(() ->
                validator.validateCertificateNotRevoked(authTokenValidatorWithEsteid2018Cert))
            .withMessage("User certificate has been revoked: Unknown status");
    }

    @Test
    void whenOcspResponseCANotTrusted_thenThrows() throws Exception {
        final SubjectCertificateNotRevokedValidator validator = getSubjectCertificateNotRevokedValidatorWithAiaOcsp(
            getResponseBuilder()
                .body(ResponseBody.create(getOcspResponseBytesFromResources("ocsp_response_unknown.der"), OCSP_RESPONSE))
                .build());
        assertThatExceptionOfType(CertificateNotTrustedException.class)
            .isThrownBy(() ->
                validator.validateCertificateNotRevoked(authTokenValidatorWithEsteid2018Cert))
            .withMessage("Certificate EMAILADDRESS=pki@sk.ee, CN=TEST of SK OCSP RESPONDER 2020, OU=OCSP, O=AS Sertifitseerimiskeskus, C=EE is not trusted");
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
    // to create a mock response, see OCSPBuilder in https://github.com/wbond/ocspbuilder/blob/master/ocspbuilder/__init__.py.
    private static byte[] getOcspResponseBytesFromResources() throws IOException {
        return getOcspResponseBytesFromResources("ocsp_response.der");
    }

    private static byte[] getOcspResponseBytesFromResources(String resource) throws IOException {
        try (final InputStream resourceAsStream = ClassLoader.getSystemResourceAsStream(resource)) {
            return ByteStreams.toByteArray(Objects.requireNonNull(resourceAsStream));
        }
    }

    @NotNull
    private SubjectCertificateNotRevokedValidator getSubjectCertificateNotRevokedValidatorWithAiaOcsp(Response response) throws JceException, URISyntaxException, CertificateException, IOException {
        final OcspClient client = (url, request) -> new OCSPResp(Objects.requireNonNull(response.body()).bytes());
        return getSubjectCertificateNotRevokedValidatorWithAiaOcsp(client);
    }

    @NotNull
    private SubjectCertificateNotRevokedValidator getSubjectCertificateNotRevokedValidatorWithAiaOcsp(OcspClient client) throws JceException, URISyntaxException, CertificateException, IOException {
        final OcspServiceProvider ocspServiceProvider = new OcspServiceProvider(new AiaOcspServiceConfiguration(
            new AiaOcspResponderConfiguration(new URI("http://aia.demo.sk.ee/esteid2018"), getTestEsteid2018CA())));
        return new SubjectCertificateNotRevokedValidator(trustedValidator, client, ocspServiceProvider);
    }

    private static void setSubjectCertificateIssuerCertificate(SubjectCertificateTrustedValidator trustedValidator) throws NoSuchFieldException, IllegalAccessException, CertificateException, IOException {
        final Field field = trustedValidator.getClass().getDeclaredField("subjectCertificateIssuerCertificate");
        field.setAccessible(true);
        field.set(trustedValidator, getTestEsteid2018CA());
    }

    @NotNull
    private static Response.Builder getResponseBuilder() {
        return new Response.Builder()
            .request(new Request.Builder().url("http://testing").build())
            .message("testing")
            .protocol(Protocol.HTTP_1_1)
            .code(200);
    }

}
