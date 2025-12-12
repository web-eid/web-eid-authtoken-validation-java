// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.certificate;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import eu.webeid.ocsp.OcspCertificateRevocationChecker;
import eu.webeid.ocsp.client.OcspClientImpl;
import eu.webeid.ocsp.exceptions.UserCertificateOCSPCheckFailedException;
import eu.webeid.ocsp.service.AiaOcspServiceConfiguration;
import eu.webeid.ocsp.service.DesignatedOcspServiceConfiguration;
import eu.webeid.ocsp.service.OcspServiceProvider;
import eu.webeid.security.exceptions.CertificateRevocationCheckFailedException;
import eu.webeid.security.exceptions.CertificateRevokedException;
import eu.webeid.security.validator.revocationcheck.RevocationInfo;
import eu.webeid.security.validator.revocationcheck.RevocationMode;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.ocsp.ResponseBytes;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Exercises the real JDK and bundled OCSP HTTP clients against a local, signing responder. */
class OcspNetworkTest {

    private final Instant now = Instant.now();
    private final AtomicInteger requestCount = new AtomicInteger();
    private final AtomicReference<OCSPReq> receivedRequest = new AtomicReference<>();
    private final AtomicReference<String> receivedPath = new AtomicReference<>();
    private final AtomicReference<Exception> serverFailure = new AtomicReference<>();
    private HttpServer server;
    private URI aiaUri;
    private URI designatedUri;
    private X509Certificate issuer;
    private X509Certificate subject;
    private X509Certificate responder;
    private KeyPair responderKeys;
    private volatile Reply reply = Reply.GOOD;
    private volatile boolean includeNonce = true;

    private enum Reply { GOOD, REVOKED, TRY_LATER, DISCONNECT, UNSUPPORTED_TYPE, MISSING_RESPONSE }

    @BeforeEach
    void setup() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        aiaUri = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/aia");
        designatedUri = aiaUri.resolve("/designated");

        final KeyPair issuerKeys = newKeys();
        responderKeys = newKeys();
        final X500Name issuerName = new X500Name("CN=Local OCSP test CA");
        final var issuerBuilder = certificateBuilder(issuerName, issuerName, issuerKeys, 1);
        issuerBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        issuerBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        issuer = sign(issuerBuilder, issuerKeys);

        final var subjectBuilder = certificateBuilder(issuerName, new X500Name("CN=Local OCSP test subject"), newKeys(), 2);
        subjectBuilder.addExtension(Extension.authorityInfoAccess, false, new AuthorityInformationAccess(
                AccessDescription.id_ad_ocsp, new GeneralName(GeneralName.uniformResourceIdentifier, aiaUri.toString())));
        subject = sign(subjectBuilder, issuerKeys);

        final var responderBuilder = certificateBuilder(issuerName, new X500Name("CN=Local OCSP test responder"), responderKeys, 3);
        responderBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        responderBuilder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning));
        responder = sign(responderBuilder, issuerKeys);

        server.createContext("/aia", this::respond);
        server.createContext("/designated", this::respond);
        server.start();
    }

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
        assertThat(serverFailure.get()).as("Local responder failure").isNull();
    }

    @ParameterizedTest
    @EnumSource(value = RevocationMode.class, names = {"PLATFORM_OCSP", "CUSTOM_CHECKER"})
    void whenResponderReturnsGood_thenValidationSendsRequestAndSucceeds(RevocationMode mode) throws Exception {
        final List<RevocationInfo> info = validate(mode, true);

        assertRequestReachedResponder(mode);
        assertThat(receivedRequest.get().getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce)).isNotNull();
        if (mode == RevocationMode.CUSTOM_CHECKER) {
            assertThat(info).singleElement().extracting(RevocationInfo::ocspResponderUri).isEqualTo(designatedUri);
        } else {
            assertThat(info).isEmpty();
        }
    }

    @Test
    void whenPlatformMakesTwoChecks_thenRequestsContainDifferent32ByteNonces() throws Exception {
        validate(RevocationMode.PLATFORM_OCSP, true);
        final byte[] firstNonce = nonce(receivedRequest.get());
        validate(RevocationMode.PLATFORM_OCSP, true);

        assertThat(requestCount.get()).isEqualTo(2);
        assertThat(firstNonce).hasSize(32).isNotEqualTo(nonce(receivedRequest.get()));
        assertThat(nonce(receivedRequest.get())).hasSize(32);
    }

    @ParameterizedTest
    @EnumSource(value = RevocationMode.class, names = {"PLATFORM_OCSP", "CUSTOM_CHECKER"})
    void whenResponderReturnsRevoked_thenValidationRejectsCertificate(RevocationMode mode) {
        reply = Reply.REVOKED;

        assertThatThrownBy(() -> validate(mode, true)).isInstanceOf(CertificateRevokedException.class);
        assertRequestReachedResponder(mode);
    }

    @ParameterizedTest
    @EnumSource(value = RevocationMode.class, names = {"PLATFORM_OCSP", "CUSTOM_CHECKER"})
    void whenResponderReturnsTryLater_thenValidationReportsFailure(RevocationMode mode) {
        reply = Reply.TRY_LATER;

        assertThatThrownBy(() -> validate(mode, true)).isInstanceOf(CertificateRevocationCheckFailedException.class);
        assertRequestReachedResponder(mode);
    }

    @ParameterizedTest
    @EnumSource(value = RevocationMode.class, names = {"PLATFORM_OCSP", "CUSTOM_CHECKER"})
    void whenResponderDisconnects_thenValidationReportsFailureWithCause(RevocationMode mode) {
        reply = Reply.DISCONNECT;

        assertThatThrownBy(() -> validate(mode, true))
                .isInstanceOf(CertificateRevocationCheckFailedException.class)
                .hasRootCauseInstanceOf(IOException.class);
        assertRequestReachedResponder(mode);
    }

    @ParameterizedTest
    @EnumSource(value = Reply.class, names = {"UNSUPPORTED_TYPE", "MISSING_RESPONSE"})
    void whenBasicResponseIsMissingOrUnsupported_thenCustomCheckerReportsFailure(Reply response) {
        reply = response;

        assertThatThrownBy(() -> validate(RevocationMode.CUSTOM_CHECKER, true))
                .isInstanceOf(UserCertificateOCSPCheckFailedException.class)
                .hasMessageContaining("Missing or unsupported Basic OCSP Response");
        assertRequestReachedResponder(RevocationMode.CUSTOM_CHECKER);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void whenDesignatedResponderOmitsNonce_thenConfiguredPolicyIsEnforced(boolean nonceEnabled) throws Exception {
        includeNonce = false;

        if (nonceEnabled) {
            assertThatThrownBy(() -> validate(RevocationMode.CUSTOM_CHECKER, true))
                    .isInstanceOf(UserCertificateOCSPCheckFailedException.class)
                    .hasMessageContaining("nonce extension missing");
        } else {
            validate(RevocationMode.CUSTOM_CHECKER, false);
            assertThat(receivedRequest.get().getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce)).isNull();
        }
        assertRequestReachedResponder(RevocationMode.CUSTOM_CHECKER);
    }

    private List<RevocationInfo> validate(RevocationMode mode, boolean nonceEnabled) throws Exception {
        final var anchors = CertificateValidator.buildTrustAnchorsFromCertificates(List.of(issuer));
        final var store = CertificateValidator.buildCertStoreFromCertificates(List.of(issuer));
        final OcspCertificateRevocationChecker checker = mode == RevocationMode.CUSTOM_CHECKER
                ? new OcspCertificateRevocationChecker(
                        OcspClientImpl.build(Duration.ofSeconds(2)),
                        new OcspServiceProvider(
                                new DesignatedOcspServiceConfiguration(designatedUri, responder, List.of(issuer), nonceEnabled),
                                new AiaOcspServiceConfiguration(Set.of(), anchors, store)),
                        OcspCertificateRevocationChecker.DEFAULT_TIME_SKEW,
                        OcspCertificateRevocationChecker.DEFAULT_THIS_UPDATE_AGE)
                : null;
        return CertificateValidator.validateCertificateTrustAndRevocation(
                subject, anchors, store, Date.from(now), mode, checker, null, nonceEnabled);
    }

    private void assertRequestReachedResponder(RevocationMode mode) {
        assertThat(requestCount.get()).isPositive();
        assertThat(receivedRequest.get().getRequestList()).hasSize(1);
        assertThat(receivedRequest.get().getRequestList()[0].getCertID().getSerialNumber()).isEqualTo(subject.getSerialNumber());
        assertThat(receivedPath.get()).startsWith(mode == RevocationMode.PLATFORM_OCSP ? "/aia" : "/designated");
    }

    private void respond(HttpExchange exchange) throws IOException {
        try {
            // The JDK may use GET for small requests; the bundled client uses POST.
            final byte[] bytes = exchange.getRequestMethod().equals("GET")
                    ? Base64.getDecoder().decode(URLDecoder.decode(exchange.getRequestURI().getRawPath()
                            .substring(exchange.getHttpContext().getPath().length() + 1), StandardCharsets.UTF_8))
                    : exchange.getRequestBody().readAllBytes();
            final OCSPReq request = new OCSPReq(bytes);
            receivedRequest.set(request);
            receivedPath.set(exchange.getRequestURI().getPath());
            requestCount.incrementAndGet();
            if (reply == Reply.DISCONNECT) {
                return;
            }
            final byte[] response = response(request).getEncoded();
            exchange.getResponseHeaders().set("Content-Type", "application/ocsp-response");
            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
        } catch (Exception e) {
            serverFailure.set(e);
            exchange.sendResponseHeaders(500, -1);
        } finally {
            exchange.close();
        }
    }

    private OCSPResp response(OCSPReq request) throws Exception {
        if (reply == Reply.TRY_LATER) {
            return new OCSPRespBuilder().build(OCSPResp.TRY_LATER, null);
        }
        if (reply == Reply.MISSING_RESPONSE || reply == Reply.UNSUPPORTED_TYPE) {
            return new OCSPResp(new OCSPResponse(new OCSPResponseStatus(0), reply == Reply.MISSING_RESPONSE ? null
                    : new ResponseBytes(new ASN1ObjectIdentifier("1.2.3.4"), new DEROctetString(new byte[0]))));
        }
        final var builder = new JcaBasicOCSPRespBuilder(responder.getPublicKey(),
                new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1));
        final CertificateStatus status = reply == Reply.REVOKED
                ? new RevokedStatus(Date.from(now.minusSeconds(60)), CRLReason.keyCompromise) : CertificateStatus.GOOD;
        builder.addResponse(request.getRequestList()[0].getCertID(), status,
                Date.from(now.minusSeconds(1)), Date.from(now.plusSeconds(60)), null);
        final Extension nonce = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (includeNonce && nonce != null) {
            builder.setResponseExtensions(new Extensions(nonce));
        }
        return new OCSPRespBuilder().build(OCSPResp.SUCCESSFUL, builder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(responderKeys.getPrivate()),
                new X509CertificateHolder[] {new JcaX509CertificateHolder(responder)}, Date.from(now)));
    }

    private static byte[] nonce(OCSPReq request) throws IOException {
        return ASN1OctetString.getInstance(request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce)
                .getExtnValue().getOctets()).getOctets();
    }

    private JcaX509v3CertificateBuilder certificateBuilder(X500Name issuerName, X500Name subjectName, KeyPair keys, int serial) {
        // Generate certificates around the test time so fixtures do not expire or depend on responder rotation.
        return new JcaX509v3CertificateBuilder(issuerName, BigInteger.valueOf(serial),
                Date.from(now.minusSeconds(3600)), Date.from(now.plusSeconds(3600)), subjectName, keys.getPublic());
    }

    private static X509Certificate sign(JcaX509v3CertificateBuilder builder, KeyPair issuerKeys) throws Exception {
        return new JcaX509CertificateConverter().getCertificate(builder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeys.getPrivate())));
    }

    private static KeyPair newKeys() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }
}
