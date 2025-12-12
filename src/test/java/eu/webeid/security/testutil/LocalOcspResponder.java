// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.testutil;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
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
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** Local HTTP responder with generated certificates, signed OCSP replies, and request recording. */
public final class LocalOcspResponder implements AutoCloseable {

    private final Instant now = Instant.now();
    private final AtomicInteger requestCount = new AtomicInteger();
    private final AtomicReference<OCSPReq> receivedRequest = new AtomicReference<>();
    private final AtomicReference<String> receivedPath = new AtomicReference<>();
    private final AtomicReference<Exception> serverFailure = new AtomicReference<>();
    private HttpServer server;
    private URI aiaUri;
    private URI designatedUri;
    private X509Certificate root;
    private X509Certificate issuer;
    private X509Certificate otherIssuer;
    private X509Certificate subject;
    private volatile X509Certificate responder;
    private KeyPair issuerKeys;
    private KeyPair responderKeys;
    private volatile Reply reply = Reply.GOOD;
    private volatile boolean includeNonce = true;

    public enum Reply { GOOD, REVOKED, TRY_LATER, DISCONNECT, UNSUPPORTED_TYPE, MISSING_RESPONSE }

    public void start() throws Exception {
        start(false);
    }

    public void startWithIntermediate() throws Exception {
        start(true);
    }

    private void start(boolean withIntermediate) throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        aiaUri = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/aia");
        designatedUri = aiaUri.resolve("/designated");

        issuerKeys = newKeys();
        responderKeys = newKeys();
        final X500Name issuerName = new X500Name(withIntermediate
                ? "CN=Local OCSP test intermediate CA" : "CN=Local OCSP test CA");
        final X500Name rootName = new X500Name("CN=Local OCSP test root CA");
        KeyPair rootKeys = null;
        if (withIntermediate) {
            rootKeys = newKeys();
            final var rootBuilder = certificateBuilder(rootName, rootName, rootKeys, 10);
            rootBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            rootBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
            root = sign(rootBuilder, rootKeys);
        }
        final var issuerBuilder = certificateBuilder(withIntermediate ? rootName : issuerName, issuerName, issuerKeys, 1);
        issuerBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        issuerBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        issuer = sign(issuerBuilder, withIntermediate ? rootKeys : issuerKeys);
        if (!withIntermediate) {
            root = issuer;
        }

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

    @Override
    public void close() {
        if (server != null) {
            server.stop(0);
        }
        if (serverFailure.get() != null) {
            throw new AssertionError("Local responder failure", serverFailure.get());
        }
    }

    public Instant now() {
        return now;
    }

    public URI aiaUri() {
        return aiaUri;
    }

    public URI designatedUri() {
        return designatedUri;
    }

    public X509Certificate issuer() {
        return issuer;
    }

    public X509Certificate root() {
        return root;
    }

    public X509Certificate otherIssuer() {
        return otherIssuer;
    }

    public X509Certificate subject() {
        return subject;
    }

    public X509Certificate responderCertificate() {
        return responder;
    }

    public int requestCount() {
        return requestCount.get();
    }

    public OCSPReq receivedRequest() {
        return receivedRequest.get();
    }

    public String receivedPath() {
        return receivedPath.get();
    }

    public byte[] requestNonce() {
        final Extension nonce = receivedRequest.get().getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        return nonce == null ? null : ASN1OctetString.getInstance(nonce.getExtnValue().getOctets()).getOctets();
    }

    public void setReply(Reply reply) {
        this.reply = reply;
    }

    public void setIncludeNonce(boolean includeNonce) {
        this.includeNonce = includeNonce;
    }

    public void useIssuerAsResponder() {
        responder = issuer;
        responderKeys = issuerKeys;
    }

    public void replaceResponderCertificate(boolean includeSigningUsage) throws Exception {
        final var builder = certificateBuilder(new JcaX509CertificateHolder(issuer).getSubject(),
                new X500Name("CN=Replacement OCSP test responder"), responderKeys, 4);
        if (includeSigningUsage) {
            builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning));
        }
        responder = sign(builder, issuerKeys);
    }

    public void replaceResponderCertificateFromDifferentIssuer(boolean sameIssuerName) throws Exception {
        final KeyPair otherIssuerKeys = newKeys();
        final X500Name otherIssuerName = sameIssuerName
                ? new JcaX509CertificateHolder(issuer).getSubject()
                : new X500Name("CN=Other local OCSP test CA");
        final var otherIssuerBuilder = certificateBuilder(otherIssuerName, otherIssuerName, otherIssuerKeys, 5);
        otherIssuerBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        otherIssuerBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        otherIssuer = sign(otherIssuerBuilder, otherIssuerKeys);

        final var responderBuilder = certificateBuilder(otherIssuerName,
                new X500Name("CN=Other local OCSP test responder"), responderKeys, 6);
        responderBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        responderBuilder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning));
        responder = sign(responderBuilder, otherIssuerKeys);
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
        final CertificateID requestedId = request.getRequestList()[0].getCertID();
        if (!requestedId.matchesIssuer(new JcaX509CertificateHolder(issuer),
                new JcaDigestCalculatorProviderBuilder().build())) {
            return new OCSPRespBuilder().build(OCSPResp.UNAUTHORIZED, null);
        }
        final var builder = new JcaBasicOCSPRespBuilder(responder.getPublicKey(),
                new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1));
        final CertificateStatus status = reply == Reply.REVOKED
                ? new RevokedStatus(Date.from(now.minusSeconds(60)), CRLReason.keyCompromise) : CertificateStatus.GOOD;
        builder.addResponse(requestedId, status,
                Date.from(now.minusSeconds(1)), Date.from(now.plusSeconds(60)), null);
        final Extension nonce = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (includeNonce && nonce != null) {
            builder.setResponseExtensions(new Extensions(nonce));
        }
        return new OCSPRespBuilder().build(OCSPResp.SUCCESSFUL, builder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(responderKeys.getPrivate()),
                new X509CertificateHolder[] {new JcaX509CertificateHolder(responder)}, Date.from(now)));
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
