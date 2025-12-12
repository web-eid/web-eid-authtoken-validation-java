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

package eu.webeid.security.certificate;

import eu.webeid.security.exceptions.CertificateNotTrustedException;
import eu.webeid.security.exceptions.CertificateRevocationCheckFailedException;
import eu.webeid.security.exceptions.CertificateRevokedException;
import eu.webeid.security.testutil.Certificates;
import eu.webeid.security.validator.revocationcheck.RevocationInfo;
import eu.webeid.security.validator.revocationcheck.RevocationMode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URI;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.util.Objects.requireNonNull;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CertificateValidatorTest {

    private static final Date NOW = new Date(1627776000000L);
    private static final Date OCSP_RESPONSE_DATE = new Date(1631903124000L);
    private static final Date REVOKED_OCSP_RESPONSE_DATE = new Date(1631924023000L);

    @Test
    void whenRevocationDisabled_thenValidationSucceedsWithoutRevocationInfo() throws Exception {
        final X509Certificate subject = Certificates.getJaakKristjanEsteid2018Cert();
        final X509Certificate issuer = Certificates.getTestEsteid2018CA();

        final List<RevocationInfo> revocationInfo = CertificateValidator.validateCertificateTrustAndRevocation(
                subject,
                trustAnchors(issuer),
                certStore(issuer),
                NOW,
                RevocationMode.DISABLED,
                null,
                null,
                true
        );

        assertThat(revocationInfo).isEmpty();
    }

    @Test
    void whenRevocationDisabledAndCheckerProvided_thenThrows() throws Exception {
        final X509Certificate subject = Certificates.getJaakKristjanEsteid2018Cert();
        final X509Certificate issuer = Certificates.getTestEsteid2018CA();

        assertThatThrownBy(() -> CertificateValidator.validateCertificateTrustAndRevocation(
                subject,
                trustAnchors(issuer),
                certStore(issuer),
                NOW,
                RevocationMode.DISABLED,
                (s, i) -> List.of(),
                null,
                true
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageStartingWith("customPkixRevocationChecker and certificateRevocationChecker must be null when revocationMode is DISABLED");
    }

    @Test
    void whenCustomCheckerMissing_thenThrows() throws Exception {
        final X509Certificate subject = Certificates.getJaakKristjanEsteid2018Cert();
        final X509Certificate issuer = Certificates.getTestEsteid2018CA();

        assertThatThrownBy(() -> CertificateValidator.validateCertificateTrustAndRevocation(
                subject,
                trustAnchors(issuer),
                certStore(issuer),
                NOW,
                RevocationMode.CUSTOM_CHECKER,
                null,
                null,
                true
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageStartingWith("certificateRevocationChecker must be provided when revocationMode is CUSTOM_CHECKER");
    }

    @Test
    void whenCustomCheckerAndCustomPkixProvided_thenThrows() throws Exception {
        final X509Certificate subject = Certificates.getJaakKristjanEsteid2018Cert();
        final X509Certificate issuer = Certificates.getTestEsteid2018CA();

        assertThatThrownBy(() -> CertificateValidator.validateCertificateTrustAndRevocation(
                subject,
                trustAnchors(issuer),
                certStore(issuer),
                NOW,
                RevocationMode.CUSTOM_CHECKER,
                (s, i) -> List.of(),
                new NoopPkixRevocationChecker(),
                true
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageStartingWith("customPkixRevocationChecker must be null when revocationMode is CUSTOM_CHECKER");
    }

    @Test
    void whenCustomCheckerReturnsRevocationInfo_thenItIsReturned() throws Exception {
        final X509Certificate subject = Certificates.getJaakKristjanEsteid2018Cert();
        final X509Certificate issuer = Certificates.getTestEsteid2018CA();
        final RevocationInfo expected = new RevocationInfo(
                URI.create("http://ocsp.example"),
                null
        );

        final List<RevocationInfo> revocationInfo = CertificateValidator.validateCertificateTrustAndRevocation(
                subject,
                trustAnchors(issuer),
                certStore(issuer),
                NOW,
                RevocationMode.CUSTOM_CHECKER,
                (s, i) -> List.of(expected),
                null,
                true
        );

        assertThat(revocationInfo).containsExactly(expected);
    }

    @Test
    void whenCustomPkixMissing_thenThrows() throws Exception {
        final X509Certificate subject = Certificates.getJaakKristjanEsteid2018Cert();
        final X509Certificate issuer = Certificates.getTestEsteid2018CA();

        assertThatThrownBy(() -> CertificateValidator.validateCertificateTrustAndRevocation(
                subject,
                trustAnchors(issuer),
                certStore(issuer),
                NOW,
                RevocationMode.CUSTOM_PKIX,
                null,
                null,
                true
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageStartingWith("customPkixRevocationChecker must be provided when revocationMode is CUSTOM_PKIX");
    }

    @Test
    void whenCustomPkixAndCustomCheckerProvided_thenThrows() throws Exception {
        final X509Certificate subject = Certificates.getJaakKristjanEsteid2018Cert();
        final X509Certificate issuer = Certificates.getTestEsteid2018CA();

        assertThatThrownBy(() -> CertificateValidator.validateCertificateTrustAndRevocation(
                subject,
                trustAnchors(issuer),
                certStore(issuer),
                NOW,
                RevocationMode.CUSTOM_PKIX,
                (s, i) -> List.of(),
                new NoopPkixRevocationChecker(),
                true
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageStartingWith("certificateRevocationChecker must be null when revocationMode is CUSTOM_PKIX");
    }

    @Test
    void whenCustomPkixWithOcspResponder_thenRevocationInfoContainsResponder() throws Exception {
        final X509Certificate subject = Certificates.getJaakKristjanEsteid2018Cert();
        final X509Certificate issuer = Certificates.getTestEsteid2018CA();
        final NoopPkixRevocationChecker checker = new NoopPkixRevocationChecker();
        checker.setOcspResponder(URI.create("http://ocsp.example"));

        final List<RevocationInfo> revocationInfo = CertificateValidator.validateCertificateTrustAndRevocation(
                subject,
                trustAnchors(issuer),
                certStore(issuer),
                NOW,
                RevocationMode.CUSTOM_PKIX,
                null,
                checker,
                true
        );

        assertThat(revocationInfo).containsExactly(new RevocationInfo(checker.getOcspResponder(), null));
    }

    @Test
    void whenCustomPkixUsesBundledOcspResponse_thenValidationSucceeds() throws Exception {
        final X509Certificate subject = Certificates.getJaakKristjanEsteid2018Cert();
        final X509Certificate issuer = Certificates.getTestEsteid2018CA();

        assertThat(CertificateValidator.validateCertificateTrustAndRevocation(
                subject,
                trustAnchors(issuer),
                certStore(issuer),
                OCSP_RESPONSE_DATE,
                RevocationMode.CUSTOM_PKIX,
                null,
                pkixCheckerWithOcspResponse(subject, "/ocsp_response.der"),
                true
        )).isEmpty();
    }

    @Test
    void whenCustomPkixUsesBundledRevokedOcspResponse_thenThrowsCertificateRevoked() throws Exception {
        final X509Certificate subject = Certificates.getJaakKristjanEsteid2018Cert();
        final X509Certificate issuer = Certificates.getTestEsteid2018CA();

        assertThatThrownBy(() -> CertificateValidator.validateCertificateTrustAndRevocation(
                subject,
                trustAnchors(issuer),
                certStore(issuer),
                REVOKED_OCSP_RESPONSE_DATE,
                RevocationMode.CUSTOM_PKIX,
                null,
                pkixCheckerWithOcspResponse(subject, "/ocsp_response_revoked.der"),
                true
        ))
                .isInstanceOf(CertificateRevokedException.class)
                .hasCauseInstanceOf(CertPathValidatorException.class);
    }

    @Test
    void whenCustomPkixCannotDetermineRevocationStatus_thenThrowsRevocationCheckFailedWithCause() throws Exception {
        final X509Certificate subject = Certificates.getJaakKristjanEsteid2018Cert();
        final X509Certificate issuer = Certificates.getTestEsteid2018CA();
        final CertPathValidatorException checkerFailure = new CertPathValidatorException(
                "OCSP responder returned TRY_LATER",
                null,
                null,
                -1,
                CertPathValidatorException.BasicReason.UNDETERMINED_REVOCATION_STATUS
        );

        assertThatThrownBy(() -> CertificateValidator.validateCertificateTrustAndRevocation(
                subject,
                trustAnchors(issuer),
                certStore(issuer),
                NOW,
                RevocationMode.CUSTOM_PKIX,
                null,
                new FailingPkixRevocationChecker(checkerFailure),
                true
        ))
                .isInstanceOf(CertificateRevocationCheckFailedException.class)
                .hasMessageContaining("OCSP responder returned TRY_LATER")
                .hasCause(checkerFailure);
    }

    @Test
    void whenCustomPkixReportsRevoked_thenThrowsCertificateRevokedWithCause() throws Exception {
        final X509Certificate subject = Certificates.getJaakKristjanEsteid2018Cert();
        final X509Certificate issuer = Certificates.getTestEsteid2018CA();
        final CertPathValidatorException checkerFailure = new CertPathValidatorException(
                "Certificate has been revoked",
                null,
                null,
                -1,
                CertPathValidatorException.BasicReason.REVOKED
        );

        assertThatThrownBy(() -> CertificateValidator.validateCertificateTrustAndRevocation(
                subject,
                trustAnchors(issuer),
                certStore(issuer),
                NOW,
                RevocationMode.CUSTOM_PKIX,
                null,
                new FailingPkixRevocationChecker(checkerFailure),
                true
        ))
                .isInstanceOf(CertificateRevokedException.class)
                .hasCause(checkerFailure);
    }

    @Test
    void whenCustomPkixReportsUnspecifiedFailure_thenThrowsRevocationCheckFailedWithCause() throws Exception {
        final X509Certificate subject = Certificates.getJaakKristjanEsteid2018Cert();
        final X509Certificate issuer = Certificates.getTestEsteid2018CA();
        final CertPathValidatorException checkerFailure = new CertPathValidatorException(
                "Certificate does not specify OCSP responder"
        );

        assertThatThrownBy(() -> CertificateValidator.validateCertificateTrustAndRevocation(
                subject,
                trustAnchors(issuer),
                certStore(issuer),
                NOW,
                RevocationMode.CUSTOM_PKIX,
                null,
                new FailingPkixRevocationChecker(checkerFailure),
                true
        ))
                .isInstanceOf(CertificateRevocationCheckFailedException.class)
                .hasMessageContaining("Certificate does not specify OCSP responder")
                .hasCause(checkerFailure);
    }

    @Test
    void whenCustomPkixReportsNonRevocationValidationFailure_thenThrowsCertificateNotTrusted() throws Exception {
        final X509Certificate subject = Certificates.getJaakKristjanEsteid2018Cert();
        final X509Certificate issuer = Certificates.getTestEsteid2018CA();
        final CertPathValidatorException checkerFailure = new CertPathValidatorException(
                "Invalid certificate signature",
                null,
                null,
                -1,
                CertPathValidatorException.BasicReason.INVALID_SIGNATURE
        );

        assertThatThrownBy(() -> CertificateValidator.validateCertificateTrustAndRevocation(
                subject,
                trustAnchors(issuer),
                certStore(issuer),
                NOW,
                RevocationMode.CUSTOM_PKIX,
                null,
                new FailingPkixRevocationChecker(checkerFailure),
                true
        ))
                .isInstanceOf(CertificateNotTrustedException.class)
                .hasCause(checkerFailure);
    }

    @Test
    void whenPlatformOcspHasCustomChecker_thenThrows() throws Exception {
        final X509Certificate subject = Certificates.getJaakKristjanEsteid2018Cert();
        final X509Certificate issuer = Certificates.getTestEsteid2018CA();

        assertThatThrownBy(() -> CertificateValidator.validateCertificateTrustAndRevocation(
                subject,
                trustAnchors(issuer),
                certStore(issuer),
                NOW,
                RevocationMode.PLATFORM_OCSP,
                (s, i) -> List.of(),
                null,
                true
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageStartingWith("customPkixRevocationChecker and certificateRevocationChecker must be null when revocationMode is PLATFORM_OCSP");
    }

    @Test
    void whenJdkOcspNoncePropertyIsNotSet_thenFreshApplicationNonceIsConfigured() {
        final NoopPkixRevocationChecker firstChecker = new NoopPkixRevocationChecker();
        final NoopPkixRevocationChecker secondChecker = new NoopPkixRevocationChecker();

        CertificateValidator.configureOcspNonce(firstChecker, true, null);
        CertificateValidator.configureOcspNonce(secondChecker, true, null);

        assertThat(firstChecker.getOcspExtensions())
                .singleElement()
                .isInstanceOf(OcspNonceExtension.class);
        assertThat(firstChecker.getOcspExtensions().get(0).getValue())
                .isNotEqualTo(secondChecker.getOcspExtensions().get(0).getValue());
    }

    @Test
    void whenPlatformOcspNonceIsDisabledAndJdkPropertyIsUnset_thenApplicationNonceIsNotConfigured() {
        final NoopPkixRevocationChecker checker = new NoopPkixRevocationChecker();

        CertificateValidator.configureOcspNonce(checker, false, null);

        assertThat(checker.getOcspExtensions()).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void whenJdkOcspNoncePropertyIsTrue_thenNonceGenerationIsLeftToJdk(boolean platformOcspNonceEnabled) {
        final NoopPkixRevocationChecker checker = new NoopPkixRevocationChecker();

        CertificateValidator.configureOcspNonce(checker, platformOcspNonceEnabled, "true");

        assertThat(checker.getOcspExtensions()).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void whenJdkOcspNoncePropertyIsFalse_thenApplicationNonceIsNotConfigured(boolean platformOcspNonceEnabled) {
        final NoopPkixRevocationChecker checker = new NoopPkixRevocationChecker();

        CertificateValidator.configureOcspNonce(checker, platformOcspNonceEnabled, "false");

        assertThat(checker.getOcspExtensions()).isEmpty();
    }

    @Test
    void whenPlatformOcspWithUntrustedIssuer_thenThrowsCertificateNotTrusted() throws Exception {
        final X509Certificate subject = Certificates.getJaakKristjanEsteid2018Cert();
        final X509Certificate wrongIssuer = Certificates.getTestEsteid2015CA();

        assertThatThrownBy(() -> CertificateValidator.validateCertificateTrustAndRevocation(
                subject,
                trustAnchors(wrongIssuer),
                certStore(wrongIssuer),
                NOW,
                RevocationMode.PLATFORM_OCSP,
                null,
                null,
                true
        ))
                .isInstanceOf(CertificateNotTrustedException.class);
    }

    private static Set<TrustAnchor> trustAnchors(X509Certificate issuer) {
        return CertificateValidator.buildTrustAnchorsFromCertificates(List.of(issuer));
    }

    private static CertStore certStore(X509Certificate issuer) throws Exception {
        return CertificateValidator.buildCertStoreFromCertificates(List.of(issuer));
    }

    private static PKIXRevocationChecker pkixCheckerWithOcspResponse(X509Certificate subject,
                                                                     String responseResource) throws Exception {
        final PKIXRevocationChecker checker = (PKIXRevocationChecker) CertPathValidator
                .getInstance(CertPathValidator.getDefaultType())
                .getRevocationChecker();
        checker.setOptions(Set.of(
                PKIXRevocationChecker.Option.ONLY_END_ENTITY,
                PKIXRevocationChecker.Option.NO_FALLBACK
        ));
        checker.setOcspResponses(Map.of(
                subject,
                requireNonNull(CertificateValidatorTest.class.getResourceAsStream(responseResource)).readAllBytes()
        ));
        return checker;
    }

    private static final class NoopPkixRevocationChecker extends PKIXRevocationChecker {
        @Override
        public void init(boolean forward) {
        }

        @Override
        public boolean isForwardCheckingSupported() {
            return false;
        }

        @Override
        public Set<String> getSupportedExtensions() {
            return null;
        }

        @Override
        public void check(Certificate cert, Collection<String> unresolvedCritExts) {
        }

        @Override
        public List<CertPathValidatorException> getSoftFailExceptions() {
            return List.of();
        }
    }

    private static final class FailingPkixRevocationChecker extends PKIXRevocationChecker {
        private final CertPathValidatorException failure;

        private FailingPkixRevocationChecker(CertPathValidatorException failure) {
            this.failure = failure;
        }

        @Override
        public void init(boolean forward) {
        }

        @Override
        public boolean isForwardCheckingSupported() {
            return false;
        }

        @Override
        public Set<String> getSupportedExtensions() {
            return null;
        }

        @Override
        public void check(Certificate cert, Collection<String> unresolvedCritExts) throws CertPathValidatorException {
            throw failure;
        }

        @Override
        public List<CertPathValidatorException> getSoftFailExceptions() {
            return List.of();
        }
    }
}
