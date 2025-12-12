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
import eu.webeid.security.testutil.Certificates;
import eu.webeid.security.validator.revocationcheck.RevocationInfo;
import eu.webeid.security.validator.revocationcheck.RevocationMode;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CertificateValidatorTest {

    private static final Date NOW = new Date(1627776000000L);

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
                null
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
                null
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
                null
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageStartingWith("certificateRevocationChecker must be provided when revocationMode is CUSTOM_OCSP");
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
                new NoopPkixRevocationChecker()
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageStartingWith("customPkixRevocationChecker must be null when revocationMode is CUSTOM_OCSP");
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
                null
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
                null
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
                new NoopPkixRevocationChecker()
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
                checker
        );

        assertThat(revocationInfo).containsExactly(new RevocationInfo(checker.getOcspResponder(), null));
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
                null
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageStartingWith("customPkixRevocationChecker and certificateRevocationChecker must be null when revocationMode is PLATFORM_OCSP");
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
                null
        ))
                .isInstanceOf(CertificateNotTrustedException.class);
    }

    private static Set<TrustAnchor> trustAnchors(X509Certificate issuer) {
        return CertificateValidator.buildTrustAnchorsFromCertificates(List.of(issuer));
    }

    private static CertStore certStore(X509Certificate issuer) throws Exception {
        return CertificateValidator.buildCertStoreFromCertificates(List.of(issuer));
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
}
