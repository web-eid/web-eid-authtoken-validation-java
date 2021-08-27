package org.webeid.security.validator.ocsp;

import org.bouncycastle.cert.X509CertificateHolder;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.webeid.security.exceptions.JceException;
import org.webeid.security.exceptions.OCSPCertificateException;
import org.webeid.security.validator.ocsp.service.AiaOcspResponderConfiguration;
import org.webeid.security.validator.ocsp.service.AiaOcspServiceConfiguration;
import org.webeid.security.validator.ocsp.service.DesignatedOcspServiceConfiguration;
import org.webeid.security.validator.ocsp.service.OcspService;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.CertificateException;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.webeid.security.testutil.Certificates.*;

class OcspServiceProviderTest {

    @Test
    void whenDesignatedOcspServiceConfigurationProvided_thenCreatesDesignatedOcspService() throws Exception {
        final OcspServiceProvider ocspServiceProvider =
            new OcspServiceProvider(new DesignatedOcspServiceConfiguration(new URI("http://demo.sk.ee/ocsp"), getTestSkOcspResponder2020()));
        final OcspService service = ocspServiceProvider.getService(null);
        assertThat(service.getUrl()).isEqualTo(new URI("http://demo.sk.ee/ocsp"));
        assertThat(service.doesSupportNonce()).isTrue();
        assertThatCode(() ->
            service.validateResponderCertificate(new X509CertificateHolder(getTestSkOcspResponder2020().getEncoded()), new Date(1630000000000L)))
            .doesNotThrowAnyException();
    }

    @Test
    void whenAiaOcspServiceConfigurationProvided_thenCreatesAiaOcspService() throws Exception {
        final OcspServiceProvider ocspServiceProvider = getAiaOcspServiceProvider();
        final OcspService service2018 = ocspServiceProvider.getService(getJaakKristjanEsteid2018Cert());
        assertThat(service2018.getUrl()).isEqualTo(new URI("http://aia.demo.sk.ee/esteid2018"));
        assertThat(service2018.doesSupportNonce()).isTrue();
        assertThatCode(() ->
            // Use the CA certificate instead of responder certificate for convenience.
            service2018.validateResponderCertificate(new X509CertificateHolder(getTestEsteid2018CA().getEncoded()), new Date(1630000000000L)))
            .doesNotThrowAnyException();

        final OcspService service2015 = ocspServiceProvider.getService(getMariliisEsteid2015Cert());
        assertThat(service2015.getUrl()).isEqualTo(new URI("http://aia.demo.sk.ee/esteid2015"));
        assertThat(service2015.doesSupportNonce()).isFalse();
        assertThatCode(() ->
            // Use the CA certificate instead of responder certificate for convenience.
            service2015.validateResponderCertificate(new X509CertificateHolder(getTestEsteid2015CA().getEncoded()), new Date(1630000000000L)))
            .doesNotThrowAnyException();
    }

    @Test
    void whenAiaOcspServiceConfigurationDoesNotHaveResponderCertTrustedCA_thenThrows() throws Exception {
        final OcspServiceProvider ocspServiceProvider = getAiaOcspServiceProvider();
        final OcspService service2018 = ocspServiceProvider.getService(getJaakKristjanEsteid2018Cert());
        final X509CertificateHolder wrongResponderCert = new X509CertificateHolder(getMariliisEsteid2015Cert().getEncoded());
        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() ->
                service2018.validateResponderCertificate(wrongResponderCert, new Date(1630000000000L)));
    }

    @NotNull
    private OcspServiceProvider getAiaOcspServiceProvider() throws URISyntaxException, CertificateException, JceException, IOException {
        return new OcspServiceProvider(new AiaOcspServiceConfiguration(
            new AiaOcspResponderConfiguration(new URI("http://aia.demo.sk.ee/esteid2018"), getTestEsteid2018CA()),
            new AiaOcspResponderConfiguration(new URI("http://aia.demo.sk.ee/esteid2015"), getTestEsteid2015CA(), false)
        ));
    }
}
