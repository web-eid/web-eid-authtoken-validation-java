package org.webeid.security.validator.ocsp;

import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.Test;
import org.webeid.security.exceptions.OCSPCertificateException;
import org.webeid.security.validator.ocsp.service.OcspService;

import java.net.URI;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.webeid.security.testutil.Certificates.getJaakKristjanEsteid2018Cert;
import static org.webeid.security.testutil.Certificates.getMariliisEsteid2015Cert;
import static org.webeid.security.testutil.Certificates.getTestEsteid2015CA;
import static org.webeid.security.testutil.Certificates.getTestEsteid2018CA;
import static org.webeid.security.testutil.Certificates.getTestSkOcspResponder2020;
import static org.webeid.security.testutil.OcspServiceMaker.getAiaOcspServiceProvider;
import static org.webeid.security.testutil.OcspServiceMaker.getDesignatedOcspServiceProvider;

class OcspServiceProviderTest {

    @Test
    void whenDesignatedOcspServiceConfigurationProvided_thenCreatesDesignatedOcspService() throws Exception {
        final OcspServiceProvider ocspServiceProvider = getDesignatedOcspServiceProvider();
        final OcspService service = ocspServiceProvider.getService(getJaakKristjanEsteid2018Cert());
        assertThat(service.getAccessLocation()).isEqualTo(new URI("http://demo.sk.ee/ocsp"));
        assertThat(service.doesSupportNonce()).isTrue();
        assertThatCode(() ->
            service.validateResponderCertificate(new X509CertificateHolder(getTestSkOcspResponder2020().getEncoded()), new Date(1630000000000L)))
            .doesNotThrowAnyException();
        assertThatCode(() ->
            service.validateResponderCertificate(new X509CertificateHolder(getTestEsteid2018CA().getEncoded()), new Date(1630000000000L)))
            .isInstanceOf(OCSPCertificateException.class)
            .hasMessage("Responder certificate from the OCSP response is not equal to the configured designated OCSP responder certificate");
    }

    @Test
    void whenAiaOcspServiceConfigurationProvided_thenCreatesAiaOcspService() throws Exception {
        final OcspServiceProvider ocspServiceProvider = getAiaOcspServiceProvider();
        final OcspService service2018 = ocspServiceProvider.getService(getJaakKristjanEsteid2018Cert());
        assertThat(service2018.getAccessLocation()).isEqualTo(new URI("http://aia.demo.sk.ee/esteid2018"));
        assertThat(service2018.doesSupportNonce()).isTrue();
        assertThatCode(() ->
            // Use the CA certificate instead of responder certificate for convenience.
            service2018.validateResponderCertificate(new X509CertificateHolder(getTestEsteid2018CA().getEncoded()), new Date(1630000000000L)))
            .doesNotThrowAnyException();

        final OcspService service2015 = ocspServiceProvider.getService(getMariliisEsteid2015Cert());
        assertThat(service2015.getAccessLocation()).isEqualTo(new URI("http://aia.demo.sk.ee/esteid2015"));
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


}
