package org.webeid.security.testutil;

import com.google.common.collect.Sets;
import org.jetbrains.annotations.NotNull;
import org.webeid.security.exceptions.JceException;
import org.webeid.security.exceptions.OCSPCertificateException;
import org.webeid.security.validator.ocsp.OcspServiceProvider;
import org.webeid.security.validator.ocsp.service.AiaOcspServiceConfiguration;
import org.webeid.security.validator.ocsp.service.DesignatedOcspServiceConfiguration;

import java.io.IOException;
import java.net.URI;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import static org.webeid.security.certificate.CertificateValidator.buildCertStoreFromCertificates;
import static org.webeid.security.certificate.CertificateValidator.buildTrustAnchorsFromCertificates;
import static org.webeid.security.testutil.Certificates.*;
import static org.webeid.security.validator.ocsp.OcspUrl.AIA_ESTEID_2015;

public class OcspServiceMaker {

    private static final String TEST_OCSP_ACCESS_LOCATION = "http://demo.sk.ee/ocsp";
    private static final List<X509Certificate> TRUSTED_CA_CERTIFICATES;
    private static final URI TEST_ESTEID_2015 = URI.create("http://aia.demo.sk.ee/esteid2015");

    static {
        try {
            TRUSTED_CA_CERTIFICATES = Arrays.asList(getTestEsteid2018CA(), getTestEsteid2015CA());
        } catch (CertificateException | IOException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @NotNull
    public static OcspServiceProvider getAiaOcspServiceProvider() throws JceException {
        return new OcspServiceProvider(null, getAiaOcspServiceConfiguration());
    }

    @NotNull
    public static OcspServiceProvider getDesignatedOcspServiceProvider() throws CertificateException, IOException, OCSPCertificateException, JceException {
        return new OcspServiceProvider(getDesignatedOcspServiceConfiguration(), getAiaOcspServiceConfiguration());
    }

    @NotNull
    public static OcspServiceProvider getDesignatedOcspServiceProvider(boolean doesSupportNonce) throws CertificateException, IOException, JceException, OCSPCertificateException {
        return new OcspServiceProvider(getDesignatedOcspServiceConfiguration(doesSupportNonce), getAiaOcspServiceConfiguration());
    }

    @NotNull
    public static OcspServiceProvider getDesignatedOcspServiceProvider(String ocspServiceAccessLocation) throws CertificateException, IOException, OCSPCertificateException, JceException {
        return new OcspServiceProvider(getDesignatedOcspServiceConfiguration(true, ocspServiceAccessLocation), getAiaOcspServiceConfiguration());
    }

    private static AiaOcspServiceConfiguration getAiaOcspServiceConfiguration() throws JceException {
        return new AiaOcspServiceConfiguration(
            Sets.newHashSet(AIA_ESTEID_2015, TEST_ESTEID_2015),
            buildTrustAnchorsFromCertificates(TRUSTED_CA_CERTIFICATES),
            buildCertStoreFromCertificates(TRUSTED_CA_CERTIFICATES));
    }

    public static DesignatedOcspServiceConfiguration getDesignatedOcspServiceConfiguration() throws CertificateException, IOException, OCSPCertificateException {
        return getDesignatedOcspServiceConfiguration(true, TEST_OCSP_ACCESS_LOCATION);
    }

    private static DesignatedOcspServiceConfiguration getDesignatedOcspServiceConfiguration(boolean doesSupportNonce) throws CertificateException, IOException, OCSPCertificateException {
        return getDesignatedOcspServiceConfiguration(doesSupportNonce, TEST_OCSP_ACCESS_LOCATION);
    }

    private static DesignatedOcspServiceConfiguration getDesignatedOcspServiceConfiguration(boolean doesSupportNonce, String ocspServiceAccessLocation) throws CertificateException, IOException, OCSPCertificateException {
        return new DesignatedOcspServiceConfiguration(
            URI.create(ocspServiceAccessLocation),
            getTestSkOcspResponder2020(),
            TRUSTED_CA_CERTIFICATES,
            doesSupportNonce);
    }

}
