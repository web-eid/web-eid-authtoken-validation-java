// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.ocsp.service;

import eu.webeid.security.certificate.CertificateValidator;
import eu.webeid.security.exceptions.JceException;
import eu.webeid.ocsp.exceptions.OCSPCertificateException;
import org.bouncycastle.asn1.x500.X500Name;

import java.io.IOException;
import java.net.URI;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Set;

import static eu.webeid.security.testutil.Certificates.getTestEsteid2015CA;
import static eu.webeid.security.testutil.Certificates.getTestEsteid2018CA;
import static eu.webeid.security.testutil.Certificates.getTestSelfSignedOcspResponder;

public class OcspServiceMaker {

    public static final Duration MAX_THIS_UPDATE_AGE = Duration.ofMinutes(3);
    public static final Duration MAX_NEXT_UPDATE_AGE = Duration.ofMinutes(20);

    private static final String TEST_OCSP_ACCESS_LOCATION = "http://demo.sk.ee/ocsp";
    private static final List<X509Certificate> TRUSTED_CA_CERTIFICATES;
    private static final X500Name ISSUER_DN = new X500Name("CN=TEST of ESTEID-SK 2015, OID.2.5.4.97=NTREE-10747013, O=AS Sertifitseerimiskeskus, C=EE");

    static {
        try {
            TRUSTED_CA_CERTIFICATES = List.of(getTestEsteid2018CA(), getTestEsteid2015CA());
        } catch (CertificateException | IOException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    public static OcspServiceProvider getAiaOcspServiceProvider() throws JceException {
        return new OcspServiceProvider(null, getAiaOcspServiceConfiguration());
    }

    public static OcspServiceProvider getDesignatedOcspServiceProvider() throws CertificateException, IOException, OCSPCertificateException, JceException {
        return new OcspServiceProvider(getDesignatedOcspServiceConfiguration(), getAiaOcspServiceConfiguration());
    }

    public static OcspServiceProvider getDesignatedOcspServiceProvider(boolean doesSupportNonce) throws CertificateException, IOException, JceException, OCSPCertificateException {
        return new OcspServiceProvider(getDesignatedOcspServiceConfiguration(doesSupportNonce), getAiaOcspServiceConfiguration());
    }

    public static OcspServiceProvider getDesignatedOcspServiceProvider(String ocspServiceAccessLocation) throws CertificateException, IOException, OCSPCertificateException, JceException {
        return new OcspServiceProvider(getDesignatedOcspServiceConfiguration(true, ocspServiceAccessLocation), getAiaOcspServiceConfiguration());
    }

    private static AiaOcspServiceConfiguration getAiaOcspServiceConfiguration() throws JceException {
        return new AiaOcspServiceConfiguration(
            Set.of(ISSUER_DN),
            CertificateValidator.buildTrustAnchorsFromCertificates(TRUSTED_CA_CERTIFICATES),
            CertificateValidator.buildCertStoreFromCertificates(TRUSTED_CA_CERTIFICATES),
            MAX_THIS_UPDATE_AGE,
            MAX_NEXT_UPDATE_AGE);
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
            getTestSelfSignedOcspResponder(),
            TRUSTED_CA_CERTIFICATES,
            doesSupportNonce,
            MAX_THIS_UPDATE_AGE,
            MAX_NEXT_UPDATE_AGE);
    }

}
