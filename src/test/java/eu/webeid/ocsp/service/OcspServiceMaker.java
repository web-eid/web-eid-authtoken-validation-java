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

package eu.webeid.ocsp.service;

import eu.webeid.security.certificate.CertificateValidator;
import eu.webeid.security.exceptions.JceException;
import eu.webeid.ocsp.exceptions.OCSPCertificateException;

import java.io.IOException;
import java.net.URI;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import static eu.webeid.security.testutil.Certificates.getTestEsteid2015CA;
import static eu.webeid.security.testutil.Certificates.getTestEsteid2018CA;
import static eu.webeid.security.testutil.Certificates.getTestSkOcspResponder2020;

public class OcspServiceMaker {

    private static final String TEST_OCSP_ACCESS_LOCATION = "http://demo.sk.ee/ocsp";
    private static final List<X509Certificate> TRUSTED_CA_CERTIFICATES;
    private static final String ISSUER_CN = "TEST of ESTEID-SK 2015";

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
            Set.of(ISSUER_CN),
            CertificateValidator.buildTrustAnchorsFromCertificates(TRUSTED_CA_CERTIFICATES),
            CertificateValidator.buildCertStoreFromCertificates(TRUSTED_CA_CERTIFICATES));
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
