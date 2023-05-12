/*
 * Copyright (c) 2020-2023 Estonian Information System Authority
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

package eu.webeid.security.testutil;

import eu.webeid.security.certificate.CertificateValidator;
import eu.webeid.security.exceptions.JceException;
import eu.webeid.security.exceptions.OCSPCertificateException;
import eu.webeid.security.validator.ocsp.service.AiaOcspServiceConfiguration;
import eu.webeid.security.validator.ocsp.service.DesignatedOcspServiceConfiguration;
import org.jetbrains.annotations.NotNull;
import eu.webeid.security.validator.ocsp.OcspServiceProvider;

import java.io.IOException;
import java.net.URI;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import static eu.webeid.security.testutil.Certificates.*;
import static eu.webeid.security.util.Collections.newHashSet;
import static eu.webeid.security.validator.ocsp.OcspUrl.AIA_ESTEID_2015;

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
            newHashSet(AIA_ESTEID_2015, TEST_ESTEID_2015),
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
