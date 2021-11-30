/*
 * Copyright (c) 2020-2021 Estonian Information System Authority
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

package eu.webeid.security.validator.ocsp;

import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.validator.ocsp.service.AiaOcspService;
import eu.webeid.security.validator.ocsp.service.AiaOcspServiceConfiguration;
import eu.webeid.security.validator.ocsp.service.DesignatedOcspService;
import eu.webeid.security.validator.ocsp.service.DesignatedOcspServiceConfiguration;
import eu.webeid.security.validator.ocsp.service.OcspService;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Objects;

public class OcspServiceProvider {

    private final DesignatedOcspService designatedOcspService;
    private final AiaOcspServiceConfiguration aiaOcspServiceConfiguration;

    public OcspServiceProvider(DesignatedOcspServiceConfiguration designatedOcspServiceConfiguration, AiaOcspServiceConfiguration aiaOcspServiceConfiguration) {
        designatedOcspService = designatedOcspServiceConfiguration != null ?
            new DesignatedOcspService(designatedOcspServiceConfiguration)
            : null;
        this.aiaOcspServiceConfiguration = Objects.requireNonNull(aiaOcspServiceConfiguration, "aiaOcspServiceConfiguration");
    }

    /**
     * A static factory method that returns either the designated or AIA OCSP service instance depending on whether
     * the designated OCSP service is configured and supports the issuer of the certificate.
     *
     * @param certificate subject certificate that is to be checked with OCSP
     * @return either the designated or AIA OCSP service instance
     * @throws AuthTokenException when AIA URL is not found in certificate
     * @throws CertificateEncodingException when certificate is invalid
     */
    public OcspService getService(X509Certificate certificate) throws AuthTokenException, CertificateEncodingException {
        if (designatedOcspService != null && designatedOcspService.supportsIssuerOf(certificate)) {
            return designatedOcspService;
        }
        return new AiaOcspService(aiaOcspServiceConfiguration, certificate);
    }

}
