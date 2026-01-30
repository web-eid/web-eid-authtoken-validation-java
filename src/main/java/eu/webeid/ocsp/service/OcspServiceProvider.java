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

import eu.webeid.ocsp.exceptions.UserCertificateOCSPCheckFailedException;
import eu.webeid.resilientocsp.service.FallbackOcspService;
import eu.webeid.resilientocsp.service.FallbackOcspServiceConfiguration;
import eu.webeid.security.exceptions.AuthTokenException;

import java.net.URI;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import static eu.webeid.ocsp.protocol.OcspUrl.getOcspUri;

public class OcspServiceProvider {

    private final DesignatedOcspService designatedOcspService;
    private final AiaOcspServiceConfiguration aiaOcspServiceConfiguration;
    private final Map<URI, FallbackOcspService> fallbackOcspServiceMap;

    public OcspServiceProvider(DesignatedOcspServiceConfiguration designatedOcspServiceConfiguration, AiaOcspServiceConfiguration aiaOcspServiceConfiguration) {
        this(designatedOcspServiceConfiguration, aiaOcspServiceConfiguration, null);
    }

    public OcspServiceProvider(DesignatedOcspServiceConfiguration designatedOcspServiceConfiguration, AiaOcspServiceConfiguration aiaOcspServiceConfiguration, Collection<FallbackOcspServiceConfiguration> fallbackOcspServiceConfigurations) {
        designatedOcspService = designatedOcspServiceConfiguration != null ?
            new DesignatedOcspService(designatedOcspServiceConfiguration)
            : null;
        this.aiaOcspServiceConfiguration = Objects.requireNonNull(aiaOcspServiceConfiguration, "aiaOcspServiceConfiguration");
        this.fallbackOcspServiceMap = fallbackOcspServiceConfigurations != null ? fallbackOcspServiceConfigurations.stream()
            .collect(Collectors.toMap(FallbackOcspServiceConfiguration::getOcspServiceAccessLocation, FallbackOcspService::new))
            : Map.of();
    }

    /**
     * A static factory method that returns either the designated or AIA OCSP service instance depending on whether
     * the designated OCSP service is configured and supports the issuer of the certificate.
     *
     * @param certificate subject certificate that is to be checked with OCSP
     * @return either the designated or AIA OCSP service instance
     * @throws AuthTokenException when AIA URL is not found in certificate
     * @throws IllegalArgumentException when certificate is invalid
     */
    public OcspService getService(X509Certificate certificate) throws AuthTokenException, CertificateEncodingException {
        if (designatedOcspService != null && designatedOcspService.supportsIssuerOf(certificate)) {
            return designatedOcspService;
        }
        URI ocspServiceUri = getOcspUri(certificate).orElseThrow(() ->
            new UserCertificateOCSPCheckFailedException("Getting the AIA OCSP responder field from the certificate failed"));
        FallbackOcspService fallbackOcspService = fallbackOcspServiceMap.get(ocspServiceUri);
        return new AiaOcspService(aiaOcspServiceConfiguration, certificate, fallbackOcspService);
    }

    public FallbackOcspService getFallbackService(URI ocspServiceUri) {
        return fallbackOcspServiceMap.get(ocspServiceUri);
    }
}
