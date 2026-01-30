// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.ocsp.service;

import eu.webeid.security.exceptions.AuthTokenException;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class OcspServiceProvider {

    private final DesignatedOcspService designatedOcspService;
    private final AiaOcspServiceConfiguration aiaOcspServiceConfiguration;
    private final Map<X509Certificate, FallbackOcspService> fallbackOcspServiceMap;

    public OcspServiceProvider(DesignatedOcspServiceConfiguration designatedOcspServiceConfiguration, AiaOcspServiceConfiguration aiaOcspServiceConfiguration) {
        this(designatedOcspServiceConfiguration, aiaOcspServiceConfiguration, null);
    }

    public OcspServiceProvider(DesignatedOcspServiceConfiguration designatedOcspServiceConfiguration, AiaOcspServiceConfiguration aiaOcspServiceConfiguration, Collection<FallbackOcspServiceConfiguration> fallbackOcspServiceConfigurations) {
        designatedOcspService = designatedOcspServiceConfiguration != null ?
            new DesignatedOcspService(designatedOcspServiceConfiguration)
            : null;
        this.aiaOcspServiceConfiguration = Objects.requireNonNull(aiaOcspServiceConfiguration, "aiaOcspServiceConfiguration");
        this.fallbackOcspServiceMap = buildFallbackOcspServiceMap(fallbackOcspServiceConfigurations);
    }

    private static Map<X509Certificate, FallbackOcspService> buildFallbackOcspServiceMap(Collection<FallbackOcspServiceConfiguration> fallbackOcspServiceConfigurations) {
        if (fallbackOcspServiceConfigurations != null) {
            Map<X509Certificate, FallbackOcspService> fallbackOcspServices = new HashMap<>();
            for (FallbackOcspServiceConfiguration configuration : fallbackOcspServiceConfigurations) {
                fallbackOcspServices.put(configuration.getIssuerCertificate(), new FallbackOcspService(configuration));
            }
            return Map.copyOf(fallbackOcspServices);
        }
        return Map.of();
    }

    /**
     * A static factory method that returns either the designated or AIA OCSP service instance depending on whether
     * the designated OCSP service is configured for the certificate's validated direct issuer.
     *
     * @param certificate subject certificate that is to be checked with OCSP
     * @param issuerCertificate direct issuer from the validated certification path
     * @return either the designated or AIA OCSP service instance
     * @throws AuthTokenException when AIA URL is not found in certificate
     */
    public OcspService getService(X509Certificate certificate, X509Certificate issuerCertificate) throws AuthTokenException {
        if (designatedOcspService != null && designatedOcspService.supportsIssuer(issuerCertificate)) {
            return designatedOcspService;
        }
        final FallbackOcspService fallbackOcspService = fallbackOcspServiceMap.get(issuerCertificate);
        return new AiaOcspService(aiaOcspServiceConfiguration, certificate, fallbackOcspService);
    }
}
