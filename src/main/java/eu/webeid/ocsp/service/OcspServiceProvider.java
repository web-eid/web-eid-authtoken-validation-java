// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.ocsp.service;

import eu.webeid.security.exceptions.AuthTokenException;
import org.bouncycastle.asn1.x500.X500Name;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class OcspServiceProvider {

    private final DesignatedOcspService designatedOcspService;
    private final AiaOcspServiceConfiguration aiaOcspServiceConfiguration;
    private final Map<X500Name, FallbackOcspService> fallbackOcspServiceMap = new HashMap<>();

    public OcspServiceProvider(DesignatedOcspServiceConfiguration designatedOcspServiceConfiguration, AiaOcspServiceConfiguration aiaOcspServiceConfiguration) {
        this(designatedOcspServiceConfiguration, aiaOcspServiceConfiguration, null);
    }

    public OcspServiceProvider(DesignatedOcspServiceConfiguration designatedOcspServiceConfiguration, AiaOcspServiceConfiguration aiaOcspServiceConfiguration, Collection<FallbackOcspServiceConfiguration> fallbackOcspServiceConfigurations) {
        designatedOcspService = designatedOcspServiceConfiguration != null ?
            new DesignatedOcspService(designatedOcspServiceConfiguration)
            : null;
        this.aiaOcspServiceConfiguration = Objects.requireNonNull(aiaOcspServiceConfiguration, "aiaOcspServiceConfiguration");
        if (fallbackOcspServiceConfigurations != null) {
            for (FallbackOcspServiceConfiguration configuration : fallbackOcspServiceConfigurations) {
                fallbackOcspServiceMap.put(configuration.getIssuerDN(), new FallbackOcspService(configuration));
            }
        }
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
        final X500Name issuerDistinguishedName = X500Name.getInstance(issuerCertificate.getSubjectX500Principal().getEncoded());
        final FallbackOcspService fallbackOcspService = fallbackOcspServiceMap.get(issuerDistinguishedName);
        return new AiaOcspService(aiaOcspServiceConfiguration, certificate, fallbackOcspService);
    }
}
