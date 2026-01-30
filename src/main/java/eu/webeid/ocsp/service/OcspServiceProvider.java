// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.ocsp.service;

import eu.webeid.ocsp.exceptions.UserCertificateOCSPCheckFailedException;
import eu.webeid.security.exceptions.AuthTokenException;
import org.bouncycastle.asn1.x500.X500Name;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static eu.webeid.ocsp.protocol.IssuerDistinguishedName.getIssuerDistinguishedName;

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
     * the designated OCSP service is configured and supports the issuer of the certificate.
     *
     * @param certificate subject certificate that is to be checked with OCSP
     * @return either the designated or AIA OCSP service instance
     * @throws UserCertificateOCSPCheckFailedException when issuer common name is not found in certificate
     * @throws IllegalArgumentException when certificate is invalid
     */
    public OcspService getService(X509Certificate certificate) throws AuthTokenException, CertificateEncodingException {
        if (designatedOcspService != null && designatedOcspService.supportsIssuerOf(certificate)) {
            return designatedOcspService;
        }
        X500Name issuerDistinguishedName = getIssuerDistinguishedName(certificate);
        FallbackOcspService fallbackOcspService = fallbackOcspServiceMap.get(issuerDistinguishedName);
        return new AiaOcspService(aiaOcspServiceConfiguration, certificate, fallbackOcspService);
    }
}
