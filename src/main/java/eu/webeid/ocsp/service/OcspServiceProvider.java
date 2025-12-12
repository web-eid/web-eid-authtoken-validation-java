// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.ocsp.service;

import eu.webeid.security.exceptions.AuthTokenException;

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
        return new AiaOcspService(aiaOcspServiceConfiguration, certificate);
    }

}
