package org.webeid.security.validator.ocsp;

import org.webeid.security.exceptions.TokenValidationException;
import org.webeid.security.validator.ocsp.service.AiaOcspService;
import org.webeid.security.validator.ocsp.service.AiaOcspServiceConfiguration;
import org.webeid.security.validator.ocsp.service.DesignatedOcspService;
import org.webeid.security.validator.ocsp.service.DesignatedOcspServiceConfiguration;
import org.webeid.security.validator.ocsp.service.OcspService;

import java.security.cert.X509Certificate;

public class OcspServiceProvider {

    private final AiaOcspServiceConfiguration aiaOcspServiceConfiguration;
    private final DesignatedOcspService designatedOcspService;

    public OcspServiceProvider(DesignatedOcspServiceConfiguration designatedOcspServiceConfiguration) {
        this.designatedOcspService = new DesignatedOcspService(designatedOcspServiceConfiguration);
        this.aiaOcspServiceConfiguration = null;
    }

    public OcspServiceProvider(AiaOcspServiceConfiguration aiaOcspServiceConfiguration) {
        this.aiaOcspServiceConfiguration = aiaOcspServiceConfiguration;
        this.designatedOcspService = null;
    }

    public OcspService getService(X509Certificate certificate) throws TokenValidationException {
        return designatedOcspService != null ?
            designatedOcspService :
            new AiaOcspService(aiaOcspServiceConfiguration, certificate);
    }

}
