package org.webeid.security.validator.ocsp.service;

import org.webeid.security.exceptions.AiaOcspResponderConfigurationException;

import java.net.URI;
import java.util.HashMap;

public class AiaOcspServiceConfiguration {

    private final HashMap<URI, AiaOcspResponderConfiguration> configs = new HashMap<>();

    public AiaOcspServiceConfiguration(AiaOcspResponderConfiguration... aiaOcspResponderConfiguration) {
        for (AiaOcspResponderConfiguration conf : aiaOcspResponderConfiguration) {
            configs.put(conf.getResponderUrl(), conf);
        }
    }

    public AiaOcspResponderConfiguration getResponderConfigurationForUrl(URI url) throws AiaOcspResponderConfigurationException {
        final AiaOcspResponderConfiguration configuration = configs.get(url);
        if (configuration == null) {
            throw new AiaOcspResponderConfigurationException("No AIA OCSP responder configuration exists for URL " + url);
        }
        return configuration;
    }

}
