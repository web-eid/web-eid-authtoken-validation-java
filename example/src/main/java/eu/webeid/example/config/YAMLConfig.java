// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.config;

import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties
@ConfigurationProperties(prefix = "web-eid-auth-token.validation")
public class YAMLConfig {

    @Value("local-origin")
    private String localOrigin;

    @Value("site-cert-hash")
    private String siteCertHash;

    @Value("truststore-password")
    private String trustStorePassword;

    private Duration ocspRequestTimeout = Duration.ofSeconds(5L);

    @Value("#{new Boolean('${web-eid-auth-token.validation.use-digidoc4j-prod-configuration}'.trim())}")
    private Boolean useDigiDoc4jProdConfiguration;

    public String getLocalOrigin() {
        return localOrigin;
    }

    public void setLocalOrigin(String localOrigin) {
        this.localOrigin = localOrigin;
    }

    public String getSiteCertHash() {
        return siteCertHash;
    }

    public void setSiteCertHash(String siteCertHash) {
        this.siteCertHash = siteCertHash;
    }

    public String getTrustStorePassword() {
        return trustStorePassword;
    }

    public void setTrustStorePassword(String trustStorePassword) {
        this.trustStorePassword = trustStorePassword;
    }

    public boolean getUseDigiDoc4jProdConfiguration() {
        return useDigiDoc4jProdConfiguration;
    }

    public void setUseDigiDoc4jProdConfiguration(boolean useDigiDoc4jProdConfiguration) {
        this.useDigiDoc4jProdConfiguration = useDigiDoc4jProdConfiguration;
    }

    public Duration getOcspRequestTimeout() {
        return ocspRequestTimeout;
    }

    public void setOcspRequestTimeout(Duration ocspRequestTimeout) {
        this.ocspRequestTimeout = ocspRequestTimeout;
    }
}
