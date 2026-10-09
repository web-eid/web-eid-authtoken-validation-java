// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "web-eid-auth-token.csrf")
public class CsrfConfigurationProperties {

    private boolean useSpaConfiguration;
    private String cookieDomain;

    public boolean isUseSpaConfiguration() {
        return useSpaConfiguration;
    }

    public void setUseSpaConfiguration(boolean useSpaConfiguration) {
        this.useSpaConfiguration = useSpaConfiguration;
    }

    public String getCookieDomain() {
        return cookieDomain;
    }

    public void setCookieDomain(String cookieDomain) {
        this.cookieDomain = cookieDomain;
    }
}
