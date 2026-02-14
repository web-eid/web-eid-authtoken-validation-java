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

package eu.webeid.example.config;

import java.time.Duration;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties
@ConfigurationProperties(prefix = "web-eid-auth-token.validation")
public class YAMLConfig {

    private static final Logger LOG = LoggerFactory.getLogger(YAMLConfig.class);

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
        if (StringUtils.endsWith(localOrigin, "/")) {
            throw new IllegalArgumentException("Configuration parameter local-origin cannot end with '/': " + localOrigin);
        }
        if (StringUtils.startsWith(localOrigin, "http:")) {
            try {
                if (InetAddress.getByName(new URI(localOrigin).getHost()).isLoopbackAddress()) {
                    this.localOrigin = localOrigin.replaceFirst("^http:", "https:");
                    LOG.warn("Configuration local-origin contains http protocol {}, which is not supported. Replacing it with secure {}", localOrigin, this.localOrigin);
                    return;
                }
            } catch (URISyntaxException e) {
                LOG.error("Configuration parameter origin-local does not contain an URL: {}", localOrigin, e);
            } catch (UnknownHostException e) {
                LOG.error("Unable to determine if origin-local {} is loopback address", localOrigin, e);
            }
        }
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
