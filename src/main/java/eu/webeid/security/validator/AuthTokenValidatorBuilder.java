/*
 * Copyright (c) 2020-2021 Estonian Information System Authority
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

package eu.webeid.security.validator;

import eu.webeid.security.exceptions.JceException;
import eu.webeid.security.validator.ocsp.service.DesignatedOcspServiceConfiguration;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Collections;
import java.util.stream.Collectors;

/**
 * Builder for constructing {@link AuthTokenValidator} instances.
 */
public class AuthTokenValidatorBuilder {

    private static final Logger LOG = LoggerFactory.getLogger(AuthTokenValidatorBuilder.class);

    private final AuthTokenValidationConfiguration configuration = new AuthTokenValidationConfiguration();

    /**
     * Sets the expected site origin, i.e. the domain that the application is running on.
     * <p>
     * Origin is a mandatory configuration parameter.
     *
     * @param origin origin URL as defined in <a href="https://developer.mozilla.org/en-US/docs/Web/API/Location/origin">MDN</a>,
     *               in the form of {@code <scheme> "://" <hostname> [ ":" <port> ]}
     * @return the builder instance for method chaining
     */
    public AuthTokenValidatorBuilder withSiteOrigin(URI origin) {
        configuration.setSiteOrigin(origin);
        LOG.debug("Origin set to {}", configuration.getSiteOrigin());
        return this;
    }

    /**
     * Adds the given certificates to the list of trusted intermediate Certificate Authorities
     * used during validation of subject and OCSP responder certificates.
     * In order for a user or OCSP responder certificate to be considered valid, the certificate
     * of the issuer of the certificate must be present in this list.
     * <p>
     * At least one trusted intermediate Certificate Authority must be provided as a mandatory configuration parameter.
     *
     * @param certificates trusted intermediate Certificate Authority certificates
     * @return the builder instance for method chaining
     */
    public AuthTokenValidatorBuilder withTrustedCertificateAuthorities(X509Certificate... certificates) {
        Collections.addAll(configuration.getTrustedCACertificates(), certificates);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Trusted intermediate certificate authorities set to {}",
                configuration.getTrustedCACertificates().stream()
                    .map(X509Certificate::getSubjectDN)
                    .collect(Collectors.toList()));
        }
        return this;
    }

    /**
     * Adds the given policies to the list of disallowed user certificate policies.
     * In order for the user certificate to be considered valid, it must not contain any policies
     * present in this list.
     *
     * @param policies disallowed user certificate policies
     * @return the builder instance for method chaining
     */
    public AuthTokenValidatorBuilder withDisallowedCertificatePolicies(ASN1ObjectIdentifier... policies) {
        Collections.addAll(configuration.getDisallowedSubjectCertificatePolicies(), policies);
        LOG.debug("Disallowed subject certificate policies set to {}", configuration.getDisallowedSubjectCertificatePolicies());
        return this;
    }

    /**
     * Turns off user certificate revocation check with OCSP.
     * <p>
     * <b>Turning off user certificate revocation check with OCSP is dangerous and should be
     * used only in exceptional circumstances.</b>
     * By default, the revocation check is turned on.
     *
     * @return the builder instance for method chaining.
     */
    public AuthTokenValidatorBuilder withoutUserCertificateRevocationCheckWithOcsp() {
        configuration.setUserCertificateRevocationCheckWithOcspDisabled();
        LOG.warn("User certificate revocation check with OCSP is disabled, " +
            "you should turn off the revocation check only in exceptional circumstances");
        return this;
    }

    /**
     * Sets both the connection and response timeout of user certificate revocation check OCSP requests.
     * <p>
     * This is an optional configuration parameter, the default is 5 seconds.
     *
     * @param ocspRequestTimeout the duration of OCSP request connection and response timeout
     * @return the builder instance for method chaining.
     */
    public AuthTokenValidatorBuilder withOcspRequestTimeout(Duration ocspRequestTimeout) {
        configuration.setOcspRequestTimeout(ocspRequestTimeout);
        LOG.debug("OCSP request timeout set to {}", ocspRequestTimeout);
        return this;
    }

    /**
     * Adds the given URLs to the list of OCSP URLs for which the nonce protocol extension will be disabled.
     * The OCSP URL is extracted from the user certificate and some OCSP services don't support the nonce extension.
     *
     * @param urls OCSP URLs for which the nonce protocol extension will be disabled
     * @return the builder instance for method chaining
     */
    public AuthTokenValidatorBuilder withNonceDisabledOcspUrls(URI... urls) {
        Collections.addAll(configuration.getNonceDisabledOcspUrls(), urls);
        LOG.debug("OCSP URLs for which the nonce protocol extension is disabled set to {}", configuration.getNonceDisabledOcspUrls());
        return this;
    }

    /**
     * Activates the provided designated OCSP service for user certificate revocation check with OCSP.
     * The designated service is only used for checking the status of the certificates whose issuers are
     * supported by the service, falling back to the default OCSP service access location from
     * the certificate's AIA extension if not.
     *
     * @param serviceConfiguration configuration of the designated OCSP service
     * @return the builder instance for method chaining
     */
    public AuthTokenValidatorBuilder withDesignatedOcspServiceConfiguration(DesignatedOcspServiceConfiguration serviceConfiguration) {
        configuration.setDesignatedOcspServiceConfiguration(serviceConfiguration);
        LOG.debug("Using designated OCSP service configuration");
        return this;
    }

    /**
     * Validates the configuration and builds the {@link AuthTokenValidator} object with it.
     * The returned {@link AuthTokenValidator} object is immutable/thread-safe.
     *
     * @return the configured authentication token validator object
     * @throws NullPointerException     when required parameters are null
     * @throws IllegalArgumentException when any parameter is invalid
     * @throws RuntimeException         when JCE configuration is invalid
     */
    public AuthTokenValidator build() throws NullPointerException, IllegalArgumentException, JceException {
        configuration.validate();
        return new AuthTokenValidatorImpl(configuration);
    }

}
