// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.validator;

import eu.webeid.security.exceptions.JceException;
import eu.webeid.security.validator.revocationcheck.CertificateRevocationChecker;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509Certificate;
import java.util.Collections;

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
                    .map(X509Certificate::getSubjectX500Principal)
                    .toList());
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
     * Turns off user certificate revocation check (with OCSP and/or CRL).
     * <p>
     * <b>Turning off user certificate revocation check is dangerous and should be used only in
     * exceptional circumstances.</b>
     * By default, the revocation check is turned on.
     *
     * @return the builder instance for method chaining.
     */
    public AuthTokenValidatorBuilder withoutUserCertificateRevocationCheck() {
        configuration.setUserCertificateRevocationCheckDisabled();
        LOG.warn("User certificate revocation check is disabled, " +
            "you should turn off the revocation check only in exceptional circumstances");
        return this;
    }

    /**
     * Controls whether the library supplies a nonce for platform OCSP requests. Enabled by default.
     * <p>
     * An explicitly configured {@code jdk.security.certpath.ocspNonce} JVM system property takes precedence:
     * {@code true} delegates nonce generation to the JDK and {@code false} disables it, regardless of this setting.
     * This setting has no effect on custom revocation checkers or when revocation checking is disabled.
     * Enabling a request nonce does not require the JDK to reject a response without a nonce.
     *
     * @param enabled whether to supply a nonce when the JVM nonce property is unset
     * @return the builder instance for method chaining
     */
    public AuthTokenValidatorBuilder withPlatformOcspNonceEnabled(boolean enabled) {
        configuration.setPlatformOcspNonceEnabled(enabled);
        return this;
    }

    /**
     * Configures a custom certificate revocation checker for validating user certificate revocation status.
     * <p>
     * When set, the platform (provider default) revocation mechanism is disabled and revocation checking is
     * delegated to the given {@link CertificateRevocationChecker}. This option is mutually exclusive with
     * {@link #withPKIXRevocationChecker(PKIXRevocationChecker)} and {@link #withoutUserCertificateRevocationCheck()}.
     *
     * @param customChecker custom certificate revocation checker implementation
     * @return the builder instance for method chaining
     */
    public AuthTokenValidatorBuilder withCertificateRevocationChecker(CertificateRevocationChecker customChecker) {
        configuration.setCertificateRevocationChecker(customChecker);
        return this;
    }

    /**
     * Configures a custom {@link PKIXRevocationChecker} to be used as the revocation mechanism during user certificate
     * validation with platform PKIX.
     * <p>
     * When set, this checker replaces the platform (provider default) {@link PKIXRevocationChecker}. This option is
     * mutually exclusive with {@link #withCertificateRevocationChecker(CertificateRevocationChecker)}
     * and {@link #withoutUserCertificateRevocationCheck()}.
     *
     * @param customChecker custom PKIX revocation checker
     * @return the builder instance for method chaining
     * @throws NullPointerException if {@code customChecker} is null
     */
    public AuthTokenValidatorBuilder withPKIXRevocationChecker(PKIXRevocationChecker customChecker) {
        configuration.setPkixRevocationChecker(customChecker);
        return this;
    }

    /**
     * Validates the configuration and builds the {@link AuthTokenValidator} object with it.
     * The returned {@link AuthTokenValidator} object is immutable/thread-safe.
     *
     * @return the configured authentication token validator object
     * @throws IllegalArgumentException when any parameter is invalid
     * @throws JceException             when JCE configuration is invalid
     */
    public AuthTokenValidator build() throws IllegalArgumentException, JceException {
        configuration.validate();
        return new AuthTokenValidatorImpl(configuration);
    }

}
