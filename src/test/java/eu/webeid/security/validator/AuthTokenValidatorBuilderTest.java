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

package eu.webeid.security.validator;

import eu.webeid.security.testutil.AuthTokenValidators;
import eu.webeid.security.validator.ocsp.OcspServiceProvider;
import eu.webeid.security.validator.ocsp.service.AiaOcspService;
import eu.webeid.security.validator.ocsp.service.AiaOcspServiceConfiguration.ResponderIssuerMatchingPolicy;
import eu.webeid.security.validator.ocsp.service.OcspService;
import eu.webeid.security.validator.versionvalidators.AuthTokenVersionValidatorFactory;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.net.URI;
import java.time.Duration;
import java.util.List;

import static eu.webeid.security.validator.ocsp.service.AiaOcspServiceConfiguration.ResponderIssuerMatchingPolicy.EXACT_CERTIFICATE;
import static eu.webeid.security.validator.ocsp.service.AiaOcspServiceConfiguration.ResponderIssuerMatchingPolicy.SUBJECT_AND_PUBLIC_KEY;
import static eu.webeid.security.testutil.Certificates.getJaakKristjanEsteid2018Cert;
import static eu.webeid.security.testutil.Certificates.getTestEsteid2018CA;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class AuthTokenValidatorBuilderTest {

    // AuthTokenValidationConfiguration has a package-private constructor, but some tests need access to it outside its package.
    // Provide a public accessor to it for these tests.
    public static final AuthTokenValidationConfiguration CONFIGURATION = new AuthTokenValidationConfiguration();

    final AuthTokenValidatorBuilder builder = new AuthTokenValidatorBuilder();

    @Test
    void testOriginMissing() {
        assertThatThrownBy(builder::build)
            .isInstanceOf(NullPointerException.class)
            .hasMessageStartingWith("Origin URI must not be null");
    }

    @Test
    void testRootCertificateAuthorityMissing() {
        final AuthTokenValidatorBuilder builderWithMissingRootCa = builder
            .withSiteOrigin(URI.create("https://ria.ee"));
        assertThatThrownBy(builderWithMissingRootCa::build)
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageStartingWith("At least one trusted certificate authority must be provided");
    }

    @Test
    void testValidatorOriginNotUrl() {
        assertThatThrownBy(() -> AuthTokenValidators.getAuthTokenValidator("not-url"))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void testValidatorOriginExcessiveElements() {
        assertThatThrownBy(() -> AuthTokenValidators.getAuthTokenValidator("https://ria.ee/excessive-element"))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void testValidatorOriginNotHttps() {
        assertThatThrownBy(() -> AuthTokenValidators.getAuthTokenValidator("http://ria.ee"))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void testValidatorOriginNotValidUrl() {
        assertThatThrownBy(() -> AuthTokenValidators.getAuthTokenValidator("ria://ria.ee"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageStartingWith("Provided URI is not a valid URL");
    }

    @Test
    void testValidatorOriginNotValidSyntax() {
        assertThatThrownBy(() -> AuthTokenValidators.getAuthTokenValidator("https:///ria.ee"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageStartingWith("An URI syntax exception occurred");
    }

    @Test
    void testInvalidOcspResponseTimeSkew() throws Exception {
        final AuthTokenValidatorBuilder builderWithInvalidOcspResponseTimeSkew = AuthTokenValidators.getDefaultAuthTokenValidatorBuilder()
            .withAllowedOcspResponseTimeSkew(Duration.ofMinutes(-1));
        assertThatThrownBy(builderWithInvalidOcspResponseTimeSkew::build)
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageStartingWith("Allowed OCSP response time-skew must be greater than zero");
    }

    @Test
    void testInvalidMaxOcspResponseThisUpdateAge() throws Exception {
        final AuthTokenValidatorBuilder builderWithInvalidOcspResponseTimeSkew = AuthTokenValidators.getDefaultAuthTokenValidatorBuilder()
            .withMaxOcspResponseThisUpdateAge(Duration.ZERO);
        assertThatThrownBy(builderWithInvalidOcspResponseTimeSkew::build)
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageStartingWith("Max OCSP response thisUpdate age must be greater than zero");
    }

    @Test
    void testInvalidOcspRequestTimeout() throws Exception {
        final AuthTokenValidatorBuilder builderWithInvalidOcspResponseTimeSkew = AuthTokenValidators.getDefaultAuthTokenValidatorBuilder()
            .withOcspRequestTimeout(Duration.ofMinutes(-1));
        assertThatThrownBy(builderWithInvalidOcspResponseTimeSkew::build)
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageStartingWith("OCSP request timeout must be greater than zero");
    }

    @Test
    void aiaOcspResponderIssuerMatchingPolicyDefaultsToExactCertificate() {
        final AuthTokenValidationConfiguration configuration = new AuthTokenValidationConfiguration();

        assertThat(configuration.getAiaOcspResponderIssuerMatchingPolicy()).isEqualTo(EXACT_CERTIFICATE);
        assertThat(configuration.copy().getAiaOcspResponderIssuerMatchingPolicy()).isEqualTo(EXACT_CERTIFICATE);
    }

    @Test
    void aiaOcspResponderIssuerMatchingPolicyIsCopied() {
        final AuthTokenValidationConfiguration configuration = new AuthTokenValidationConfiguration();

        configuration.setAiaOcspResponderIssuerMatchingPolicy(SUBJECT_AND_PUBLIC_KEY);

        assertThat(configuration.copy().getAiaOcspResponderIssuerMatchingPolicy())
            .isEqualTo(SUBJECT_AND_PUBLIC_KEY);
    }

    @Test
    void configuredAiaOcspResponderIssuerMatchingPolicyReachesAiaService() throws Exception {
        final AuthTokenValidator validator = AuthTokenValidators.getDefaultAuthTokenValidatorBuilder()
            .withAiaOcspResponderIssuerMatchingPolicy(SUBJECT_AND_PUBLIC_KEY)
            .withOcspClient((url, request) -> null)
            .build();

        final OcspServiceProvider serviceProvider = ocspServiceProviderOf(validator);
        final OcspService aiaService = serviceProvider.getService(
            getJaakKristjanEsteid2018Cert(), getTestEsteid2018CA(), List.of());

        assertThat(aiaService).isInstanceOf(AiaOcspService.class);
        final ResponderIssuerMatchingPolicy matchingPolicy = getField(aiaService, "responderIssuerMatchingPolicy");
        assertThat(matchingPolicy).isEqualTo(SUBJECT_AND_PUBLIC_KEY);
    }

    // The version validators all share a single OcspServiceProvider instance; locate it without depending on the
    // validator list order or on which class in the validator hierarchy declares the field.
    private static OcspServiceProvider ocspServiceProviderOf(AuthTokenValidator validator) throws Exception {
        final AuthTokenVersionValidatorFactory factory = getField(validator, "tokenValidatorFactory");
        final List<?> validators = getField(factory, "validators");
        for (final Object versionValidator : validators) {
            final Field field = findField(versionValidator.getClass(), "ocspServiceProvider");
            if (field != null) {
                field.setAccessible(true);
                return (OcspServiceProvider) field.get(versionValidator);
            }
        }
        throw new AssertionError("No version validator exposes an OcspServiceProvider field");
    }

    @SuppressWarnings("unchecked")
    private static <T> T getField(Object instance, String fieldName) throws Exception {
        final Field field = findField(instance.getClass(), fieldName);
        if (field == null) {
            throw new NoSuchFieldException(fieldName);
        }
        field.setAccessible(true);
        return (T) field.get(instance);
    }

    private static Field findField(Class<?> type, String fieldName) {
        for (Class<?> currentClass = type; currentClass != null; currentClass = currentClass.getSuperclass()) {
            try {
                return currentClass.getDeclaredField(fieldName);
            } catch (NoSuchFieldException ignored) {
                // Not declared here; search the superclass.
            }
        }
        return null;
    }
}
