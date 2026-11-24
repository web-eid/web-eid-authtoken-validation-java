// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.security;

import eu.webeid.example.security.dto.AuthTokenDTO;
import eu.webeid.example.testutil.ObjectMother;
import eu.webeid.security.challenge.ChallengeNonce;
import eu.webeid.security.challenge.ChallengeNonceStore;
import eu.webeid.security.exceptions.UserCertificateDisallowedPolicyException;
import eu.webeid.security.validator.AuthTokenValidator;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import javax.security.auth.x500.X500Principal;
import java.time.ZonedDateTime;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(OutputCaptureExtension.class)
class AuthTokenDTOAuthenticationProviderTest {

    private static final X500Principal CERTIFICATE_ISSUER = new X500Principal("CN=Example CA");
    private static final ASN1ObjectIdentifier CERTIFICATE_POLICY = new ASN1ObjectIdentifier("1.2.3");

    @Test
    void whenAllowListRejectsCertificate_thenConfigurationDetailsAreLogged(CapturedOutput output) throws Exception {
        final UserCertificateDisallowedPolicyException validationException =
            new UserCertificateDisallowedPolicyException(CERTIFICATE_ISSUER, Set.of(CERTIFICATE_POLICY));

        authenticateWithValidationException(validationException);

        assertThat(output)
            .contains("Certificate policy allow-list rejected an unverified certificate")
            .contains("AuthTokenValidatorBuilder.withAllowedCertificatePolicies(...)")
            .contains("issuerRFC2253='CN=Example CA'")
            .contains("certificatePolicyOids=[1.2.3]");
    }

    @Test
    void whenDenyListRejectsCertificate_thenConfigurationDetailsAreNotLogged(CapturedOutput output) throws Exception {
        authenticateWithValidationException(new UserCertificateDisallowedPolicyException());

        assertThat(output).doesNotContain("AuthTokenValidatorBuilder.withAllowedCertificatePolicies(...)");
    }

    private static void authenticateWithValidationException(
            UserCertificateDisallowedPolicyException validationException) throws Exception {
        final AuthTokenValidator tokenValidator = mock(AuthTokenValidator.class);
        final ChallengeNonceStore challengeNonceStore = mock(ChallengeNonceStore.class);
        final AuthTokenDTO credentials = ObjectMother.mockAuthToken();
        when(challengeNonceStore.getAndRemove()).thenReturn(
            new ChallengeNonce("nonce", ZonedDateTime.now().plusMinutes(1))
        );
        when(tokenValidator.validate(any(), eq("nonce"))).thenThrow(validationException);

        final AuthTokenDTOAuthenticationProvider provider =
            new AuthTokenDTOAuthenticationProvider(tokenValidator, challengeNonceStore);

        assertThatThrownBy(() -> provider.authenticate(
            new UsernamePasswordAuthenticationToken("user", credentials)
        ))
            .isInstanceOf(AuthenticationServiceException.class)
            .hasCause(validationException);
    }
}
