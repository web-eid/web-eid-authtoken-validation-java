// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.security;

import eu.webeid.example.security.dto.AuthTokenDTO;
import eu.webeid.security.authtoken.WebEidAuthToken;
import eu.webeid.security.challenge.ChallengeNonceStore;
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.validator.AuthTokenValidator;
import eu.webeid.security.validator.ValidationInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Component;

import java.security.cert.CertificateEncodingException;
import java.util.List;

/**
 * Validates the Web eID authentication token supplied in AuthTokenDTO.
 */
@Component
public class AuthTokenDTOAuthenticationProvider implements AuthenticationProvider {
    public static final String ROLE_USER = "ROLE_USER";
    private static final GrantedAuthority USER_ROLE = new SimpleGrantedAuthority(ROLE_USER);

    private static final Logger LOG = LoggerFactory.getLogger(AuthTokenDTOAuthenticationProvider.class);

    private final AuthTokenValidator tokenValidator;
    private final ChallengeNonceStore challengeNonceStore;

    public AuthTokenDTOAuthenticationProvider(AuthTokenValidator tokenValidator, ChallengeNonceStore challengeNonceStore) {
        this.tokenValidator = tokenValidator;
        this.challengeNonceStore = challengeNonceStore;
    }

    @Override
    public Authentication authenticate(Authentication auth) throws AuthenticationException {
        LOG.info("authenticate(): {}", auth);

        if (!(auth.getCredentials() instanceof AuthTokenDTO credentials) || credentials.token() == null) {
            throw new AuthenticationServiceException("Authentication token is missing");
        }
        final WebEidAuthToken authToken = credentials.token();

        final List<GrantedAuthority> authorities = List.of(USER_ROLE);

        try {
            final String nonce = challengeNonceStore.getAndRemove().getBase64EncodedNonce();
            final ValidationInfo validationInfo = tokenValidator.validate(authToken, nonce);
            return WebEidAuthentication.fromCertificate(validationInfo.subjectCertificate(), authorities);
        } catch (AuthTokenException e) {
            throw new AuthenticationServiceException("Web eID token validation failed", e);
        } catch (CertificateEncodingException e) {
            throw new AuthenticationServiceException("Web eID token has incorrect certificate subject fields", e);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        LOG.info("supports(): {}", authentication);
        return PreAuthenticatedAuthenticationToken.class.equals(authentication);
    }

}
