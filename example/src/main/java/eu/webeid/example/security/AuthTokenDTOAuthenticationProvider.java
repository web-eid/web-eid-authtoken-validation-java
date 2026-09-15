// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.security;

import eu.webeid.example.security.dto.AuthTokenDTO;
import eu.webeid.security.authtoken.WebEidAuthToken;
import eu.webeid.security.challenge.ChallengeNonceStore;
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.validator.AuthTokenValidator;
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
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

/**
 * Parses JWT from token string inside AuthTokenDTO and attempts authentication.
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

        final PreAuthenticatedAuthenticationToken authentication = (PreAuthenticatedAuthenticationToken) auth;
        final WebEidAuthToken authToken = ((AuthTokenDTO) authentication.getCredentials()).getToken();

        final List<GrantedAuthority> authorities = Collections.singletonList(USER_ROLE);

        try {
            final String nonce = challengeNonceStore.getAndRemove().getBase64EncodedNonce();
            final X509Certificate userCertificate = tokenValidator.validate(authToken, nonce);
            return WebEidAuthentication.fromCertificate(userCertificate, authorities);
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
