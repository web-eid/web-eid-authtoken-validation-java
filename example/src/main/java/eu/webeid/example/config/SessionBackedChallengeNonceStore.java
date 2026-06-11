// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.config;

import org.springframework.beans.factory.ObjectFactory;
import eu.webeid.security.challenge.ChallengeNonce;
import eu.webeid.security.challenge.ChallengeNonceStore;

import jakarta.servlet.http.HttpSession;

public class SessionBackedChallengeNonceStore implements ChallengeNonceStore {

    private static final String CHALLENGE_NONCE_KEY = "challenge-nonce";

    final ObjectFactory<HttpSession> httpSessionFactory;

    public SessionBackedChallengeNonceStore(ObjectFactory<HttpSession> httpSessionFactory) {
        this.httpSessionFactory = httpSessionFactory;
    }

    @Override
    public void put(ChallengeNonce challengeNonce) {
        currentSession().setAttribute(CHALLENGE_NONCE_KEY, challengeNonce);
    }

    @Override
    public ChallengeNonce getAndRemoveImpl() {
        final ChallengeNonce challengeNonce = (ChallengeNonce) currentSession().getAttribute(CHALLENGE_NONCE_KEY);
        currentSession().removeAttribute(CHALLENGE_NONCE_KEY);
        return challengeNonce;
    }

    private HttpSession currentSession() {
        return httpSessionFactory.getObject();
    }

}
