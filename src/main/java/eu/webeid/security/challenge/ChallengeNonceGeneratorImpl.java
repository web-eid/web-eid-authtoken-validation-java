// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.challenge;

import eu.webeid.security.util.DateAndTime;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.Base64;

final class ChallengeNonceGeneratorImpl implements ChallengeNonceGenerator {

    private final ChallengeNonceStore challengeNonceStore;
    private final SecureRandom secureRandom;
    private final Duration ttl;

    ChallengeNonceGeneratorImpl(ChallengeNonceStore challengeNonceStore, SecureRandom secureRandom, Duration ttl) {
        this.challengeNonceStore = challengeNonceStore;
        this.secureRandom = secureRandom;
        this.ttl = ttl;
    }

    @Override
    public ChallengeNonce generateAndStoreNonce() {
        final byte[] nonceBytes = new byte[NONCE_LENGTH];
        secureRandom.nextBytes(nonceBytes);
        final ZonedDateTime expirationTime = DateAndTime.utcNow().plus(ttl);
        final String base64Nonce = Base64.getEncoder().encodeToString(nonceBytes);
        final ChallengeNonce challengeNonce = new ChallengeNonce(base64Nonce, expirationTime);
        challengeNonceStore.put(challengeNonce);
        return challengeNonce;
    }

}
