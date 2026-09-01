// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.challenge;

import eu.webeid.security.util.DateAndTime;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Objects;

/**
 * Builder for constructing {@link ChallengeNonceGenerator} instances.
 */
public class ChallengeNonceGeneratorBuilder {

    private static final SecureRandom RANDOM = new SecureRandom();

    private ChallengeNonceStore challengeNonceStore;
    private SecureRandom secureRandom = RANDOM;
    private Duration ttl = Duration.ofMinutes(5);

    /**
     * Override default nonce time-to-live duration.
     * <p>
     * When the time-to-live passes, the nonce is considered to be expired.
     *
     * @param duration challenge nonce time-to-live duration
     * @return current builder instance
     */
    public ChallengeNonceGeneratorBuilder withNonceTtl(Duration duration) {
        this.ttl = duration;
        return this;
    }

    /**
     * Sets the challenge nonce store where the generated challenge nonces will be stored.
     *
     * @param challengeNonceStore challenge nonce store
     * @return current builder instance
     */
    public ChallengeNonceGeneratorBuilder withChallengeNonceStore(ChallengeNonceStore challengeNonceStore) {
        this.challengeNonceStore = challengeNonceStore;
        return this;
    }

    /**
     * Sets the source of random bytes for the nonce.
     *
     * @param secureRandom secure random generator
     * @return current builder instance
     */
    public ChallengeNonceGeneratorBuilder withSecureRandom(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
        return this;
    }

    /**
     * Validates the configuration and builds the {@link ChallengeNonceGenerator} instance.
     *
     * @return new challenge nonce generator instance
     */
    public ChallengeNonceGenerator build() {
        validateParameters();
        return new ChallengeNonceGeneratorImpl(this.challengeNonceStore, this.secureRandom, this.ttl);
    }

    private void validateParameters() {
        Objects.requireNonNull(challengeNonceStore, "Challenge nonce store must not be null");
        Objects.requireNonNull(secureRandom, "Secure random generator must not be null");
        DateAndTime.requirePositiveDuration(ttl, "Nonce TTL");
    }
}
