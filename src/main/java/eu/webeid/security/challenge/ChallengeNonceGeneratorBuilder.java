/*
 * Copyright (c) 2020, 2021 The Web eID Project
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
     * @param duration time-to-live duration
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
