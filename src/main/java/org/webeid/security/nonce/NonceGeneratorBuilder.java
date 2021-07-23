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

package org.webeid.security.nonce;

import javax.cache.Cache;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.Objects;

/**
 * Builder for constructing {@link NonceGenerator} instances.
 */
public class NonceGeneratorBuilder {

    private static final SecureRandom RANDOM = new SecureRandom();

    private Cache<String, ZonedDateTime> cache;
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
    public NonceGeneratorBuilder withNonceTtl(Duration duration) {
        this.ttl = duration;
        return this;
    }

    /**
     * Sets the cache where generated nonce values will be stored.
     * <p>
     * The key of the cache is the Base64-encoded nonce and the value is the nonce expiry time.
     *
     * @param cache nonce cache
     * @return current builder instance
     */
    public NonceGeneratorBuilder withNonceCache(Cache<String, ZonedDateTime> cache) {
        this.cache = cache;
        return this;
    }

    /**
     * Sets the source of random bytes for the nonce.
     *
     * @param secureRandom secure random generator
     * @return current builder instance
     */
    public NonceGeneratorBuilder withSecureRandom(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
        return this;
    }

    /**
     * Builds the new nonce generator instance.
     *
     * @return new nonce generator instance
     */
    public NonceGenerator build() {
        validateParameters();
        return new NonceGeneratorImpl(this.cache, this.secureRandom, this.ttl);
    }

    public static void requirePositiveDuration(Duration duration, String fieldName) {
        Objects.requireNonNull(duration, fieldName + " must not be null");
        if (duration.isNegative() || duration.isZero()) {
            throw new IllegalArgumentException(fieldName + " must be greater than zero");
        }
    }

    private void validateParameters() {
        Objects.requireNonNull(cache, "Cache must not be null");
        Objects.requireNonNull(secureRandom, "Secure random generator must not be null");
        requirePositiveDuration(ttl, "Nonce TTL");
    }
}
