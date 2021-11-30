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
