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

package eu.webeid.security.challenge;

import eu.webeid.security.exceptions.AuthTokenException;
import org.junit.jupiter.api.Test;
import eu.webeid.security.exceptions.ChallengeNonceExpiredException;
import eu.webeid.security.exceptions.ChallengeNonceNotFoundException;

import java.time.Duration;

import static org.assertj.core.api.Assertions.*;

class ChallengeNonceGeneratorTest {

    final ChallengeNonceStore challengeNonceStore = new InMemoryChallengeNonceStore();

    @Test
    void validateNonceGeneration() throws AuthTokenException {
        final ChallengeNonceGenerator challengeNonceGenerator = new ChallengeNonceGeneratorBuilder()
            .withChallengeNonceStore(challengeNonceStore)
            .withNonceTtl(Duration.ofSeconds(1))
            .build();

        final ChallengeNonce nonce1 = challengeNonceGenerator.generateAndStoreNonce();
        final ChallengeNonce nonce2 = challengeNonceGenerator.generateAndStoreNonce();
        final ChallengeNonce nonce2fromStore = challengeNonceStore.getAndRemove();

        assertThat(nonce2).isEqualTo(nonce2fromStore);

        assertThat(nonce1.getBase64EncodedNonce())
            .hasSize(44) // Base64-encoded 32 bytes
            .isNotEqualTo(nonce2.getBase64EncodedNonce());

        // It might be possible to add an entropy test by compressing the nonce bytes
        // and verifying that the result is longer than for non-random strings.
    }

    @Test
    void validateUnexpiredNonce() throws InterruptedException {
        final ChallengeNonceGenerator challengeNonceGenerator = new ChallengeNonceGeneratorBuilder()
            .withChallengeNonceStore(challengeNonceStore)
            .withNonceTtl(Duration.ofMillis(20))
            .build();

        challengeNonceGenerator.generateAndStoreNonce();

        Thread.sleep(10);

        assertThatCode(challengeNonceStore::getAndRemove)
            .doesNotThrowAnyException();
    }

    @Test
    void validateNonceExpiration() throws InterruptedException {
        final ChallengeNonceGenerator challengeNonceGenerator = new ChallengeNonceGeneratorBuilder()
            .withChallengeNonceStore(challengeNonceStore)
            .withNonceTtl(Duration.ofMillis(10))
            .build();

        challengeNonceGenerator.generateAndStoreNonce();

        Thread.sleep(20);

        assertThatThrownBy(challengeNonceStore::getAndRemove)
            .isInstanceOf(ChallengeNonceExpiredException.class);
    }

    @Test
    void validateNonceNotFound() {
        assertThatThrownBy(challengeNonceStore::getAndRemove)
            .isInstanceOf(ChallengeNonceNotFoundException.class);
    }

}
