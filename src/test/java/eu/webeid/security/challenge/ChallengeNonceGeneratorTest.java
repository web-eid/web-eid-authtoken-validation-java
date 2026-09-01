// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

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
