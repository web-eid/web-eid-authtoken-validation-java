// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.challenge;

/**
 * Generates challenge nonces, cryptographically strong random bytestrings that must be used only once.
 */
public interface ChallengeNonceGenerator {

    int NONCE_LENGTH = 32;

    /**
     * Generates a cryptographic nonce, a large random number that can be used only once,
     * and stores it in a {@link ChallengeNonceStore}.
     *
     * @return a {@link ChallengeNonce} that contains the Base64-encoded nonce and its expiry time
     */
    ChallengeNonce generateAndStoreNonce();
}
