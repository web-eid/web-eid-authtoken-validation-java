// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.exceptions;

/**
 * Thrown when the challenge nonce was not found in the nonce store.
 */
public class ChallengeNonceNotFoundException extends AuthTokenException {

    public ChallengeNonceNotFoundException() {
        super("Challenge nonce was not found in the nonce store");
    }

}
