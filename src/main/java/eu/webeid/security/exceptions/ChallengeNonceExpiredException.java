// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.exceptions;

/**
 * Thrown when the challenge nonce has expired.
 */
public class ChallengeNonceExpiredException extends AuthTokenException {

    public ChallengeNonceExpiredException() {
        super("Challenge nonce has expired");
    }

}
