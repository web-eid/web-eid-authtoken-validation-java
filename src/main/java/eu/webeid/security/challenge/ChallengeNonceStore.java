// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.challenge;

import eu.webeid.security.exceptions.ChallengeNonceExpiredException;
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.exceptions.ChallengeNonceNotFoundException;

import static eu.webeid.security.util.DateAndTime.utcNow;

/**
 * A store for storing generated challenge nonces and accessing their generation time.
 */
public interface ChallengeNonceStore {

    void put(ChallengeNonce challengeNonce);

    ChallengeNonce getAndRemoveImpl();

    default ChallengeNonce getAndRemove() throws AuthTokenException {
        final ChallengeNonce challengeNonce = getAndRemoveImpl();
        if (challengeNonce == null) {
            throw new ChallengeNonceNotFoundException();
        }
        if (utcNow().isAfter(challengeNonce.getExpirationTime())) {
            throw new ChallengeNonceExpiredException();
        }
        return challengeNonce;
    }

}
