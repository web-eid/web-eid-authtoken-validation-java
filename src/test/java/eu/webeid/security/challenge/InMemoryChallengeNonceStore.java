// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.challenge;

public class InMemoryChallengeNonceStore implements ChallengeNonceStore {

    private ChallengeNonce challengeNonce;

    @Override
    public void put(ChallengeNonce challengeNonce) {
        this.challengeNonce = challengeNonce;
    }

    @Override
    public ChallengeNonce getAndRemoveImpl() {
        final ChallengeNonce result = challengeNonce;
        challengeNonce = null;
        return result;
    }

}
