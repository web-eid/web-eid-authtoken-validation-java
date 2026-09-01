// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.challenge;

import java.time.ZonedDateTime;
import java.util.Objects;

public class ChallengeNonce {

    private final String base64EncodedNonce;
    private final ZonedDateTime expirationTime;

    public ChallengeNonce(String base64EncodedNonce, ZonedDateTime expirationTime) {
        this.base64EncodedNonce = Objects.requireNonNull(base64EncodedNonce);
        this.expirationTime = Objects.requireNonNull(expirationTime);
    }

    public ZonedDateTime getExpirationTime() {
        return expirationTime;
    }

    public String getBase64EncodedNonce() {
        return base64EncodedNonce;
    }

}
