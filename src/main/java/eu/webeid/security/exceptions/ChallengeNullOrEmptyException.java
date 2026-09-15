// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.exceptions;

public class ChallengeNullOrEmptyException extends AuthTokenException {
    public ChallengeNullOrEmptyException() {
        super("Provided challenge is null or empty");
    }
}
