// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.web.rest;

import eu.webeid.example.service.dto.ChallengeDTO;
import eu.webeid.security.challenge.ChallengeNonceGenerator;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("auth")
public class ChallengeController {

    private final ChallengeNonceGenerator challengeNonceGenerator;

    public ChallengeController(ChallengeNonceGenerator challengeNonceGenerator) {
        this.challengeNonceGenerator = challengeNonceGenerator;
    }

    @GetMapping("challenge")
    public ChallengeDTO challenge() {
        final ChallengeDTO challenge = new ChallengeDTO();
        challenge.setNonce(challengeNonceGenerator.generateAndStoreNonce().getBase64EncodedNonce());
        return challenge;
    }
}
