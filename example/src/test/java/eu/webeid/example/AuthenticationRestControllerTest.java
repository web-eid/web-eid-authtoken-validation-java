// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import eu.webeid.example.web.rest.ChallengeController;

import static org.assertj.core.api.Assertions.assertThat;
import static eu.webeid.security.challenge.ChallengeNonceGenerator.NONCE_LENGTH;

@SpringBootTest
class AuthenticationRestControllerTest {

    @Autowired
    ChallengeController authRestController;

    @Test
    void testChallengeNonceLength() {
        assertThat(authRestController.challenge().getNonce().length())
                .isEqualTo(nonceGeneratorNonceBase64Length());
    }

    private int nonceGeneratorNonceBase64Length() {
        return (NONCE_LENGTH * 8 + 6 - 1) / 6 + 1;
    }

}
