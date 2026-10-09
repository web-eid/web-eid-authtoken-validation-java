// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class CookieDomainResolverTest {

    @Test
    void givenLocalOrigin_whenParsingLocalOriginToGetCookieDomain_thenApexDomainIsParsedCorrectly() {
        assertThat(CookieDomainResolver.toApexDomain("https://www.id.ee")).isEqualTo("id.ee");
        assertThat(CookieDomainResolver.toApexDomain("https://id.ee")).isEqualTo("id.ee");
        assertThat(CookieDomainResolver.toApexDomain("https://www.id.ee:8443")).isEqualTo("id.ee");
    }
}
