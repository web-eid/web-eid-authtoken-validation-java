// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example;

import jakarta.servlet.Filter;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

@SpringBootTest(properties = {
    "web-eid-auth-token.csrf.use-spa-configuration=true",
    "web-eid-auth-token.csrf.cookie-domain=configured.example"
})
@WebAppConfiguration
class ConfiguredCookieDomainSpaCsrfConfigurationTest {

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private Filter[] springSecurityFilterChain;

    @Test
    void rootWhenCookieDomainIsConfiguredUsesConfiguredDomain() throws Exception {
        MockHttpServletResponse response = MockMvcBuilders.webAppContextSetup(context)
            .addFilters(springSecurityFilterChain)
            .build()
            .perform(get("/"))
            .andReturn()
            .getResponse();

        assertThat(response.getHeader(HttpHeaders.SET_COOKIE))
            .startsWith("WEBEID-XSRF-TOKEN=")
            .contains("Domain=configured.example");
    }
}
