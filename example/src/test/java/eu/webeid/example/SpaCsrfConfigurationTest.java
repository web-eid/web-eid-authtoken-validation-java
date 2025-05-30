// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example;

import jakarta.servlet.Filter;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

@SpringBootTest(properties = "web-eid-auth-token.csrf.use-spa-configuration=true")
@WebAppConfiguration
class SpaCsrfConfigurationTest {

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private Filter[] springSecurityFilterChain;

    @Test
    void rootWhenSpaCsrfConfigurationIsEnabledWritesReadableXsrfTokenCookie() throws Exception {
        MockHttpServletResponse response = MockMvcBuilders.webAppContextSetup(context)
                .addFilters(springSecurityFilterChain)
                .build()
                .perform(get("/"))
                .andReturn()
                .getResponse();

        assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
        assertThat(response.getHeader(HttpHeaders.SET_COOKIE))
                .startsWith("WEBEID-XSRF-TOKEN=")
                .containsPattern("WEBEID-XSRF-TOKEN=[^;]+")
                .contains("Path=/")
                .contains("Domain=ria.ee")
                .doesNotContain("HttpOnly");
        assertThat(response.getContentAsString())
                .doesNotContain("id=\"csrftoken\"")
                .doesNotContain("id=\"csrfheadername\"");
    }
}
