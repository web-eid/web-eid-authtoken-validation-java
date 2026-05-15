package eu.webeid.example.config;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.servlet.ServletContext;
import jakarta.servlet.SessionCookieConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {"web-eid-auth-token.validation.local-origin=https://localhost"})
class CookieHttpsTest {

    @Autowired
    private ServletWebServerApplicationContext context;

    @Test
    void whenLocalOriginStartsWithHttp_thenCookeDoesNotHaveHostPrefix() {
        ServletContext servletContext = context.getServletContext();
        SessionCookieConfig cookieConfig = servletContext.getSessionCookieConfig();
        assertThat(cookieConfig.getName()).isEqualTo("__Host-JSESSIONID");
    }

}
