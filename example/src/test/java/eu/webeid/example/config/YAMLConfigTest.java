package eu.webeid.example.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class YAMLConfigTest {

    @ValueSource(strings = {
        "http://localhost",
        "http://localhost:8080",
        "http://127.0.0.1",
        "http://127.0.0.1:8080",
        "http://::1",
        "http://[::1]:8080"
    })
    @ParameterizedTest
    void givenLocalOriginHttpLoopbackAddress_whenParsingLocalOrigin_thenItIsReplacedWithHttps(String origin) {
        YAMLConfig yamlConfig = new YAMLConfig();
        yamlConfig.setLocalOrigin(origin);
        assertThat(yamlConfig.getLocalOrigin()).isEqualTo(origin.replaceFirst("^http:", "https:"));
    }

    @ValueSource(strings = {
        "https://localhost",
        "https://localhost:8080",
        "https://127.0.0.1",
        "https://127.0.0.1:8080",
        "https://::1",
        "https://[::1]:8080",
    })
    @ParameterizedTest
    void givenLocalOriginHttpsLoopbackAddress_whenParsingLocalOrigin_thenOriginalIsKept(String origin) {
        YAMLConfig yamlConfig = new YAMLConfig();
        yamlConfig.setLocalOrigin(origin);
        assertThat(yamlConfig.getLocalOrigin()).isEqualTo(origin);
    }

    @ValueSource(strings = {
        "http://somename.app",
        "http://somename.app:8080",
        "http://8.8.8.8",
        "http://8.8.8.8:8080",
        "http://[2001:4860:4860::8888]",
        "http://[2001:4860:4860::8888]:8080",
    })
    @ParameterizedTest
    void givenLocalOriginHttpNonLoopbackAddress_whenParsingLocalOrigin_thenOriginalIsKept(String origin) {
        YAMLConfig yamlConfig = new YAMLConfig();
        yamlConfig.setLocalOrigin(origin);
        assertThat(yamlConfig.getLocalOrigin()).isEqualTo(origin);
    }

    @ValueSource(strings = {
        "https://localhost/",
        "https://localhost:8080/"
    })
    @ParameterizedTest
    void givenLocalOriginThatEndsWithSlash_whenParsingLocalOrigin_thenExceptionIsThrown(String origin) {
        YAMLConfig yamlConfig = new YAMLConfig();
        assertThatThrownBy(() -> yamlConfig.setLocalOrigin(origin))
            .hasMessage("Configuration parameter local-origin cannot end with '/': " + origin);
    }
}
