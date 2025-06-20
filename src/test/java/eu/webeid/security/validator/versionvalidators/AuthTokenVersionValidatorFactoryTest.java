/*
 * Copyright (c) 2020-2025 Estonian Information System Authority
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package eu.webeid.security.validator.versionvalidators;

import eu.webeid.security.exceptions.AuthTokenParseException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthTokenVersionValidatorFactoryTest {

    @Test
    void whenValidatorSupportsFormat_thenSupportsReturnsTrue() {
        AuthTokenVersionValidator v11 = mock(AuthTokenVersionValidator.class);
        when(v11.supports("web-eid:1.1")).thenReturn(true);

        AuthTokenVersionValidatorFactory factory = new AuthTokenVersionValidatorFactory(List.of(v11));

        assertThat(factory.supports("web-eid:1.1")).isTrue();
    }

    @Test
    void whenValidatorDoesNotSupportFormat_thenSupportsReturnsFalse() {
        AuthTokenVersionValidator v11 = mock(AuthTokenVersionValidator.class);
        when(v11.supports("web-eid:1.1")).thenReturn(false);

        AuthTokenVersionValidatorFactory factory = new AuthTokenVersionValidatorFactory(List.of(v11));

        assertThat(factory.supports("web-eid:2")).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"web-eid:0.9", "web-eid:2", "foo", "1", "web-eid"})
    void whenUnsupportedFormat_thenGetValidatorForThrows(String format) {
        AuthTokenVersionValidatorFactory factory = new AuthTokenVersionValidatorFactory(List.of());
        assertThatThrownBy(() -> factory.getValidatorFor(format))
            .isInstanceOf(AuthTokenParseException.class)
            .hasMessage("Token format version '" + format + "' is currently not supported");
    }

    @Test
    void whenMultipleValidatorsAndFirstIsV11_thenGetValidatorForReturnsV11() throws AuthTokenParseException {
        AuthTokenVersionValidator v11 = mock(AuthTokenVersionValidator.class);
        when(v11.supports("web-eid:1.1")).thenReturn(true);

        AuthTokenVersionValidator v1 = mock(AuthTokenVersionValidator.class);
        when(v1.supports("web-eid:1")).thenReturn(true);

        AuthTokenVersionValidatorFactory factory = new AuthTokenVersionValidatorFactory(List.of(v11, v1));

        AuthTokenVersionValidator chosen = factory.getValidatorFor("web-eid:1.1");

        assertThat(chosen).isSameAs(v11);
    }

    @Test
    void whenFormatIsBaseV1_thenGetValidatorForReturnsV1() throws AuthTokenParseException {
        AuthTokenVersionValidator v11 = mock(AuthTokenVersionValidator.class);
        when(v11.supports("web-eid:1.1")).thenReturn(true);

        AuthTokenVersionValidator v1 = mock(AuthTokenVersionValidator.class);
        when(v1.supports("web-eid:1")).thenReturn(true);

        AuthTokenVersionValidatorFactory factory = new AuthTokenVersionValidatorFactory(List.of(v11, v1));

        AuthTokenVersionValidator chosen = factory.getValidatorFor("web-eid:1");

        assertThat(chosen).isSameAs(v1);
    }
}
