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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

class AuthTokenVersionTest {

    @ParameterizedTest
    @CsvSource({
        "web-eid:1,     1, 0, true",
        "web-eid:1.0,   1, 0, true",
        "web-eid:1.1,   1, 0, true",
        "web-eid:1.1,   1, 1, true",
        "web-eid:1.999, 1, 1, true",
        "web-eid:2.0,   2, 0, true",
        "web-eid:2.3,   2, 1, true",
        "web-eid:1.0,   1, 1, false",
        "web-eid:1,     1, 1, false",
        "web-eid:2,     1, 0, false",
        "web-eid:1.5,   2, 0, false",
        "web-eid:1.00,  1, 0, false",
        "web-eid:1.000, 1, 0, false",
        "web-eid:01,    1, 0, false",
        "web-eid:1.,    1, 0, false",
        "web-eid:1.1.0, 1, 0, false",
        "web-eid:0.9,   1, 0, false",
        "webauthn:1,    1, 0, false"
    })
    void whenFormatMatchesRequiredMajorAndAtLeastRequiredMinor_thenSupportsReturnsExpected(
        String format, int requiredMajorVersion, int requiredMinorVersion, boolean expected) {
        assertThat(AuthTokenVersion.supports(format, requiredMajorVersion, requiredMinorVersion)).isEqualTo(expected);
    }

    @Test
    void whenFormatIsNull_thenSupportsReturnsFalse() {
        assertThat(AuthTokenVersion.supports(null, 1, 0)).isFalse();
    }

    @ParameterizedTest
    @CsvSource({
        "web-eid:1,     1, 0, true",
        "web-eid:1.0,   1, 0, true",
        "web-eid:1.1,   1, 1, true",
        "web-eid:2.0,   2, 0, true",
        "web-eid:1.1,   1, 0, false",
        "web-eid:1.2,   1, 1, false",
        "web-eid:1.0,   1, 1, false",
        "web-eid:1,     2, 0, false",
        "web-eid:1.00,  1, 0, false",
        "web-eid:01,    1, 0, false",
        "webauthn:1,    1, 0, false"
    })
    void whenFormatMatchesRequiredMajorAndExactMinor_thenSupportsExactlyReturnsExpected(
        String format, int requiredMajorVersion, int requiredMinorVersion, boolean expected) {
        assertThat(AuthTokenVersion.supportsExactly(format, requiredMajorVersion, requiredMinorVersion)).isEqualTo(expected);
    }

    @Test
    void whenFormatIsNull_thenSupportsExactlyReturnsFalse() {
        assertThat(AuthTokenVersion.supportsExactly(null, 1, 0)).isFalse();
    }
}
