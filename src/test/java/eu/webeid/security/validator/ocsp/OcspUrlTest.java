/*
 * Copyright (c) 2020-2021 Estonian Information System Authority
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

package eu.webeid.security.validator.ocsp;

import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static eu.webeid.security.validator.ocsp.OcspUrl.getOcspUri;

class OcspUrlTest {

    @Test
    void whenExtensionValueIsNull_thenReturnsNull() {
        final X509Certificate mockCertificate = mock(X509Certificate.class);
        when(mockCertificate.getExtensionValue(anyString())).thenReturn(null);
        assertThat(getOcspUri(mockCertificate)).isNull();
    }

    @Test
    void whenExtensionValueIsInvalid_thenReturnsNull() {
        final X509Certificate mockCertificate = mock(X509Certificate.class);
        when(mockCertificate.getExtensionValue(anyString())).thenReturn(new byte[]{1, 2, 3});
        assertThat(getOcspUri(mockCertificate)).isNull();
    }

    @Test
    void whenExtensionValueIsNotAia_thenReturnsNull() {
        final X509Certificate mockCertificate = mock(X509Certificate.class);
        when(mockCertificate.getExtensionValue(anyString())).thenReturn(new byte[]{
            4, 64, 48, 62, 48, 50, 6, 11, 43, 6, 1, 4, 1, -125, -111, 33, 1, 2, 1, 48,
            35, 48, 33, 6, 8, 43, 6, 1, 5, 5, 7, 2, 1, 22, 21, 104, 116, 116, 112, 115,
            58, 47, 47, 119, 119, 119, 46, 115, 107, 46, 101, 101, 47, 67, 80, 83, 48,
            8, 6, 6, 4, 0, -113, 122, 1, 2});
        assertThat(getOcspUri(mockCertificate)).isNull();
    }

}
