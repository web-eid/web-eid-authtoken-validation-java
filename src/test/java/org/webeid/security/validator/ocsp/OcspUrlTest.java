package org.webeid.security.validator.ocsp;

import org.bouncycastle.asn1.x509.Extension;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.webeid.security.validator.ocsp.OcspUrl.getOcspUri;

class OcspUrlTest {

    @Test
    void whenExtensionValueIsNull_thenReturnsNull() throws Exception {
        final X509Certificate mockCertificate = mock(X509Certificate.class);
        when(mockCertificate.getExtensionValue(anyString())).thenReturn(null);
        assertThat(getOcspUri(mockCertificate)).isNull();
    }

    @Test
    void whenExtensionValueIsInvalid_thenReturnsNull() throws Exception {
        final X509Certificate mockCertificate = mock(X509Certificate.class);
        when(mockCertificate.getExtensionValue(anyString())).thenReturn(new byte[]{1, 2, 3});
        assertThat(getOcspUri(mockCertificate)).isNull();
    }

    @Test
    void whenExtensionValueIsNotAia_thenReturnsNull() throws Exception {
        final X509Certificate mockCertificate = mock(X509Certificate.class);
        when(mockCertificate.getExtensionValue(anyString())).thenReturn(new byte[]{
            4, 64, 48, 62, 48, 50, 6, 11, 43, 6, 1, 4, 1, -125, -111, 33, 1, 2, 1, 48,
            35, 48, 33, 6, 8, 43, 6, 1, 5, 5, 7, 2, 1, 22, 21, 104, 116, 116, 112, 115,
            58, 47, 47, 119, 119, 119, 46, 115, 107, 46, 101, 101, 47, 67, 80, 83, 48,
            8, 6, 6, 4, 0, -113, 122, 1, 2});
        assertThat(getOcspUri(mockCertificate)).isNull();
    }

}
