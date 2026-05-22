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

package eu.webeid.ocsp.client;

import eu.webeid.ocsp.exceptions.OCSPClientException;
import eu.webeid.security.testutil.ResourceUtil;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Flow;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OcspClientImplTest {

    private static final URI OCSP_URI = URI.create("http://ocsp.test/");
    private static final Duration TIMEOUT = Duration.ofSeconds(5);

    @Test
    void whenHttpResponseStatusIsNot200_thenThrowsWithStatusCodeAndBody() throws Exception {
        byte[] body = "not-found".getBytes();
        HttpClient httpClient = mockHttpClient(mockResponse(404, body, "text/plain"));
        OcspClientImpl client = new OcspClientImpl(httpClient, TIMEOUT);

        assertThatExceptionOfType(OCSPClientException.class)
            .isThrownBy(() -> client.request(OCSP_URI, encodableOcspReq()))
            .withMessageStartingWith("OCSP request was not successful")
            .satisfies(ex -> {
                assertThat(ex.getStatusCode()).isEqualTo(404);
                assertThat(ex.getResponseBody()).isEqualTo(body);
            });
    }

    @Test
    void whenContentTypeIsNotOcspResponse_thenThrows() throws Exception {
        HttpClient httpClient = mockHttpClient(mockResponse(200, new byte[]{0x01}, "text/html"));
        OcspClientImpl client = new OcspClientImpl(httpClient, TIMEOUT);

        assertThatExceptionOfType(OCSPClientException.class)
            .isThrownBy(() -> client.request(OCSP_URI, encodableOcspReq()))
            .withMessage("OCSP response content type is not application/ocsp-response");
    }

    @Test
    void whenHttpClientThrowsInterruptedException_thenRestoresInterruptFlagAndThrows() throws Exception {
        HttpClient httpClient = mock(HttpClient.class);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenThrow(new InterruptedException("interrupted"));
        OcspClientImpl client = new OcspClientImpl(httpClient, TIMEOUT);

        try {
            assertThatExceptionOfType(OCSPClientException.class)
                .isThrownBy(() -> client.request(OCSP_URI, encodableOcspReq()))
                .withMessage("Interrupted while sending OCSP request")
                .withCauseInstanceOf(InterruptedException.class);
        } finally {
            // Always clear so a failing assertion above doesn't leak the interrupt flag to other tests.
            assertThat(Thread.interrupted()).as("interrupt flag must be set by InterruptedException handling").isTrue();
        }
    }

    @Test
    void whenHttpClientThrowsIOException_thenThrows() throws Exception {
        HttpClient httpClient = mock(HttpClient.class);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenThrow(new IOException("network down"));
        OcspClientImpl client = new OcspClientImpl(httpClient, TIMEOUT);

        assertThatExceptionOfType(OCSPClientException.class)
            .isThrownBy(() -> client.request(OCSP_URI, encodableOcspReq()))
            .withCauseInstanceOf(IOException.class);
    }

    @Test
    void whenOcspReqGetEncodedThrowsIOException_thenThrows() throws Exception {
        OCSPReq ocspReq = mock(OCSPReq.class);
        when(ocspReq.getEncoded()).thenThrow(new IOException("encoding failed"));
        OcspClientImpl client = new OcspClientImpl(mock(HttpClient.class), TIMEOUT);

        assertThatExceptionOfType(OCSPClientException.class)
            .isThrownBy(() -> client.request(OCSP_URI, ocspReq))
            .withCauseInstanceOf(IOException.class);
    }

    @Test
    void whenResponseBodyIsInvalidOcsp_thenThrowsWithIoExceptionCause() throws Exception {
        HttpClient httpClient = mockHttpClient(mockResponse(200, "not-an-ocsp-response".getBytes(), "application/ocsp-response"));
        OcspClientImpl client = new OcspClientImpl(httpClient, TIMEOUT);

        assertThatExceptionOfType(OCSPClientException.class)
            .isThrownBy(() -> client.request(OCSP_URI, encodableOcspReq()))
            .withCauseInstanceOf(IOException.class);
    }

    @Test
    void whenRequestIsSent_thenOcspRequestIsPostedWithCorrectUriHeaderAndBody() throws Exception {
        byte[] responseBody = ResourceUtil.bytesFromResource("ocsp_response.der");
        HttpClient httpClient = mockHttpClient(mockResponse(200, responseBody, "application/ocsp-response"));
        OcspClientImpl client = new OcspClientImpl(httpClient, TIMEOUT);
        OCSPReq ocspReq = encodableOcspReq();

        client.request(OCSP_URI, ocspReq);

        ArgumentCaptor<HttpRequest> requestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(httpClient).send(requestCaptor.capture(), any(HttpResponse.BodyHandler.class));
        HttpRequest request = requestCaptor.getValue();

        assertThat(request.uri()).isEqualTo(OCSP_URI);
        assertThat(request.method()).isEqualTo("POST");
        assertThat(request.headers().firstValue("Content-Type")).contains("application/ocsp-request");
        assertThat(request.bodyPublisher()).isPresent();
        assertThat(request.bodyPublisher().get().contentLength()).isEqualTo(ocspReq.getEncoded().length);
        assertThat(readBodyPublisher(request.bodyPublisher().get())).isEqualTo(ocspReq.getEncoded());
    }

    @Test
    void whenResponseIsValidOcsp_thenReturnsParsedOcspResp() throws Exception {
        byte[] responseBody = ResourceUtil.bytesFromResource("ocsp_response.der");
        HttpClient httpClient = mockHttpClient(mockResponse(200, responseBody, "application/ocsp-response"));
        OcspClientImpl client = new OcspClientImpl(httpClient, TIMEOUT);

        OCSPResp ocspResp = client.request(OCSP_URI, encodableOcspReq());

        assertThat(ocspResp).isNotNull();
        assertThat(ocspResp.getStatus()).isEqualTo(OCSPResp.SUCCESSFUL);
    }

    @Test
    void whenHttpClientIsNull_thenThrows() {
        assertThatExceptionOfType(NullPointerException.class)
            .isThrownBy(() -> new OcspClientImpl(null, TIMEOUT));
    }

    @SuppressWarnings("unchecked")
    private static HttpClient mockHttpClient(HttpResponse<byte[]> response) throws Exception {
        HttpClient httpClient = mock(HttpClient.class);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(response);
        return httpClient;
    }

    @SuppressWarnings("unchecked")
    private static HttpResponse<byte[]> mockResponse(int statusCode, byte[] body, String contentType) {
        HttpResponse<byte[]> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(statusCode);
        when(response.body()).thenReturn(body);
        HttpHeaders headers = HttpHeaders.of(Map.of("Content-Type", List.of(contentType)), (k, v) -> true);
        when(response.headers()).thenReturn(headers);
        return response;
    }

    private static OCSPReq encodableOcspReq() throws IOException {
        OCSPReq ocspReq = mock(OCSPReq.class);
        when(ocspReq.getEncoded()).thenReturn(new byte[]{0x30, 0x00});
        return ocspReq;
    }

    private static byte[] readBodyPublisher(HttpRequest.BodyPublisher bodyPublisher) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        CompletableFuture<byte[]> result = new CompletableFuture<>();

        bodyPublisher.subscribe(new Flow.Subscriber<>() {
            @Override
            public void onSubscribe(Flow.Subscription subscription) {
                subscription.request(Long.MAX_VALUE);
            }

            @Override
            public void onNext(ByteBuffer item) {
                byte[] chunk = new byte[item.remaining()];
                item.get(chunk);
                output.write(chunk, 0, chunk.length);
            }

            @Override
            public void onError(Throwable throwable) {
                result.completeExceptionally(throwable);
            }

            @Override
            public void onComplete() {
                result.complete(output.toByteArray());
            }
        });

        return result.join();
    }
}
