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

import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import static eu.webeid.security.util.DateAndTime.requirePositiveDuration;
import static java.util.Objects.requireNonNull;

public class OcspClientImpl implements OcspClient {

    private static final Logger LOG = LoggerFactory.getLogger(OcspClientImpl.class);
    private static final String OCSP_REQUEST_TYPE = "application/ocsp-request";
    private static final String OCSP_RESPONSE_TYPE = "application/ocsp-response";
    public static final String CONTENT_TYPE = "Content-Type";

    private final HttpClient httpClient;
    private final Duration ocspRequestTimeout;

    public static OcspClient build(Duration ocspRequestTimeout) {
        requirePositiveDuration(ocspRequestTimeout, "ocspRequestTimeout");
        return new OcspClientImpl(
            HttpClient.newBuilder()
                .connectTimeout(ocspRequestTimeout)
                .build(),
            ocspRequestTimeout);
    }

    /**
     * Use the built-in HttpClient to fetch the OCSP response from the OCSP responder service.
     *
     * @param uri     OCSP server URL
     * @param ocspReq OCSP request
     * @return OCSP response from the server
     * @throws IOException if the request could not be executed due to cancellation, a connectivity problem or timeout,
     *                     or if the response status is not successful, or if response has wrong content type.
     */
    @Override
    public OCSPResp request(URI uri, OCSPReq ocspReq) throws IOException {
        final HttpRequest request = HttpRequest.newBuilder()
            .uri(uri)
            .header(CONTENT_TYPE, OCSP_REQUEST_TYPE)
            .POST(HttpRequest.BodyPublishers.ofByteArray(ocspReq.getEncoded()))
            .timeout(ocspRequestTimeout)
            .build();

        final HttpResponse<byte[]> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while sending OCSP request", e);
        }

        if (response.statusCode() != 200) {
            throw new IOException("OCSP request was not successful, response: " + response);
        } else {
            LOG.debug("OCSP response: {}", response);
        }
        final String contentType = response.headers().firstValue(CONTENT_TYPE).orElse("");
        if (!contentType.startsWith(OCSP_RESPONSE_TYPE)) {
            throw new IOException("OCSP response content type is not " + OCSP_RESPONSE_TYPE);
        }
        return new OCSPResp(response.body());
    }

    public OcspClientImpl(HttpClient httpClient, Duration ocspRequestTimeout) {
        this.httpClient = requireNonNull(httpClient, "httpClient");
        this.ocspRequestTimeout = requirePositiveDuration(ocspRequestTimeout, "ocspRequestTimeout");
    }

}
