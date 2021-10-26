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

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.Objects;

public class OcspClientImpl implements OcspClient {

    private static final Logger LOG = LoggerFactory.getLogger(OcspClientImpl.class);
    private static final MediaType OCSP_REQUEST_TYPE = MediaType.get("application/ocsp-request");
    private static final MediaType OCSP_RESPONSE_TYPE = MediaType.get("application/ocsp-response");

    private final OkHttpClient httpClient;

    public static OcspClient build(Duration ocspRequestTimeout) {
        return new OcspClientImpl(
            new OkHttpClient.Builder()
                .connectTimeout(ocspRequestTimeout)
                .callTimeout(ocspRequestTimeout)
                .build()
        );
    }

    /**
     * Use OkHttpClient to fetch the OCSP response from the OCSP responder service.
     *
     * @param uri        OCSP server URL
     * @param ocspReq    OCSP request
     * @return OCSP response from the server
     * @throws IOException if the request could not be executed due to cancellation, a connectivity problem or timeout,
     *                     or if the response status is not successful, or if response has wrong content type.
     */
    @Override
    public OCSPResp request(URI uri, OCSPReq ocspReq) throws IOException {
        final RequestBody requestBody = RequestBody.create(ocspReq.getEncoded(), OCSP_REQUEST_TYPE);
        final Request request = new Request.Builder()
            .url(uri.toURL())
            .post(requestBody)
            .build();

        try (final Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("OCSP request was not successful, response: " + response);
            } else {
                LOG.debug("OCSP response: {}", response);
            }
            try (final ResponseBody responseBody = Objects.requireNonNull(response.body(), "response body")) {
                Objects.requireNonNull(responseBody.contentType(), "response content type");
                if (!OCSP_RESPONSE_TYPE.type().equals(responseBody.contentType().type()) ||
                    !OCSP_RESPONSE_TYPE.subtype().equals(responseBody.contentType().subtype())) {
                    throw new IOException("OCSP response content type is not " + OCSP_RESPONSE_TYPE);
                }
                return new OCSPResp(responseBody.bytes());
            }
        }
    }

    private OcspClientImpl(OkHttpClient httpClient) {
        this.httpClient = httpClient;
    }

}
