/*
 * Copyright (c) 2020 The Web eID Project
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

/*
 * Copyright 2017 The Netty Project
 * Copyright 2020 The Web eID project
 *
 * The Netty Project and The Web eID Project license this file to you under the
 * Apache License, version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package org.webeid.security.validator.ocsp;

import okhttp3.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Objects;

public final class OcspUtils {

    private static final Logger LOG = LoggerFactory.getLogger(OcspUtils.class);

    /**
     * The OID for OCSP responder URLs.
     * <p>
     * http://www.alvestrand.no/objectid/1.3.6.1.5.5.7.48.1.html
     */
    private static final ASN1ObjectIdentifier OCSP_RESPONDER_OID
        = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1").intern();

    private static final MediaType OCSP_REQUEST_TYPE = MediaType.get("application/ocsp-request");
    private static final MediaType OCSP_RESPONSE_TYPE = MediaType.get("application/ocsp-response");

    private OcspUtils() {
    }

    /**
     * Returns the OCSP responder {@link URI} or {@code null} if it doesn't have one.
     */
    public static URI ocspUri(X509Certificate certificate) throws IOException {
        final byte[] value = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (value == null) {
            return null;
        }

        final ASN1Primitive authorityInfoAccess = JcaX509ExtensionUtils.parseExtensionValue(value);
        if (!(authorityInfoAccess instanceof DLSequence)) {
            return null;
        }

        final DLSequence aiaSequence = (DLSequence) authorityInfoAccess;
        final DLTaggedObject taggedObject = findObject(aiaSequence, OCSP_RESPONDER_OID, DLTaggedObject.class);
        if (taggedObject == null) {
            return null;
        }

        if (taggedObject.getTagNo() != BERTags.OBJECT_IDENTIFIER) {
            return null;
        }

        final byte[] encoded = taggedObject.getEncoded();
        int length = (int) encoded[1] & 0xFF;
        final String uri = new String(encoded, 2, length, StandardCharsets.UTF_8);
        return URI.create(uri);
    }

    private static <T> T findObject(DLSequence sequence, ASN1ObjectIdentifier oid, Class<T> type) {
        for (final ASN1Encodable element : sequence) {
            if (!(element instanceof DLSequence)) {
                continue;
            }

            final DLSequence subSequence = (DLSequence) element;
            if (subSequence.size() != 2) {
                continue;
            }

            final ASN1Encodable key = subSequence.getObjectAt(0);
            final ASN1Encodable value = subSequence.getObjectAt(1);

            if (key.equals(oid) && type.isInstance(value)) {
                return type.cast(value);
            }
        }

        return null;
    }

    /**
     * Use OkHttpClient to fetch the OCSP response from the CA's OCSP responder server.
     *
     * @param uri        OCSP server URL
     * @param ocspReq    OCSP request
     * @param httpClient OkHttpClient instance
     * @return OCSP response from the server
     * @throws IOException if the request could not be executed due to cancellation, a connectivity problem or timeout,
     *                     or if the response status is not successful, or if response has wrong content type.
     */
    public static OCSPResp request(URI uri, OCSPReq ocspReq, OkHttpClient httpClient) throws IOException {
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
            try (final ResponseBody responseBody = Objects.requireNonNull(response.body())) {
                if (!OCSP_RESPONSE_TYPE.equals(responseBody.contentType())) {
                    throw new IOException("OCSP response content type is not " + OCSP_RESPONSE_TYPE);
                }
                return new OCSPResp(responseBody.bytes());
            }
        }
    }

}
