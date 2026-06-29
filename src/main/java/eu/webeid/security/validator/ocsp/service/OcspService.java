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

package eu.webeid.security.validator.ocsp.service;

import eu.webeid.security.exceptions.AuthTokenException;
import org.bouncycastle.cert.X509CertificateHolder;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

public interface OcspService {

    boolean doesSupportNonce();

    URI getAccessLocation();

    /**
     * Validates that the OCSP responder certificate is trusted.
     *
     * @param cert the responder certificate from the OCSP response
     * @param additionalIntermediateCertificates untrusted, token-supplied intermediate certificates that may be needed
     *     to build the responder's certification path to a trusted CA; may be empty
     * @param now validation date
     */
    void validateResponderCertificate(X509CertificateHolder cert,
                                      List<X509Certificate> additionalIntermediateCertificates,
                                      Date now) throws AuthTokenException;

}
