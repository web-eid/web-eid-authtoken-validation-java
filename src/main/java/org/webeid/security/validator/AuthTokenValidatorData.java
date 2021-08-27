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

package org.webeid.security.validator;

import java.security.cert.X509Certificate;

/**
 * Context data class used internally by validators.
 * <p>
 * Not part of public API.
 */
public final class AuthTokenValidatorData {

    private final X509Certificate subjectCertificate;
    private String nonce;
    private String origin;
    private String siteCertificateFingerprint;

    public AuthTokenValidatorData(X509Certificate subjectCertificate) {
        this.subjectCertificate = subjectCertificate;
    }

    public X509Certificate getSubjectCertificate() {
        return subjectCertificate;
    }

    public String getNonce() {
        return nonce;
    }

    void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getOrigin() {
        return origin;
    }

    void setOrigin(String origin) {
        this.origin = origin;
    }

    public String getSiteCertificateFingerprint() {
        return siteCertificateFingerprint;
    }

    public void setSiteCertificateFingerprint(String siteCertificateFingerprint) {
        this.siteCertificateFingerprint = siteCertificateFingerprint;
    }
}
