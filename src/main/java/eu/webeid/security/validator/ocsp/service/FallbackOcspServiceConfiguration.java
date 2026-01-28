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

import eu.webeid.security.exceptions.OCSPCertificateException;
import eu.webeid.security.validator.ocsp.OcspResponseValidator;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.Objects;

public class FallbackOcspServiceConfiguration {

    private final URI ocspServiceAccessLocation;
    private final URI fallbackOcspServiceAccessLocation;
    private final X509Certificate responderCertificate;
    private final boolean doesSupportNonce;

    public FallbackOcspServiceConfiguration(URI ocspServiceAccessLocation, URI fallbackOcspServiceAccessLocation, X509Certificate responderCertificate, boolean doesSupportNonce) throws OCSPCertificateException {
        this.ocspServiceAccessLocation = Objects.requireNonNull(ocspServiceAccessLocation, "Primary OCSP service access location");
        this.fallbackOcspServiceAccessLocation = Objects.requireNonNull(fallbackOcspServiceAccessLocation, "Fallback OCSP service access location");
        this.responderCertificate = Objects.requireNonNull(responderCertificate, "Fallback OCSP responder certificate");
        OcspResponseValidator.validateHasSigningExtension(responderCertificate);
        this.doesSupportNonce = doesSupportNonce;
    }

    public URI getOcspServiceAccessLocation() {
        return ocspServiceAccessLocation;
    }

    public URI getFallbackOcspServiceAccessLocation() {
        return fallbackOcspServiceAccessLocation;
    }

    public X509Certificate getResponderCertificate() {
        return responderCertificate;
    }

    public boolean doesSupportNonce() {
        return doesSupportNonce;
    }

}
