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

import org.webeid.security.exceptions.TokenValidationException;
import org.webeid.security.util.CertUtil;
import org.webeid.security.util.TitleCase;

import java.security.cert.X509Certificate;

/**
 * Validates the provided Web eID authentication token.
 */
public interface AuthTokenValidator {

    /**
     * Validates the Web eID authentication token signed by the subject and returns
     * the subject certificate that can be used for retrieving information about the subject.
     * <p>
     * See {@link CertUtil} and {@link TitleCase} for convenience methods for retrieving user
     * information from the certificate.
     *
     * @param tokenWithSignature the Web eID authentication token, in OpenID X509 ID Token format, with signature
     * @return validated subject certificate
     * @throws TokenValidationException when validation fails
     */
    X509Certificate validate(String tokenWithSignature) throws TokenValidationException;
}
