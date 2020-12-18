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

import com.google.common.base.Strings;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.webeid.security.exceptions.TokenExpiredException;
import org.webeid.security.exceptions.TokenParseException;
import org.webeid.security.exceptions.TokenSignatureValidationException;
import org.webeid.security.exceptions.TokenValidationException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Parses the Web eID authentication token using the JJWT library.
 */
final class AuthTokenParser {

    private static final Logger LOG = LoggerFactory.getLogger(AuthTokenParser.class);

    private final String authToken;
    private final JwtParser parser;
    private X509Certificate subjectCertificate;
    private Claims body;

    /**
     * @param authToken        the Web eID authentication token with signature
     * @param allowedClockSkew the tolerated client computer clock skew when verifying the token {@code exp} field
     */
    AuthTokenParser(String authToken, Duration allowedClockSkew) {
        this.authToken = authToken;
        this.parser = Jwts.parserBuilder()
            .setSigningKeyResolver(new X5cFieldPublicKeyResolver())
            .setAllowedClockSkewSeconds(allowedClockSkew.getSeconds())
            .build();
    }

    /**
     * Parses the header part of the token.
     *
     * @return {@link AuthTokenValidatorData} object with token header data filled in
     * @throws TokenParseException when header parsing fails or header fields are missing or invalid
     */
    AuthTokenValidatorData parseHeaderFromTokenString() throws TokenParseException {
        try {
            int headerPos = authToken.indexOf(".");
            @SuppressWarnings("rawtypes") final Jwt headerJwt = parser.parse(authToken.substring(0, headerPos + 1) + ".");

            LOG.trace("JWT header: {}", headerJwt);

            @SuppressWarnings("rawtypes") final Header header = headerJwt.getHeader();

            @SuppressWarnings({"rawtypes", "unchecked"}) final List subjectCertificateList = getListFieldOrThrow(header, "x5c", "header");
            final String subjectCertificateField = (String) subjectCertificateList.get(0);
            if (Strings.isNullOrEmpty(subjectCertificateField)) {
                throw new TokenParseException("Certificate from x5c field must not be empty");
            }
            @SuppressWarnings("unchecked") final String signatureAlgorithm = getStringFieldOrThrow(header, "alg", "header");

            subjectCertificate = parseCertificate(subjectCertificateField);
            LOG.trace("Subject certificate: {}", subjectCertificateField);

            // Validate signature algorithm name
            SignatureAlgorithm.forName(signatureAlgorithm);

            return new AuthTokenValidatorData(subjectCertificate);
        } catch (TokenParseException e) {
            throw e;
        } catch (Exception e) {
            throw new TokenParseException(e);
        }
    }

    /**
     * Parses the body part of the token and validates token signature.
     *
     * @throws TokenValidationException when body parsing fails or signature is invalid
     */
    void validateTokenSignatureAndParseClaims() throws TokenValidationException {
        try {
            final Jws<Claims> claimsJws = parser.parseClaimsJws(authToken);
            body = claimsJws.getBody();
            LOG.trace("JWT body: {}", body);

        } catch (ExpiredJwtException e) {
            throw new TokenExpiredException(e);
        } catch (SecurityException | UnsupportedJwtException e) {
            throw new TokenSignatureValidationException(e);
        } catch (JwtException e) {
            throw new TokenParseException(e);
        }
    }

    /**
     * Populates data from the body part of the token into the provided {@link AuthTokenValidatorData} object.
     *
     * @param data {@link AuthTokenValidatorData} object that will be filled with body data
     * @throws TokenParseException when body fields are missing or invalid
     */
    void populateDataFromClaims(AuthTokenValidatorData data) throws TokenParseException {
        try {
            final String nonceField = getStringFieldOrThrow(body, "nonce", "body");

            // The "aud" field value is an array that contains the origin and may also contain site certificate fingerprint
            final List audienceField = getListFieldOrThrow(body, "aud", "body");
            final String origin = (String) audienceField.get(0);
            if (Strings.isNullOrEmpty(origin)) {
                throw new TokenParseException("origin from aud field must not be empty");
            }

            data.setNonce(nonceField);
            data.setOrigin(origin);

            if (audienceField.size() > 1) {
                final String siteCertificateFingerprintField = (String) audienceField.get(1);
                if (Strings.isNullOrEmpty(siteCertificateFingerprintField)
                    || !siteCertificateFingerprintField.startsWith("urn:cert:sha-256:")) {
                    throw new TokenParseException("site certificate fingerprint from aud field must start with urn:cert:sha-256:");
                }
                data.setSiteCertificateFingerprint(siteCertificateFingerprintField);
            }
        } catch (TokenParseException e) {
            throw e;
        } catch (Exception e) {
            throw new TokenParseException(e);
        }
    }

    private class X5cFieldPublicKeyResolver implements SigningKeyResolver {
        @Override
        public Key resolveSigningKey(JwsHeader jwsHeader, Claims claims) {
            return subjectCertificate.getPublicKey();
        }

        @Override
        public Key resolveSigningKey(JwsHeader jwsHeader, String s) {
            throw new UnsupportedOperationException("Not implemented");
        }
    }

    private String getStringFieldOrThrow(Map<String, Object> fields, String fieldName, String sectionName) throws TokenParseException {
        final String fieldValue = (String) fields.get(fieldName);
        if (Strings.isNullOrEmpty(fieldValue)) {
            throw new TokenParseException(fieldName + " field must be present and not empty in authentication token " + sectionName);
        }
        return fieldValue;
    }

    private List getListFieldOrThrow(Map<String, Object> fields, String fieldName, String sectionName) throws TokenParseException {
        if (fields.get(fieldName) != null && !(fields.get(fieldName) instanceof List)) {
            throw new TokenParseException(fieldName + " field in authentication token "
                + sectionName + " must be an array");
        }

        final List fieldValue = (List) fields.get(fieldName);
        if (fieldValue == null) {
            throw new TokenParseException(fieldName + " field must be present in authentication token "
                + sectionName + " and must be an array");
        }
        if (fieldValue.isEmpty()) {
            throw new TokenParseException(fieldName + " field must not be empty in authentication token " + sectionName);
        }
        if (!(fieldValue.get(0) instanceof String)) {
            throw new TokenParseException(fieldName + " field in authentication token "
                + sectionName + " must be an array of strings, but first element is not a string");
        }

        return fieldValue;
    }

    private static X509Certificate parseCertificate(String certificateInBase64) throws CertificateException, IOException, TokenParseException {
        try {
            byte[] certificateBytes = Base64.getDecoder().decode(certificateInBase64);
            try (InputStream inStream = new ByteArrayInputStream(certificateBytes)) {
                final CertificateFactory cf = CertificateFactory.getInstance("X.509");
                return (X509Certificate) cf.generateCertificate(inStream);
            }
        } catch (IllegalArgumentException e) {
            throw new TokenParseException("x5c field must contain a valid certificate");
        }
    }
}
