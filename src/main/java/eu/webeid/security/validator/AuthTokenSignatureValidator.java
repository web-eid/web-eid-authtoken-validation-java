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
package eu.webeid.security.validator;

import com.google.common.base.Strings;
import com.google.common.primitives.Bytes;
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.exceptions.AuthTokenParseException;
import eu.webeid.security.exceptions.AuthTokenSignatureValidationException;
import eu.webeid.security.exceptions.ChallengeNullOrEmptyException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.DefaultSignatureValidatorFactory;
import io.jsonwebtoken.impl.crypto.SignatureValidator;
import io.jsonwebtoken.security.SignatureException;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import static eu.webeid.security.util.Base64Decoder.decodeBase64;

public class AuthTokenSignatureValidator {

    // Supported subset of JSON Web Signature algorithms as defined in RFC 7518, sections 3.3, 3.4, 3.5.
    // See https://github.com/web-eid/libelectronic-id/blob/main/include/electronic-id/enums.hpp#L176.
    private static final Set<String> ALLOWED_SIGNATURE_ALGORITHMS = new HashSet<>(Arrays.asList(
        "ES256", "ES384", "ES512", // ECDSA
        "PS256", "PS384", "PS512", // RSASSA-PSS
        "RS256", "RS384", "RS512"  // RSASSA-PKCS1-v1_5
    ));

    private final byte[] originBytes;

    public AuthTokenSignatureValidator(URI siteOrigin) {
        this.originBytes = siteOrigin.toString().getBytes(StandardCharsets.UTF_8);
    }

    // This method is based on the relevant subset of JJWT's DefaultJwtParser.parse().
    public void validate(String algorithm, String signature, PublicKey publicKey, String currentChallengeNonce) throws AuthTokenException {
        requireNotEmpty(algorithm, "algorithm");
        requireNotEmpty(signature, "signature");
        Objects.requireNonNull(publicKey);
        if (Strings.isNullOrEmpty(currentChallengeNonce)) {
            throw new ChallengeNullOrEmptyException();
        }

        if (!ALLOWED_SIGNATURE_ALGORITHMS.contains(algorithm)) {
            throw new AuthTokenParseException("Unsupported signature algorithm");
        }

        SignatureAlgorithm signatureAlgorithm;
        MessageDigest hashAlgorithm;
        try {
            signatureAlgorithm = SignatureAlgorithm.forName(algorithm);
            hashAlgorithm = hashAlgorithmForName(algorithm);
        } catch (SignatureException e) {
            // Should not happen, see ALLOWED_SIGNATURE_ALGORITHMS check above.
            throw new AuthTokenParseException("Invalid signature algorithm", e);
        } catch (NoSuchAlgorithmException e) {
            throw new AuthTokenParseException("Invalid hash algorithm", e);
        }
        if (signatureAlgorithm == null || signatureAlgorithm == SignatureAlgorithm.NONE) {
            // Should not happen, see ALLOWED_SIGNATURE_ALGORITHMS check above.
            throw new AuthTokenParseException("Invalid signature algorithm");
        }
        Objects.requireNonNull(hashAlgorithm, "hashAlgorithm");
        signatureAlgorithm.assertValidVerificationKey(publicKey);
        final SignatureValidator signatureValidator = DefaultSignatureValidatorFactory.INSTANCE
            .createSignatureValidator(signatureAlgorithm, publicKey);
        final byte[] decodedSignature = decodeBase64(signature);

        final byte[] originHash = hashAlgorithm.digest(originBytes);
        final byte[] nonceHash = hashAlgorithm.digest(currentChallengeNonce.getBytes(StandardCharsets.UTF_8));
        final byte[] concatSignedFields = Bytes.concat(originHash, nonceHash);

        // Note that in case of ECDSA, the eID card outputs raw R||S, but JCA's SHA384withECDSA signature
        // validation implementation requires the signature in DER encoding.
        // JJWT's EllipticCurveProvider.transcodeSignatureToDER() internally takes care of transcoding
        // raw R||S to DER as needed inside EllipticCurveProvider.isValid().
        if (!signatureValidator.isValid(concatSignedFields, decodedSignature)) {
            throw new AuthTokenSignatureValidationException();
        }
    }

    private MessageDigest hashAlgorithmForName(String algorithm) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-" + algorithm.substring(algorithm.length() - 3));
    }

    private void requireNotEmpty(String argument, String fieldName) throws AuthTokenParseException {
        if (Strings.isNullOrEmpty(argument)) {
            throw new AuthTokenParseException("'" + fieldName + "' is null or empty");
        }
    }

}
