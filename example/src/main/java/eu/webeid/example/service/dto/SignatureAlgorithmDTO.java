// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.service.dto;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class SignatureAlgorithmDTO {

    // See https://github.com/web-eid/web-eid-app/blob/main/src/controller/command-handlers/signauthutils.cpp#L121-L127
    private static final Set<String> SUPPORTED_CRYPTO_ALGOS = new HashSet<>(Arrays.asList(
            "ECC", "RSA"
    ));
    private static final Set<String> SUPPORTED_PADDING_SCHEMES = new HashSet<>(Arrays.asList(
            "NONE", "PKCS1.5", "PSS"
    ));
    // See https://github.com/web-eid/libelectronic-id/tree/main/src/electronic-id.cpp#L131
    private static final Set<String> SUPPORTED_HASH_FUNCTIONS = new HashSet<>(Arrays.asList(
            "SHA-224", "SHA-256", "SHA-384", "SHA-512",
            "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"
    ));

    private String cryptoAlgorithm;

    private String hashFunction;

    private String paddingScheme;

    public String getCryptoAlgorithm() {
        return cryptoAlgorithm;
    }

    public void setCryptoAlgorithm(String cryptoAlgorithm) {
        if (!SUPPORTED_CRYPTO_ALGOS.contains(cryptoAlgorithm)) {
            throw new IllegalArgumentException("The provided crypto algorithm is not supported");
        }
        this.cryptoAlgorithm = cryptoAlgorithm;
    }

    public String getHashFunction() {
        return hashFunction;
    }

    public void setHashFunction(String hashFunction) {
        if (!SUPPORTED_HASH_FUNCTIONS.contains(hashFunction)) {
            throw new IllegalArgumentException("The provided hash function is not supported");
        }
        this.hashFunction = hashFunction;
    }

    public String getPaddingScheme() {
        return paddingScheme;
    }

    public void setPaddingScheme(String paddingScheme) {
        if (!SUPPORTED_PADDING_SCHEMES.contains(paddingScheme)) {
            throw new IllegalArgumentException("The provided padding scheme is not supported");
        }
        this.paddingScheme = paddingScheme;
    }
}
