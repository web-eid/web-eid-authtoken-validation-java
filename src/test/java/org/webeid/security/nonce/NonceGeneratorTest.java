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

package org.webeid.security.nonce;


import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.webeid.security.testutil.AbstractTestWithCache;

import static org.assertj.core.api.Assertions.assertThat;

class NonceGeneratorTest extends AbstractTestWithCache {
    private NonceGenerator nonceGenerator;

    @Override
    @BeforeEach
    public void setup() {
        super.setup();
        nonceGenerator = new NonceGeneratorBuilder()
            .withNonceCache(cache)
            .build();
    }

    @Test
    public void validateNonceGeneration() {
        final String nonce1 = nonceGenerator.generateAndStoreNonce();
        final String nonce2 = nonceGenerator.generateAndStoreNonce();

        assertThat(nonce1.length()).isEqualTo(44); // Base64-encoded 32 bytes
        assertThat(nonce1).isNotEqualTo(nonce2);
        // It might be possible to add an entropy test by compressing the nonce bytes
        // and verifying that the result is longer than for non-random strings.
    }

}
