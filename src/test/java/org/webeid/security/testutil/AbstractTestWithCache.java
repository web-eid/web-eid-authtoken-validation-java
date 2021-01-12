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

package org.webeid.security.testutil;

import com.github.benmanes.caffeine.jcache.spi.CaffeineCachingProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;

import javax.cache.Cache;
import javax.cache.CacheManager;
import javax.cache.Caching;
import javax.cache.configuration.CompleteConfiguration;
import javax.cache.configuration.MutableConfiguration;
import java.time.LocalDateTime;

public abstract class AbstractTestWithCache {

    private static final String CACHE_NAME = "test-cache";
    private static final String CORRECT_TEST_NONCE_KEY = "12345678123456781234567812345678";
    private static final String INCORRECT_TEST_NONCE_KEY = CORRECT_TEST_NONCE_KEY + "incorrect";
    private static final String TOO_SHORT_TEST_NONCE_KEY = "1234567812345678123456781234567";

    private final CacheManager cacheManager = Caching.getCachingProvider(CaffeineCachingProvider.class.getName()).getCacheManager();
    private final CompleteConfiguration<String, LocalDateTime> cacheConfig = new MutableConfiguration<String, LocalDateTime>().setTypes(String.class, LocalDateTime.class);

    protected Cache<String, LocalDateTime> cache;

    @BeforeEach
    protected void setup() {
        cache = cacheManager.createCache(CACHE_NAME, cacheConfig);
    }

    public void putCorrectNonceToCache() {
        cache.putIfAbsent(CORRECT_TEST_NONCE_KEY, fiveMinutesFromNow());
    }

    public void putExpiredNonceToCache() {
        cache.putIfAbsent(CORRECT_TEST_NONCE_KEY, LocalDateTime.now().minusMinutes(5));
    }

    public void putIncorrectNonceToCache() {
        cache.putIfAbsent(INCORRECT_TEST_NONCE_KEY, fiveMinutesFromNow());
    }

    public void putTooShortNonceToCache() {
        cache.putIfAbsent(TOO_SHORT_TEST_NONCE_KEY, fiveMinutesFromNow());
    }

    @AfterEach
    public void tearDown() {
        cacheManager.destroyCache(CACHE_NAME);
    }

    private LocalDateTime fiveMinutesFromNow() {
        return LocalDateTime.now().plusMinutes(5);
    }

}
