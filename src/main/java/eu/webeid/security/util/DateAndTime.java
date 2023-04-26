/*
 * Copyright (c) 2020-2023 Estonian Information System Authority
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

package eu.webeid.security.util;

import io.jsonwebtoken.Clock;

import java.time.Duration;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.Objects;

public final class DateAndTime {

    public static ZonedDateTime utcNow() {
        return ZonedDateTime.now(ZoneOffset.UTC);
    }

    public static void requirePositiveDuration(Duration duration, String fieldName) {
        Objects.requireNonNull(duration, fieldName + " must not be null");
        if (duration.isNegative() || duration.isZero()) {
            throw new IllegalArgumentException(fieldName + " must be greater than zero");
        }
    }

    public static class DefaultClock implements Clock {

        public static final Clock INSTANCE = new DefaultClock();

        public Date now() {
            return new Date();
        }

    }

    private DateAndTime() {
        throw new IllegalStateException("Utility class");
    }

}
