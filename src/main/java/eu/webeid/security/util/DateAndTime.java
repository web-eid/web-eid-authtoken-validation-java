// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

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

        // Allows mocking of time-dependent behavior with Mockito.mockStatic() in tests.
        private static final Clock instance = new DefaultClock();

        public static Clock getInstance() {
            return instance;
        }

        @Override
        public Date now() {
            return new Date();
        }

    }

    private DateAndTime() {
        throw new IllegalStateException("Utility class");
    }

}
