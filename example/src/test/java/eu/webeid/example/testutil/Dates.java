// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.testutil;

import eu.europa.esig.dss.model.BLevelParameters;
import eu.webeid.security.util.DateAndTime;
import mockit.Mock;
import mockit.MockUp;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Date;

public final class Dates {

    public static ZonedDateTime getSigningDateTime() {
        return ZonedDateTime.of(2020, 4, 14, 13, 36, 49, 0,
                ZoneId.of("Europe/Tallinn"));
    }

    public static ZonedDateTime getAuthTokenValidationDateTime() {
        // Ensure that the certificates do not expire.
        return ZonedDateTime.of(2021, 7, 23, 0, 0, 0, 0,
                ZoneId.of("UTC"));
    }

    public static void setMockedSignatureDate(ZonedDateTime mockedDateTime) {
        new MockUp<BLevelParameters>() {
            @Mock
            public Date getSigningDate() {
                return Date.from(mockedDateTime.toInstant());
            }
        };
    }

    public static void setMockedAuthTokenValidationDate(ZonedDateTime mockedDateTime) {
        new MockUp<DateAndTime.DefaultClock>() {
            @Mock
            public Date now() {
                return Date.from(mockedDateTime.toInstant());
            }
        };
    }
}
