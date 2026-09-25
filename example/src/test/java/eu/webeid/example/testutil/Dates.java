// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.testutil;

import java.time.ZoneId;
import java.time.ZonedDateTime;

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

}
