// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.testutil;

import eu.europa.esig.dss.model.BLevelParameters;
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

    public static void setMockedSignatureDate(ZonedDateTime mockedDateTime) {
        new MockUp<BLevelParameters>() {
            @Mock
            public Date getSigningDate() {
                return Date.from(mockedDateTime.toInstant());
            }
        };
    }
}
