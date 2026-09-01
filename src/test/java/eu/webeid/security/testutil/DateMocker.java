// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.testutil;

import com.fasterxml.jackson.databind.util.StdDateFormat;
import eu.webeid.security.util.DateAndTime;
import io.jsonwebtoken.Clock;
import org.mockito.MockedStatic;

import java.text.ParseException;
import java.util.Date;

public class DateMocker {

    private static final StdDateFormat STD_DATE_FORMAT = new StdDateFormat();

    public static void mockDate(String iso8601Date, MockedStatic<DateAndTime.DefaultClock> mockedClock) {
        try {
            final Date theDate = STD_DATE_FORMAT.parse(iso8601Date);
            mockedClock.when(DateAndTime.DefaultClock::getInstance).thenReturn((Clock) () -> theDate);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }
}
