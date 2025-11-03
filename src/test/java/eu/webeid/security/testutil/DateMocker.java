/*
 * Copyright (c) 2020-2025 Estonian Information System Authority
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
