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

package org.webeid.security.validator;

import org.junit.jupiter.api.Test;
import org.webeid.security.exceptions.TokenExpiredException;
import org.webeid.security.testutil.AbstractTestWithValidatorAndCorrectNonce;
import org.webeid.security.testutil.Dates;
import org.webeid.security.testutil.Tokens;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClockSkewTest extends AbstractTestWithValidatorAndCorrectNonce {

    @Test
    void blockLargeClockSkew4min() throws Exception {
        // Authentication token expires at 2020-04-14 13:32:49
        Dates.setMockedDate(Dates.create("2020-04-14T13:36:49Z"));
        assertThatThrownBy(() -> validator.validate(Tokens.SIGNED))
            .isInstanceOf(TokenExpiredException.class);
    }

    @Test
    void allowSmallClockSkew2min() throws Exception {
        // Authentication token expires at 2020-04-14 13:32:49
        Dates.setMockedDate(Dates.create("2020-04-14T13:30:49Z"));
        assertThatCode(() -> validator.validate(Tokens.SIGNED))
            .doesNotThrowAnyException();
    }

}
