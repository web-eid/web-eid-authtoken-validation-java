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

package eu.webeid.security.validator.versionvalidators;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility for matching Web eID authentication token format version strings of the form
 * {@code web-eid:<major>[.<minor>]}, e.g. {@code web-eid:1} or {@code web-eid:1.1}.
 */
final class AuthTokenVersion {

    // Matches 'web-eid:<major>' with an optional canonical '.<minor>', where both numbers have no leading
    // zeros ('0' or '[1-9]\d*') and are at most 9 digits so that they always fit in an int. Non-canonical
    // spellings such as 'web-eid:1.00' or 'web-eid:01' are rejected so that ambiguous version numbers cannot
    // bypass the more specific validators.
    private static final Pattern TOKEN_FORMAT_PATTERN =
        Pattern.compile("^web-eid:(0|[1-9]\\d{0,8})(?:\\.(0|[1-9]\\d{0,8}))?$");

    private AuthTokenVersion() {
        throw new IllegalStateException("Utility class");
    }

    /**
     * Returns whether the given token format has exactly the required major version and a minor version that
     * is greater than or equal to the required minor version. A missing minor version is treated as 0.
     * Backwards-compatible minor version changes are supported within the same major version, while an
     * incompatible major version change is not.
     */
    static boolean supports(String format, int requiredExactMajorVersion, int requiredMinimalMinorVersion) {
        final Version version = parse(format);
        return version != null
            && version.major() == requiredExactMajorVersion
            && version.minor() >= requiredMinimalMinorVersion;
    }

    /**
     * Returns whether the given token format has exactly the required major version and exactly the required
     * minor version. A missing minor version is treated as 0.
     */
    static boolean supportsExactly(String format, int requiredExactMajorVersion, int requiredExactMinorVersion) {
        final Version version = parse(format);
        return version != null
            && version.major() == requiredExactMajorVersion
            && version.minor() == requiredExactMinorVersion;
    }

    private static Version parse(String format) {
        if (format == null) {
            return null;
        }
        final Matcher matcher = TOKEN_FORMAT_PATTERN.matcher(format);
        if (!matcher.matches()) {
            return null;
        }
        final int major = Integer.parseInt(matcher.group(1));
        final int minor = matcher.group(2) == null ? 0 : Integer.parseInt(matcher.group(2));
        return new Version(major, minor);
    }

    private record Version(int major, int minor) {
    }
}
