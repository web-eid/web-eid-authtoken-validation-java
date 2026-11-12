// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.testutil;

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

public final class ResourceUtil {

    private ResourceUtil() {
    }

    public static byte[] bytesFromResource(String resource) throws IOException {
        try (final InputStream resourceAsStream = ClassLoader.getSystemResourceAsStream(resource)) {
            Objects.requireNonNull(resourceAsStream, () -> "Resource not found: " + resource);
            return resourceAsStream.readAllBytes();
        }
    }
}
