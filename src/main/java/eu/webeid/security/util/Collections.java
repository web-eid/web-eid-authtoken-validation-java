// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.util;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public final class Collections {

    @SafeVarargs
    public static <T> Set<T> newHashSet(T... elements) {
        final Set<T> set = new HashSet<>();
        java.util.Collections.addAll(set, elements);
        return set;
    }

    public static byte[] concat(byte[] first, byte[] second) {
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    private Collections() {
        throw new IllegalStateException("Utility class");
    }

}
