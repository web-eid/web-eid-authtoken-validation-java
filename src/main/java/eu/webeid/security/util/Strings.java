// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.util;

public final class Strings {

    public static String toTitleCase(String input) {
        final StringBuilder titleCase = new StringBuilder(input.length());
        boolean nextTitleCase = true;

        for (char c : input.toLowerCase().toCharArray()) {
            if (!Character.isLetterOrDigit(c)) {
                nextTitleCase = true;
            } else if (nextTitleCase) {
                c = Character.toTitleCase(c);
                nextTitleCase = false;
            }
            titleCase.append(c);
        }

        return titleCase.toString();
    }

    public static boolean isNullOrEmpty(String argument) {
        return argument == null || argument.isEmpty();
    }

    private Strings() {
        throw new IllegalStateException("Utility class");
    }

}
