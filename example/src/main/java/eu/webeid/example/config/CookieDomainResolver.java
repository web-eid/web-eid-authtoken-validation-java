// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.config;

import org.apache.commons.lang3.StringUtils;

public final class CookieDomainResolver {

    public static String toApexDomain(String localOrigin) {
        if (StringUtils.isBlank(localOrigin)) {
            return null;
        }

        String hostnamePort = StringUtils.substringAfter(localOrigin, "//");
        String hostname = StringUtils.substringBefore(hostnamePort, ":");
        String[] labels = hostname.split("\\.");
        if (labels.length <= 2) {
            return hostname;
        }
        return labels[labels.length - 2] + "." + labels[labels.length - 1];
    }

    private CookieDomainResolver() {
    }
}
