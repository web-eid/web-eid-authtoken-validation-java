package org.webeid.security.util;

import java.net.URI;

public class OcspUrls {
    public static final URI ESTEID_2015 = URI.create("http://aia.sk.ee/esteid2015");

    private OcspUrls() {
        throw new IllegalStateException("Constants class");
    }

}
