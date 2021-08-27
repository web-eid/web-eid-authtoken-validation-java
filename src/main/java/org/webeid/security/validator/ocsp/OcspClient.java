package org.webeid.security.validator.ocsp;

import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;

import java.io.IOException;
import java.net.URI;

public interface OcspClient {

    OCSPResp request(URI url, OCSPReq request) throws IOException;

}
