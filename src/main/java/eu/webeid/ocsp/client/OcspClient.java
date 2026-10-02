// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.ocsp.client;

import eu.webeid.ocsp.exceptions.OCSPClientException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;

import java.net.URI;

public interface OcspClient {

    OCSPResp request(URI url, OCSPReq request) throws OCSPClientException;

}
