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

package eu.webeid.example.service;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import eu.webeid.example.config.WebEidMobileProperties;
import eu.webeid.example.security.WebEidAuthentication;
import eu.webeid.example.service.dto.CertificateDTO;
import eu.webeid.example.service.dto.DigestDTO;
import eu.webeid.example.service.dto.SignatureAlgorithmDTO;
import eu.webeid.security.authtoken.SupportedSignatureAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

@Component
public class MobileSigningService {
    public static final String CERTIFICATE_RESPONSE_PATH = "/sign/mobile/certificate";
    public static final String SIGNATURE_RESPONSE_PATH = "/sign/mobile/signature";
    public static final String WEB_EID_MOBILE_SIGN_PATH = "sign";
    public static final String WEB_EID_GET_CERT_PATH = "cert";
    private static final Logger LOG = LoggerFactory.getLogger(MobileSigningService.class);
    private static final ObjectWriter OBJECT_WRITER = new ObjectMapper().writerFor(RequestObject.class);
    private final SigningService signingService;
    private final WebEidMobileProperties webEidMobileProperties;

    public MobileSigningService(SigningService signingService, WebEidMobileProperties webEidMobileProperties) {
        this.signingService = signingService;
        this.webEidMobileProperties = webEidMobileProperties;
    }

    public MobileInitRequest initCertificateOrSigningRequest(WebEidAuthentication authentication) throws IOException, CertificateException, NoSuchAlgorithmException {
        String signingCertificate = authentication.getSigningCertificate();
        List<SupportedSignatureAlgorithm> supportedSignatureAlgorithms = authentication.getSupportedSignatureAlgorithms();
        if (signingCertificate == null || supportedSignatureAlgorithms == null) {
            return initCertificateRequest();
        }
        CertificateDTO certificateDTO = new CertificateDTO();
        certificateDTO.setCertificate(signingCertificate);
        certificateDTO.setSupportedSignatureAlgorithms(mapSupportedAlgorithms(supportedSignatureAlgorithms));
        return initSigningRequest(authentication, certificateDTO);
    }

    public MobileInitRequest initSigningRequest(WebEidAuthentication authentication, CertificateDTO certificateDTO) throws IOException, CertificateException, NoSuchAlgorithmException {
        Objects.requireNonNull(authentication, "authentication must not be null");
        Objects.requireNonNull(certificateDTO, "certificateDTO must not be null");
        final String responseUri = ServletUriComponentsBuilder.fromCurrentContextPath()
            .path(SIGNATURE_RESPONSE_PATH)
            .build()
            .toUriString();
        final DigestDTO digest = signingService.prepareContainer(certificateDTO, authentication);
        final RequestObject initRequest = new RequestObject(
            responseUri,
            certificateDTO.getCertificate(),
            digest.getHash(),
            digest.getHashFunction());
        final String payloadJson = OBJECT_WRITER.writeValueAsString(initRequest);
        final String encoded = Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(payloadJson.getBytes());
        final String requestUri = getRequestUri(WEB_EID_MOBILE_SIGN_PATH, encoded);

        return new MobileInitRequest(requestUri);
    }

    private MobileInitRequest initCertificateRequest() throws IOException {
        final String responseUri = ServletUriComponentsBuilder.fromCurrentContextPath()
            .path(CERTIFICATE_RESPONSE_PATH)
            .build()
            .toUriString();
        final RequestObject initRequest = new RequestObject(responseUri, null, null, null);
        final String payloadJson = OBJECT_WRITER.writeValueAsString(initRequest);
        final String encoded = Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(payloadJson.getBytes());
        final String requestUri = getRequestUri(WEB_EID_GET_CERT_PATH, encoded);

        return new MobileInitRequest(requestUri);
    }

    private String getRequestUri(String path, String encodedPayload) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(webEidMobileProperties.baseRequestUri());
        if (webEidMobileProperties.baseRequestUri().startsWith("http")) {
            builder.pathSegment(path);
        } else {
            builder.host(path);
        }
        return builder.fragment(encodedPayload).toUriString();
    }

    private List<SignatureAlgorithmDTO> mapSupportedAlgorithms(List<SupportedSignatureAlgorithm> algorithms) {
        return algorithms.stream().map(ssa -> {
            var dto = new SignatureAlgorithmDTO();
            dto.setCryptoAlgorithm(ssa.getCryptoAlgorithm());
            dto.setHashFunction(ssa.getHashFunction());
            dto.setPaddingScheme(ssa.getPaddingScheme());
            return dto;
        }).toList();
    }

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record MobileInitRequest(
        String requestUri
    ) {
    }

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    @JsonInclude(JsonInclude.Include.NON_NULL)
    record RequestObject(
        String responseUri,
        String signingCertificate,
        String hash,
        String hashFunction
    ) {
    }
}
