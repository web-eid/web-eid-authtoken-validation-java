// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.web.rest;

import eu.webeid.example.security.WebEidAuthentication;
import eu.webeid.example.service.SigningService;
import eu.webeid.example.service.dto.CertificateDTO;
import eu.webeid.example.service.dto.DigestDTO;
import eu.webeid.example.service.dto.FileDTO;
import eu.webeid.example.service.dto.SignatureDTO;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import static eu.webeid.example.security.AuthTokenDTOAuthenticationProvider.ROLE_USER;

@RestController
@RequestMapping("sign")
@Secured(ROLE_USER)
public class SigningController {

    private final SigningService signingService;

    public SigningController(SigningService signingService) {
        this.signingService = signingService;
    }

    @PostMapping("prepare")
    public DigestDTO prepare(@RequestBody CertificateDTO data, WebEidAuthentication authentication) throws CertificateException, NoSuchAlgorithmException, IOException {
        return signingService.prepareContainer(data, authentication);
    }

    @PostMapping("sign")
    public FileDTO sign(@RequestBody SignatureDTO data) {
        return signingService.signContainer(data);
    }

    @GetMapping(value = "download", produces = "application/vnd.etsi.asic-e+zip")
    public ResponseEntity<Resource> download() throws IOException {

        ByteArrayResource resource = signingService.getSignedContainerAsResource();
        return ResponseEntity.ok()
                .contentLength(resource.contentLength())
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + signingService.getContainerName())
                .body(resource);
    }

    /*  Here is an example endpoint that demonstrates how to handle file uploads.
        See also resources/templates/welcome-with-file-upload-support.html.

    @PostMapping(value = "upload", produces = "application/json")
    public FileDTO upload(@RequestParam("file") MultipartFile multipartFile) throws IOException {
        return signingService.createContainer(FileDTO.fromMultipartFile(multipartFile));
    }
    */
}
