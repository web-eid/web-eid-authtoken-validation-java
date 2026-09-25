// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.service.dto;

import org.springframework.core.io.ClassPathResource;
import org.springframework.util.MimeTypeUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.util.Objects;

public class FileDTO implements Serializable {
    private static final String EXAMPLE_FILENAME = "example-for-signing.txt";

    private final String name;
    private String contentType;
    private byte[] contentBytes;

    public FileDTO(String name) {
        this.name = name;
    }

    public FileDTO(String name, String contentType, byte[] contentBytes) {
        this.name = name;
        this.contentType = contentType;
        this.contentBytes = contentBytes;
    }

    public static FileDTO fromMultipartFile(MultipartFile file) throws IOException {
        return new FileDTO(
                Objects.requireNonNull(file.getOriginalFilename()),
                Objects.requireNonNull(file.getContentType()),
                Objects.requireNonNull(file.getBytes())
        );
    }

    public static FileDTO getExampleForSigningFromResources() throws IOException {
        try (InputStream stream = new ClassPathResource("/static/files/" + EXAMPLE_FILENAME).getInputStream()) {
            return new FileDTO(EXAMPLE_FILENAME, MimeTypeUtils.TEXT_PLAIN_VALUE, stream.readAllBytes());
        }
    }

    public String getName() {
        return name;
    }

    public String getContentType() {
        return contentType;
    }

    public byte[] getContentBytes() {
        return contentBytes;
    }
}
