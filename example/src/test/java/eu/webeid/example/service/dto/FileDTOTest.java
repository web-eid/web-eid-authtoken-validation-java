// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.service.dto;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.assertj.core.api.Assertions.assertThat;

class FileDTOTest {

    @Test
    void whenExampleFileIsInsideJar_thenLoadsItsContents(@TempDir Path directory) throws Exception {
        final Path jar = directory.resolve("resources.jar");
        final byte[] contents = "Example from a JAR".getBytes(StandardCharsets.UTF_8);
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
            output.putNextEntry(new JarEntry("static/files/example-for-signing.txt"));
            output.write(contents);
            output.closeEntry();
        }

        final Thread thread = Thread.currentThread();
        final ClassLoader originalLoader = thread.getContextClassLoader();
        try (URLClassLoader resourceLoader = new URLClassLoader(new URL[] {jar.toUri().toURL()}, null)) {
            thread.setContextClassLoader(resourceLoader);
            final FileDTO file = FileDTO.getExampleForSigningFromResources();

            assertThat(file.getName()).isEqualTo("example-for-signing.txt");
            assertThat(file.getContentType()).isEqualTo("text/plain");
            assertThat(file.getContentBytes()).containsExactly(contents);
        } finally {
            thread.setContextClassLoader(originalLoader);
        }
    }
}
