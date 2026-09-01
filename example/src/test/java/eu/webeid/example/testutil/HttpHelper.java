// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.testutil;

import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.DefaultMockMvcBuilder;
import eu.webeid.example.security.dto.AuthTokenDTO;
import eu.webeid.example.service.dto.CertificateDTO;
import eu.webeid.example.service.dto.SignatureDTO;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

public class HttpHelper {

    public static MvcResult login(DefaultMockMvcBuilder mvcBuilder, MockHttpSession session, AuthTokenDTO authTokenDTO) throws Exception {
        // @formatter:off
        return mvcBuilder
                .build()
                .perform(post("/auth/login")
                        .session(session)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(ObjectMother.toJson(authTokenDTO)))
                .andReturn();
        // @formatter:on
    }

    public static MockHttpServletResponse upload(DefaultMockMvcBuilder mvcBuilder, MockHttpSession session, MockMultipartFile mockMultipartFile) throws Exception {
        // @formatter:off
        return mvcBuilder
                .build()
                .perform(MockMvcRequestBuilders.multipart("/sign/upload")
                        .file(mockMultipartFile)
                        .session(session))
                .andReturn()
                .getResponse();
        // @formatter:on
    }

    public static MockHttpServletResponse prepare(DefaultMockMvcBuilder mvcBuilder, MockHttpSession session, CertificateDTO certificateDTO) throws Exception {
        // @formatter:off
        return mvcBuilder
                .build()
                .perform(post("/sign/prepare")
                        .session(session)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(ObjectMother.toJson(certificateDTO)))
                .andReturn()
                .getResponse();
        // @formatter:on
    }

    public static MockHttpServletResponse sign(DefaultMockMvcBuilder mvcBuilder, MockHttpSession session, SignatureDTO signatureDTO) throws Exception {
        // @formatter:off
        return mvcBuilder
                .build()
                .perform(post("/sign/sign")
                        .session(session)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(ObjectMother.toJson(signatureDTO)))
                .andReturn()
                .getResponse();
        // @formatter:on
    }

    public static MockHttpServletResponse download(DefaultMockMvcBuilder mvcBuilder, MockHttpSession session) throws Exception {
        // @formatter:off
        return mvcBuilder
                .build()
                .perform(get("/sign/download")
                        .session(session))
                .andReturn()
                .getResponse();
        // @formatter:on
    }
}
