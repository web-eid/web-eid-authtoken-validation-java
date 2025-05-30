// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example;

import eu.webeid.example.testutil.Dates;
import eu.webeid.example.testutil.HttpHelper;
import eu.webeid.example.testutil.ObjectMother;
import mockit.Mock;
import mockit.MockUp;
import org.digidoc4j.impl.asic.AsicSignatureFinalizer;
import org.digidoc4j.impl.asic.xades.XadesSignature;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.DefaultMockMvcBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import eu.webeid.example.service.dto.DigestDTO;
import eu.webeid.security.challenge.ChallengeNonce;
import eu.webeid.security.util.DateAndTime;
import eu.webeid.security.validator.certvalidators.SubjectCertificateNotRevokedValidator;

import java.security.cert.X509Certificate;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@WebAppConfiguration
public class WebApplicationTest {

    private static final Pattern CSRF_TOKEN_META_TAG = Pattern.compile("<meta id=\"csrftoken\" name=\"csrftoken\" content=\"[^\"]+\"/>");

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private jakarta.servlet.Filter[] springSecurityFilterChain;

    private static DefaultMockMvcBuilder mvcBuilder;

    @BeforeEach
    public void setup() {
        mvcBuilder = MockMvcBuilders.webAppContextSetup(context).addFilters(springSecurityFilterChain);
    }

    @Test
    public void testRoot() throws Exception {
        // @formatter:off
        MockHttpServletResponse response = mvcBuilder
            .build()
            .perform(get("/"))
            .andReturn()
            .getResponse();
        // @formatter:on
        assertEquals(HttpStatus.OK.value(), response.getStatus());
        assertNull(response.getCookie("WEBEID-XSRF-TOKEN"));
        String content = response.getContentAsString();
        assertTrue(CSRF_TOKEN_META_TAG.matcher(content).find());
        assertTrue(content.contains("<meta id=\"csrfheadername\" name=\"csrfheadername\" content=\"X-CSRF-TOKEN\"/>"));
    }

    @Test
    void userWhenLoggedOutReturnsUnauthorized() throws Exception {
        mvcBuilder.build().perform(get("/auth/user"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void logoutExpiresSessionCookie() throws Exception {
        MockHttpServletResponse response = mvcBuilder.build()
            .perform(post("/logout")
                .secure(true)
                .session(new MockHttpSession())
                .with(csrf()))
            .andReturn()
            .getResponse();

        assertEquals(HttpStatus.OK.value(), response.getStatus());
        assertTrue(response.getHeaders(HttpHeaders.SET_COOKIE).stream().anyMatch(cookie ->
            cookie.startsWith("__Host-JSESSIONID=")
                && cookie.contains("Path=/")
                && cookie.contains("Max-Age=0")
                && cookie.contains("Secure")));
    }

    @Test
    public void testHappyFlow_LoginPrepareSignDownload() throws Exception {

        // Arrange
        new MockUp<SubjectCertificateNotRevokedValidator>() {
            @Mock
            public void validateCertificateNotRevoked(X509Certificate subjectCertificate) {
                // Do not call real OCSP service in tests.
            }
        };

        new MockUp<AsicSignatureFinalizer>() {
            @Mock
            public void validateOcspResponse(XadesSignature xadesSignature) {
                // Do not call real OCSP service in tests.
            }
        };

        MockHttpSession session = new MockHttpSession();
        session.setAttribute("challenge-nonce", new ChallengeNonce(ObjectMother.VALID_CHALLENGE_NONCE, DateAndTime.utcNow().plusMinutes(1)));

        Dates.setMockedSignatureDate(Dates.getSigningDateTime());
        Dates.setMockedAuthTokenValidationDate(Dates.getAuthTokenValidationDateTime());

        // Act and assert
        mvcBuilder.build().perform(get("/auth/challenge"));

        MvcResult result = HttpHelper.login(mvcBuilder, session, ObjectMother.mockAuthToken());
        session = (MockHttpSession) result.getRequest().getSession();
        MockHttpServletResponse response = result.getResponse();
            assertEquals("{\"sub\":\"JAAK-KRISTJAN JÕEORG\",\"auth\":\"[ROLE_USER]\"}", response.getContentAsString());

            response = mvcBuilder.build()
                .perform(get("/auth/user").session(session))
                .andReturn()
                .getResponse();
            assertEquals(HttpStatus.OK.value(), response.getStatus());
        assertEquals("{\"sub\":\"JAAK-KRISTJAN JÕEORG\",\"auth\":\"[ROLE_USER]\"}", response.getContentAsString());

        /* Example how to test file upload.
        response = HttpHelper.upload(mvcBuilder, session, mockMultipartFile());
        assertEquals(HttpStatus.OK.value(), response.getStatus());
        public static MockMultipartFile mockMultipartFile() {
            return new MockMultipartFile("file", "test-file.txt", "text/plain", "some xml".getBytes());
        }
        */

        response = HttpHelper.prepare(mvcBuilder, session, ObjectMother.mockPrepareRequest());
        assertEquals(HttpStatus.OK.value(), response.getStatus());

        DigestDTO digestDTO = ObjectMother.jsonStringToBean(response.getContentAsString(), DigestDTO.class);

        response = HttpHelper.sign(mvcBuilder, session, ObjectMother.mockSignRequest(digestDTO.getHash()));
        assertEquals(HttpStatus.OK.value(), response.getStatus());

        response = HttpHelper.download(mvcBuilder, session);
        assertEquals(HttpStatus.OK.value(), response.getStatus());
        assertEquals("attachment; filename=example-for-signing.asice", response.getHeader("Content-Disposition"));
    }
}
