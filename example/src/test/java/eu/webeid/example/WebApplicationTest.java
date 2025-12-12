// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example;

import eu.webeid.example.config.TestValidatorConfiguration;
import eu.webeid.example.testutil.Dates;
import eu.webeid.example.testutil.HttpHelper;
import eu.webeid.example.testutil.ObjectMother;
import io.jsonwebtoken.Clock;
import org.digidoc4j.Container;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.impl.asic.asice.AsicESignatureBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
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

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockStatic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@Import(TestValidatorConfiguration.class)
@WebAppConfiguration
public class WebApplicationTest {

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
        System.out.println(response.getContentAsString());
    }

    @ParameterizedTest
    @ValueSource(strings = {"{", "null", "{}", "{\"auth-token\":null}"})
    void whenAuthenticationRequestIsMalformedOrMissingToken_thenReturnsUnauthorized(String body) throws Exception {
        mvcBuilder.build().perform(post("/auth/login")
                        .with(csrf())
                        .contentType("application/json")
                        .content(body))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void testHappyFlow_LoginPrepareSignDownload() throws Exception {

        try (var mockedClock = mockStatic(DateAndTime.DefaultClock.class);
             var mockedSignatureBuilder = mockStatic(SignatureBuilder.class)) {
            mockedClock.<Clock>when(DateAndTime.DefaultClock::getInstance)
                .thenReturn(() -> Date.from(Dates.getAuthTokenValidationDateTime().toInstant()));
            mockedSignatureBuilder.when(() -> SignatureBuilder.aSignature(any(Container.class)))
                .thenAnswer(invocation -> new TestSignatureBuilder(invocation.getArgument(0)));

            MockHttpSession session = new MockHttpSession();
            session.setAttribute("challenge-nonce", new ChallengeNonce(ObjectMother.VALID_CHALLENGE_NONCE, DateAndTime.utcNow().plusMinutes(1)));

            // Act and assert
            mvcBuilder.build().perform(get("/auth/challenge"));

            MvcResult result = HttpHelper.login(mvcBuilder, session, ObjectMother.mockAuthToken());
            session = (MockHttpSession) result.getRequest().getSession();
            MockHttpServletResponse response = result.getResponse();
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

            response = HttpHelper.sign(mvcBuilder, session, ObjectMother.mockSignRequest(digestDTO.hash()));
            assertEquals(HttpStatus.OK.value(), response.getStatus());

            response = HttpHelper.download(mvcBuilder, session);
            assertEquals(HttpStatus.OK.value(), response.getStatus());
            assertEquals("attachment; filename=example-for-signing.asice", response.getHeader("Content-Disposition"));
            final Container signedContainer = (Container) session.getAttribute("container-to-sign");
            assertEquals(1, signedContainer.getSignatures().size());
            assertEquals(SignatureProfile.T, signedContainer.getSignatures().get(0).getProfile());
        }
    }

    private static final class TestSignatureBuilder extends AsicESignatureBuilder {
        private TestSignatureBuilder(Container container) {
            setContainer(container);
            signatureParameters.setClaimedSigningDate(Date.from(Dates.getSigningDateTime().toInstant()));
        }

        @Override
        public SignatureBuilder withSignatureProfile(SignatureProfile profile) {
            // Verify that the application requests LT signatures.
            assertEquals(SignatureProfile.LT, profile);
            // LT requires OCSP evidence unavailable for this test certificate.
            // Use T (timestamped signing) for this test so it can complete without that evidence.
            return super.withSignatureProfile(SignatureProfile.T);
        }
    }
}
