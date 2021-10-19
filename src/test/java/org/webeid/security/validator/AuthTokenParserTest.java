package org.webeid.security.validator;

import org.junit.jupiter.api.Test;

import static org.webeid.security.testutil.Tokens.MINIMAL_FORMAT;

class AuthTokenParserTest {

    @Test
    void testJwtWithoutDateFields() throws Exception {
        final AuthTokenParser authTokenParser = new AuthTokenParser(MINIMAL_FORMAT);
        authTokenParser.parseHeaderFromTokenString();
        authTokenParser.validateTokenSignatureAndParseClaims();
    }

}
