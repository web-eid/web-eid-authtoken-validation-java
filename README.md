# web-eid-authtoken-validation-java

![European Regional Development Fund](https://github.com/open-eid/DigiDoc4-Client/blob/master/client/images/EL_Regionaalarengu_Fond.png)

*web-eid-authtoken-validation-java* is a Java library for issuing challenge nonces and validating Web eID authentication tokens during secure authentication with electronic ID (eID) smart cards in web applications.

More information about the Web eID project is available on the project [website](https://web-eid.eu/).

# Quickstart

Complete the steps below to add support for secure authentication with eID cards to your Java web application back end. Instructions for the front end are available [here](https://github.com/web-eid/web-eid.js).

A Java 17 or newer web application that uses Maven or Gradle to manage packages is needed for running this quickstart. Examples are for Maven, but they are straightforward to translate to Gradle.

In the following example we are using the [Spring Framework](https://spring.io/), but the examples can be easily ported to other Java web application frameworks.

## Full example project using the validation library in spring-boot
[example/README.md](example/README.md)

## 1. Add the library to your project

Add the following lines to Maven `pom.xml` to include the Web eID authentication token validation library in your project:

```xml
<dependencies>
    <dependency>
        <groupId>eu.webeid.security</groupId>
        <artifactId>authtoken-validation</artifactId>
        <version>${webeid.version}</version>
    </dependency>
</dependencies>

<repositories>
    <repository>
        <id>gitlab</id>
        <url>https://gitlab.com/api/v4/projects/19948337/packages/maven</url>
    </repository>
</repositories>
```

## 2. Configure the challenge nonce store

The validation library needs a store for saving the issued challenge nonces. As it must be guaranteed that the authentication token is received from the same browser to which the corresponding challenge nonce was issued, using a session-backed challenge nonce store is the most natural choice.

Implement the session-backed challenge nonce store as follows:

```java
import org.springframework.beans.factory.ObjectFactory;
import eu.webeid.security.challenge.ChallengeNonce;
import eu.webeid.security.challenge.ChallengeNonceStore;
import jakarta.servlet.http.HttpSession;

public class SessionBackedChallengeNonceStore implements ChallengeNonceStore {

    private static final String CHALLENGE_NONCE_KEY = "challenge-nonce";
    final ObjectFactory<HttpSession> httpSessionFactory;

    public SessionBackedChallengeNonceStore(ObjectFactory<HttpSession> httpSessionFactory) {
        this.httpSessionFactory = httpSessionFactory;
    }

    @Override
    public void put(ChallengeNonce challengeNonce) {
        currentSession().setAttribute(CHALLENGE_NONCE_KEY, challengeNonce);
    }

    @Override
    public ChallengeNonce getAndRemoveImpl() {
        final ChallengeNonce challengeNonce = (ChallengeNonce) currentSession().getAttribute(CHALLENGE_NONCE_KEY);
        currentSession().removeAttribute(CHALLENGE_NONCE_KEY);
        return challengeNonce;
    }

    private HttpSession currentSession() {
        return httpSessionFactory.getObject();
    }
}
```

## 3. Configure the challenge nonce generator

The validation library needs to generate authentication challenge nonces and store them for later validation in the challenge nonce store. Overview of challenge nonce usage is provided in the [Web eID system architecture document](https://github.com/web-eid/web-eid-system-architecture-doc#authentication-1). The challenge nonce generator will be used in the REST endpoint that issues challenges; it is thread-safe and should be scoped as a singleton.

Configure the challenge nonce generator as follows:

```java
import eu.webeid.security.challenge.ChallengeNonceGenerator;
import eu.webeid.security.challenge.ChallengeNonceGeneratorBuilder;
import eu.webeid.security.challenge.ChallengeNonceStore;

...
    public ChallengeNonceGenerator generator(ChallengeNonceStore challengeNonceStore) {
        return new ChallengeNonceGeneratorBuilder()
                .withChallengeNonceStore(challengeNonceStore)
                .build();
    }
...
```

## 4. Add trusted certificate authority certificates

You must explicitly specify which **intermediate** certificate authorities (CAs) are trusted to issue the eID authentication and OCSP responder certificates. CA certificates can be loaded from either the truststore file, resources or any stream source. We use the [`CertificateLoader`](src/main/java/eu/webeid/security/certificate/CertificateLoader.java) helper class to load CA certificates from resources here, but consider using [the truststore file](example/src/main/java/eu/webeid/example/config/ValidationConfiguration.java) instead.

First, copy the trusted certificates, for example `ESTEID2018.cer`, to `resources/cacerts/`, then load the certificates as follows:

```java
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import eu.webeid.security.certificate.CertificateLoader;

...
    private X509Certificate[] trustedIntermediateCACertificates() throws CertificateException, IOException {
         return CertificateLoader.loadCertificatesFromResources("cacerts/ESTEID2018.cer");
    }
...
```

## 5. Configure the authentication token validator

Once the prerequisites have been met, the authentication token validator itself can be configured.
The mandatory parameters are the website origin (the URL serving the web application, see section [_Basic usage_](#basic-usage) below) and trusted certificate authorities.
The authentication token validator will be used in the login processing component of your web application authentication framework; it is thread-safe and should be scoped as a singleton.

Certificate revocation checking is enabled automatically using the platform OCSP implementation. No additional OCSP configuration is needed for normal use.

```java
import java.io.IOException;
import java.net.URI;
import java.security.cert.CertificateException;
import eu.webeid.security.exceptions.JceException;
import eu.webeid.security.validator.AuthTokenValidator;
import eu.webeid.security.validator.AuthTokenValidatorBuilder;

...
    public AuthTokenValidator tokenValidator() throws JceException, CertificateException, IOException {
        return new AuthTokenValidatorBuilder()
                .withSiteOrigin(URI.create("https://example.org"))
                .withTrustedCertificateAuthorities(trustedIntermediateCACertificates())
                .build();
    }
...
```

The site origin configured with `withSiteOrigin()` must match the origin string
signed by the Web eID application. Use the [ASCII serialization of the
origin](https://html.spec.whatwg.org/multipage/browsers.html#ascii-serialisation-of-an-origin)
as specified by the [Web eID architecture
document](https://github.com/web-eid/web-eid-system-architecture-doc#web-eid-authentication-token-specification).
For internationalized domain names, configure the Punycode form, for example
`https://xn--pike-loa.ee` for `https://päike.ee`.

## 6. Add a REST endpoint for issuing challenge nonces

A REST endpoint that issues challenge nonces is required for authentication. The endpoint must support `GET` requests.

In the following example, we are using the [Spring RESTful Web Services framework](https://spring.io/guides/gs/rest-service/) to implement the endpoint, see also the full implementation [here](example/src/main/java/eu/webeid/example/web/rest/ChallengeController.java).

```java
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import eu.webeid.security.challenge.ChallengeNonceGenerator;
...

@RestController
@RequestMapping("auth")
public class ChallengeController {

    @Autowired // for brevity, prefer constructor dependency injection
    private ChallengeNonceGenerator nonceGenerator;

    @GetMapping("challenge")
    public ChallengeDTO challenge() {
        // a simple DTO with a single 'nonce' field
        final ChallengeDTO challenge = new ChallengeDTO();
        challenge.setNonce(nonceGenerator.generateAndStoreNonce().getBase64EncodedNonce());
        return challenge;
    }
}
```

Also, see general guidelines for implementing secure authentication services [here](https://github.com/SK-EID/smart-id-documentation/wiki/Secure-Implementation-Guide).

## 7. Implement authentication

Authentication consists of calling the `validate()` method of the authentication token validator. The internal implementation of the validation process is described in more detail below and in the [Web eID system architecture document](https://github.com/web-eid/web-eid-system-architecture-doc#authentication-1).

When using [Spring Security](https://spring.io/guides/topicals/spring-security-architecture) with standard cookie-based authentication,

- implement a custom authentication provider that uses the authentication token validator for authentication as shown [here](example/src/main/java/eu/webeid/example/security/AuthTokenDTOAuthenticationProvider.java),
- implement an AJAX authentication processing filter that extracts the authentication token and passes it to the authentication manager as shown [here](example/src/main/java/eu/webeid/example/security/WebEidAjaxLoginProcessingFilter.java),
- configure the authentication provider and authentication processing filter in the application configuration as shown [here](example/src/main/java/eu/webeid/example/config/ApplicationConfiguration.java).

The gist of the validation is [in the `authenticate()` method](example/src/main/java/eu/webeid/example/security/AuthTokenDTOAuthenticationProvider.java) of the authentication provider:

```java
try {
  String nonce = challengeNonceStore.getAndRemove().getBase64EncodedNonce();
  ValidationInfo validationInfo = tokenValidator.validate(authToken, nonce);
  return WebEidAuthentication.fromCertificate(validationInfo.subjectCertificate(), authorities);
} catch (AuthTokenException e) {
  throw new AuthenticationServiceException("Web eID token validation failed", e);
} catch (CertificateEncodingException e) {
  throw new AuthenticationServiceException("Invalid certificate subject fields", e);
}
```

# Table of contents

- [Quickstart](#quickstart)
- [Introduction](#introduction)
- [Authentication token format](#authentication-token-format)
- [Authentication token validation](#authentication-token-validation)
  - [Basic usage](#basic-usage)
  - [Extended configuration](#extended-configuration)
    - [Advanced OCSP configuration](src/main/java/eu/webeid/ocsp/README.md)
  - [Possible validation errors](#possible-validation-errors)
  - [Stateful and stateless authentication](#stateful-and-stateless-authentication)
- [Challenge nonce generation](#challenge-nonce-generation)
  - [Basic usage](#basic-usage-1)
  - [Extended configuration](#extended-configuration-1)
- [Differences between version 1 and version 2](#differences-between-version-1-and-version-2)

# Introduction

The Web eID authentication token validation library for Java contains the implementation of the Web eID authentication token validation process in its entirety to ensure that the authentication token sent by the Web eID browser extension contains valid, consistent data that has not been modified by a third party. It also implements secure challenge nonce generation as required by the Web eID authentication protocol. It is easy to configure and integrate into your authentication service.

The authentication protocol, authentication token format, validation requirements and challenge nonce usage is described in more detail in the [Web eID system architecture document](https://github.com/web-eid/web-eid-system-architecture-doc#authentication-1).

# Authentication token format

In the following, 

- **origin** is defined as the website origin, the URL serving the web application,
- **challenge nonce** (or challenge) is defined as a cryptographic nonce, a large random number that can be used only once, with at least 256 bits of entropy.

The Web eID authentication token is a JSON data structure that looks like the following example:

```json
{
  "unverifiedCertificate": "MIIFozCCA4ugAwIBAgIQHFpdK-zCQsFW4...",
  "algorithm": "RS256",
  "signature": "HBjNXIaUskXbfhzYQHvwjKDUWfNu4yxXZha...",
  "format": "web-eid:1.0",
  "appVersion": "https://web-eid.eu/web-eid-app/releases/v2.0.0"
}
```

It contains the following fields:

- `unverifiedCertificate`: the base64-encoded DER-encoded authentication certificate of the eID user; the public key contained in this certificate should be used to verify the signature; the certificate cannot be trusted as it is received from client side and the client can submit a malicious certificate; to establish trust, it must be verified that the certificate is signed by a trusted certificate authority,

- `algorithm`: the signature algorithm used to produce the signature; the allowed values are the algorithms specified in [JWA RFC](https://www.ietf.org/rfc/rfc7518.html) sections 3.3, 3.4 and 3.5:

    ```
      "ES256", "ES384", "ES512", // ECDSA
      "PS256", "PS384", "PS512", // RSASSA-PSS
      "RS256", "RS384", "RS512"  // RSASSA-PKCS1-v1_5
    ```

- `signature`: the base64-encoded signature of the token (see the description below),

- `format`: the type identifier and version of the token format separated by a colon character '`:`', `web-eid:1.0` as of now; the version number consists of the major and minor number separated by a dot, major version changes are incompatible with previous versions, minor version changes are backwards-compatible within the given major version,

- `appVersion`: the URL identifying the name and version of the application that issued the token; informative purpose, can be used to identify the affected application in case of faulty tokens.

The value that is signed by the user’s authentication private key and included in the `signature` field is `hash(origin)+hash(challenge)`. The hash function is used before concatenation to ensure field separation as the hash of a value is guaranteed to have a fixed length. Otherwise the origin `example.com` with challenge nonce `.eu1234` and another origin `example.com.eu` with challenge nonce `1234` would result in the same value after concatenation. The hash function `hash` is the same hash function that is used in the signature algorithm, for example SHA256 in case of RS256.


# Authentication token validation

The authentication token validation process consists of two stages:

- First, **user certificate validation**: the validator parses the token and extracts the user certificate from the *unverifiedCertificate* field. Then it checks the certificate expiration, purpose and policies. Next it checks that the certificate is signed by a trusted CA and checks the certificate status with OCSP.
- Second, **token signature validation**: the validator validates that the token signature was created using the provided user certificate by reconstructing the signed data `hash(origin)+hash(challenge)` and using the public key from the certificate to verify the signature in the `signature` field. If the signature verification succeeds, then the origin and challenge nonce have been implicitly and correctly verified without the need to implement any additional security checks.

The website back end must lookup the challenge nonce from its local store using an identifier specific to the browser session, to guarantee that the authentication token was received from the same browser to which the corresponding challenge nonce was issued. The website back end must guarantee that the challenge nonce lifetime is limited and that its expiration is checked, and that it can be used only once by removing it from the store during validation.

## Basic usage

As described in section *[5. Configure the authentication token validator](#5-configure-the-authentication-token-validator)*, the mandatory authentication token validator configuration parameters are the website origin and trusted certificate authorities.

**Origin** must be the URL serving the web application. Origin URL must be in the form of `"https://" <hostname> [ ":" <port> ]`  as defined in [MDN](https://developer.mozilla.org/en-US/docs/Web/API/Location/origin) and not contain path or query components. **Note that the `origin` URL must not end with a slash `/`**. The configured origin must use the ASCII serialization that is signed by the Web eID application. For internationalized domain names, use the Punycode form, for example `https://xn--pike-loa.ee` instead of `https://päike.ee`.

The **trusted certificate authority certificates** are used to validate that the user certificate from the authentication token and the OCSP responder certificate is signed by a trusted certificate authority. Intermediate CA certificates must be used instead of the root CA certificates so that revoked CA certificates can be removed. Trusted certificate authority certificates configuration is described in more detail in section *[4. Add trusted certificate authority certificates](#4-add-trusted-certificate-authority-certificates)*.

Before validation, the previously issued **challenge nonce** must be looked up from the store using an identifier specific to the browser session. The challenge nonce must be passed to the `validate()` method in the corresponding parameter. Setting up the challenge nonce store is described in more detail in section *[2. Configure the challenge nonce store](#2-configure-the-challenge-nonce-store)*. 

The authentication token validator configuration and construction is described in more detail in section *[5. Configure the authentication token validator](#5-configure-the-authentication-token-validator)*. Once the validator object has been constructed, it can be used for validating authentication tokens as follows:

```java  
String challengeNonce = challengeNonceStore.getAndRemove().getBase64EncodedNonce();
WebEidAuthToken token = tokenValidator.parse(tokenString);
ValidationInfo validationInfo = tokenValidator.validate(token, challengeNonce);
X509Certificate userCertificate = validationInfo.subjectCertificate();
```

The `validate()` method returns a `ValidationInfo` object on success. Use `subjectCertificate()` to obtain the validated certificate. Validation failures throw an exception, as described in [Possible validation errors](#possible-validation-errors).

Additional revocation information is available to custom integrations through `revocationInfoList()`; see the [OCSP guide](src/main/java/eu/webeid/ocsp/README.md#revocation-information).

The `CertificateData` and `Strings` classes provide helpers for extracting and formatting user information:

```java  
import eu.webeid.security.certificate.CertificateData;
import static eu.webeid.security.util.Strings.toTitleCase;

...
    
CertificateData.getSubjectCN(userCertificate).orElseThrow(); // "JÕEORG\\,JAAK-KRISTJAN\\,38001085718"
CertificateData.getSubjectIdCode(userCertificate).orElseThrow(); // "PNOEE-38001085718"
CertificateData.getSubjectCountryCode(userCertificate).orElseThrow(); // "EE"

toTitleCase(CertificateData.getSubjectGivenName(userCertificate).orElseThrow()); // "Jaak-Kristjan"
toTitleCase(CertificateData.getSubjectSurname(userCertificate).orElseThrow()); // "Jõeorg"
```

## Extended configuration

The default validator uses the platform OCSP implementation to check certificate revocation. A revoked certificate or an unsuccessful revocation check causes authentication to fail.

Use `withDisallowedCertificatePolicies(ASN1ObjectIdentifier... policies)` to add disallowed certificate policies. Estonian Mobile-ID policies are disallowed by default because smart-card authentication must not accept Mobile-ID certificates.

For more advanced revocation requirements, supply a `CertificateRevocationChecker` with `withCertificateRevocationChecker(...)`. The [OCSP configuration guide](src/main/java/eu/webeid/ocsp/README.md) covers custom implementations, the bundled OCSP checker, custom PKIX checkers, responder selection, HTTP settings, and nonce policies.

## Possible validation errors

Certificate and token validation failures are reported through `AuthTokenException` subclasses. `CertificateRevokedException` means the certificate is revoked; `CertificateRevocationCheckFailedException` means its status could not be established. Other failures are documented in the [exception classes](src/main/java/eu/webeid/security/exceptions/).

Log the exception itself, for example `LOG.warn("Web eID authentication failed", e)`, to preserve its cause chain. When wrapping it, retain the cause as shown in the authentication example above. Return a generic authentication failure to the client; keep diagnostic details in server logs. See the [OCSP diagnostics guide](src/main/java/eu/webeid/ocsp/README.md#errors-and-diagnostics) for revocation-specific details.

## Stateful and stateless authentication

In the code examples above we use the classical stateful Spring Security session cookie-based authentication mechanism, where a cookie that contains the user session ID is set during successful login and session data is stored at sever side. Cookie-based authentication must be protected against cross-site request forgery (CSRF) attacks and extra measures must be taken to secure the cookies by serving them only over HTTPS and setting the _HttpOnly_, _Secure_ and _SameSite_ attributes.

A common alternative to stateful authentication is stateless authentication with JSON Web Tokens (JWT) or secure cookie sessions where the session data resides at the client side browser and is either signed or encrypted. Secure cookie sessions are described in [RFC 6896](https://datatracker.ietf.org/doc/html/rfc6896) and in the following [article about secure cookie-based Spring Security sessions](https://www.innoq.com/en/blog/cookie-based-spring-security-session/). Usage of both an anonymous session and a cache is required to store the challenge nonce and the time it was issued before the user is authenticated. The anonymous session must be used for protection against [forged login attacks](https://en.wikipedia.org/wiki/Cross-site_request_forgery#Forging_login_requests) by guaranteeing that the authentication token is received from the same browser to which the corresponding challenge nonce was issued. The cache must be used for protection against replay attacks by guaranteeing that each authentication token can be used exactly once.


# Challenge nonce generation

The authentication protocol requires support for generating challenge nonces, large random numbers that can be used only once, and storing them for later use during token validation. The validation library uses the *java.security.SecureRandom* API as the secure random source and the `ChallengeNonceStore` interface for storing issued challenge nonces. 

No additional JVM configuration is normally required. The selected random-number generator and its entropy source depend on the JDK, operating system and security-provider configuration; some implementations may block while gathering entropy. See the [JDK's `SecureRandom` documentation](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/SecureRandom.html).

If nonce generation stalls, inspect the application's thread dump and selected `SecureRandom` implementation before changing its configuration. On Linux with the OpenJDK SUN provider, `-Djava.security.egd=file:/dev/urandom` can be supplied when starting the application to select `/dev/urandom` as the entropy source for implementations that honor this property. This setting affects the whole JVM. Alternatively, configure the challenge nonce generator with a suitable `SecureRandom` instance using `withSecureRandom(...)`.

This repository's `pom.xml` supplies `-Djava.security.egd=file:/dev/urandom` to the test JVM. That test setting is not automatically applied to applications using the library.

The authentication protocol requires a REST endpoint that issues challenge nonces as described in section *[6. Add a REST endpoint for issuing challenge nonces](#6-add-a-rest-endpoint-for-issuing-challenge-nonces)*.

Nonce usage is described in more detail in the [Web eID system architecture document](https://github.com/web-eid/web-eid-system-architecture-doc#authentication-1).

## Basic usage

As described in section *[3. Configure the challenge nonce generator](#3-configure-the-challenge-nonce-generator)*, the only mandatory configuration parameter of the challenge nonce generator is the challenge nonce store.

The challenge nonce store is used to save the nonce value along with the nonce expiry time. It must be possible to look up the challenge nonce data structure from the store using an identifier specific to the browser session. The values from the store are used by the token validator as described in the section *[Authentication token validation > Basic usage](#basic-usage)* that also contains recommendations for store usage and configuration.

The nonce generator configuration and construction is described in more detail in section *[3. Configure the challenge nonce generator](#3-configure-the-challenge-nonce-generator)*. Once the generator object has been constructed, it can be used for generating nonces as follows:

```java  
ChallengeNonce challengeNonce = nonceGenerator.generateAndStoreNonce();  
```

The `generateAndStoreNonce()` method both generates the nonce and saves it in the store.

## Extended configuration  

The following additional configuration options are available in `ChallengeNonceGeneratorBuilder`:

- `withNonceTtl(Duration duration)` – overrides the default challenge nonce time-to-live duration. When the time-to-live passes, the nonce is considered to be expired. Default challenge nonce time-to-live is 5 minutes.
- `withSecureRandom(SecureRandom)` - allows to specify a custom `SecureRandom` instance.

Extended configuration example:  
```java  
ChallengeNonceGenerator generator = new ChallengeNonceGeneratorBuilder()
        .withChallengeNonceStore(store)
        .withNonceTtl(Duration.ofMinutes(5))
        .withSecureRandom(customSecureRandom)  
        .build();
```

# Differences between version 1 and version 2

In version 1, the generated challenge nonces were stored in a JSR107 compatible cache. The goal of using a cache was to support stateful and stateless authentication with a universal API that uses the same underlying mechanism. However, in case the website had a CSRF vulnerability, this made the solution vulnerable to [forged login attacks](https://en.wikipedia.org/wiki/Cross-site_request_forgery#Forging_login_requests) (the attacker could trick the victim to submit the authentication token with the attacker's challenge nonce to the website using a CSRF attack, so that the victim was authenticated to the website as the attacker). To mitigate this attack, in version 2 the requirement is that the library adopter must guarantee that the authentication token is received from the same browser to which the corresponding challenge nonce was issued. The recommended solution is to use a session-backed challenge nonce store, as in the code examples above. The library no longer uses the JSR107 cache API and provides a `ChallengeNonceStore` interface instead.

In the internal implementation, the Web eID authentication token format changed in version 2. In version 1, the authentication token was in the OpenID X509 ID Token (JWT) format in order to be compatible with the standard OpenID Connect ID Token specification. During independent security review it was pointed out that any similarities of the Web eID authentication token to the JWT format are actually undesirable, as they would imply that the claims presented in the Web eID authentication token can be trusted and processed, while in fact they must be ignored, as they can be manipulated at the client side. The presence of the claims in the authentication token introduces a risk of vulnerabilities in case the authentication implementer decides to rely on any of them for making security critical decisions or decides to apply the same standard validation workflow that is applied to standard JWTs. Since there does not exist a standardized format for an authentication proof that corresponds to the requirements of the Web eID authentication protocol, a special purpose JSON-based format for the Web eID authentication token was adopted in version 2. The format is described in detail in the section *[Authentication token format](#authentication-token-format)*, and the full analysis of the format change is available in [this article](https://web-eid.github.io/web-eid-system-architecture-doc/web-eid-auth-token-v2-format-spec.pdf).
