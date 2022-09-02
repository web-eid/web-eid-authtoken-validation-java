# web-eid-authtoken-validation-java

![European Regional Development Fund](https://github.com/open-eid/DigiDoc4-Client/blob/master/client/images/EL_Regionaalarengu_Fond.png)

*web-eid-authtoken-validation-java* is a Java library for issuing challenge nonces and validating Web eID authentication tokens during secure authentication with electronic ID (eID) smart cards in web applications.

More information about the Web eID project is available on the project [website](https://web-eid.eu/).

# Quickstart

Complete the steps below to add support for secure authentication with eID cards to your Java web application back end. Instructions for the front end are available [here](https://github.com/web-eid/web-eid.js).

A Java web application that uses Maven or Gradle to manage packages is needed for running this quickstart. Examples are for Maven, but they are straightforward to translate to Gradle.

In the following example we are using the [Spring Framework](https://spring.io/), but the examples can be easily ported to other Java web application frameworks.

See the full example [here](https://github.com/web-eid/web-eid-spring-boot-example).

## 1. Add the library to your project

Add the following lines to Maven `pom.xml` to include the Web eID authentication token validation library in your project:

```xml
<dependencies>
    <dependency>
        <groupId>eu.webeid.security</groupId>
        <artifactId>authtoken-validation</artifactId>
        <version>2.0.1</version>
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
import javax.servlet.http.HttpSession;

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

You must explicitly specify which **intermediate** certificate authorities (CAs) are trusted to issue the eID authentication and OCSP responder certificates. CA certificates can be loaded from either the truststore file, resources or any stream source. We use the [`CertificateLoader`](https://github.com/web-eid/web-eid-authtoken-validation-java/blob/main/src/main/java/eu/webeid/security/certificate/CertificateLoader.java) helper class to load CA certificates from resources here, but consider using [the truststore file](https://github.com/web-eid/web-eid-spring-boot-example/blob/main/src/main/java/eu/webeid/example/config/ValidationConfiguration.java#L104-L123) instead.

First, copy the trusted certificates, for example `ESTEID-SK_2015.cer` and `ESTEID2018.cer`, to `resources/cacerts/`, then load the certificates as follows:

```java
import java.security.cert.X509Certificate;
import eu.webeid.security.certificate.CertificateLoader;

...
    private X509Certificate[] trustedIntermediateCACertificates() {
         return CertificateLoader.loadCertificatesFromResources(
             "cacerts/ESTEID-SK_2015.cer", "cacerts/ESTEID2018.cer");
    }
...
```

## 5. Configure the authentication token validator

Once the prerequisites have been met, the authentication token validator itself can be configured.
The mandatory parameters are the website origin (the URL serving the web application, see section [_Basic usage_](#basic-usage) below) and trusted certificate authorities.
The authentication token validator will be used in the login processing component of your web application authentication framework; it is thread-safe and should be scoped as a singleton.

```java
import eu.webeid.security.validator.AuthTokenValidator;
import eu.webeid.security.validator.AuthTokenValidatorBuilder;

...
    public AuthTokenValidator tokenValidator() throws JceException {
        return new AuthTokenValidatorBuilder()
                .withSiteOrigin("https://example.org")
                .withTrustedCertificateAuthorities(trustedCertificateAuthorities())
                .build();
    }
...
```

## 6. Add a REST endpoint for issuing challenge nonces

A REST endpoint that issues challenge nonces is required for authentication. The endpoint must support `GET` requests.

In the following example, we are using the [Spring RESTful Web Services framework](https://spring.io/guides/gs/rest-service/) to implement the endpoint, see also the full implementation [here](https://github.com/web-eid/web-eid-spring-boot-example/blob/main/src/main/java/org/webeid/example/web/rest/ChallengeController.java).

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
        // a simple DTO with a single 'challenge' field
        final ChallengeDTO challenge = new ChallengeDTO();
        challenge.setNonce(nonceGenerator.generateAndStoreNonce());
        return challenge;
    }
}
```

Also, see general guidelines for implementing secure authentication services [here](https://github.com/SK-EID/smart-id-documentation/wiki/Secure-Implementation-Guide).

## 7. Implement authentication

Authentication consists of calling the `validate()` method of the authentication token validator. The internal implementation of the validation process is described in more detail below and in the [Web eID system architecture document](https://github.com/web-eid/web-eid-system-architecture-doc#authentication-1).

When using [Spring Security](https://spring.io/guides/topicals/spring-security-architecture) with standard cookie-based authentication,

- implement a custom authentication provider that uses the authentication token validator for authentication as shown [here](https://github.com/web-eid/web-eid-spring-boot-example/blob/main/src/main/java/eu/webeid/example/security/AuthTokenDTOAuthenticationProvider.java),
- implement an AJAX authentication processing filter that extracts the authentication token and passes it to the authentication manager as shown [here](https://github.com/web-eid/web-eid-spring-boot-example/blob/main/src/main/java/eu/webeid/example/security/WebEidAjaxLoginProcessingFilter.java),
- configure the authentication provider and authentication processing filter in the application configuration as shown [here](https://github.com/web-eid/web-eid-spring-boot-example/blob/main/src/main/java/eu/webeid/example/config/ApplicationConfiguration.java).

The gist of the validation is [in the `authenticate()` method](https://github.com/web-eid/web-eid-spring-boot-example/blob/main/src/main/java/eu/webeid/example/security/AuthTokenDTOAuthenticationProvider.java#L74-L76) of the authentication provider:

```java
try {
  String nonce = challengeNonceStore.getAndRemove().getBase64EncodedNonce();
  X509Certificate userCertificate = tokenValidator.validate(authToken, nonce);
  return WebEidAuthentication.fromCertificate(userCertificate, authorities);
} catch (AuthTokenException e) {
  ...
```

# Table of contents

- [Quickstart](#quickstart)
- [Introduction](#introduction)
- [Authentication token format](#authentication-token-format)
- [Authentication token validation](#authentication-token-validation)
  - [Basic usage](#basic-usage)
  - [Extended configuration](#extended-configuration)
    - [Certificates' <em>Authority Information Access</em> (AIA) extension](#certificates-authority-information-access-aia-extension)
  - [Possible validation errors](#possible-validation-errors)
  - [Stateful and stateless authentication](#stateful-and-stateless-authentication)
- [Challenge nonce generation](#challenge-nonce-generation)
  - [Basic usage](#basic-usage-1)
  - [Extended configuration](#extended-configuration-1)
- [Upgrading from version 1 to version 2](#upgrading-from-version-1-to-version-2)

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

**Origin** must be the URL serving the web application. Origin URL must be in the form of `"https://" <hostname> [ ":" <port> ]`  as defined in [MDN](https://developer.mozilla.org/en-US/docs/Web/API/Location/origin) and not contain path or query components. Note that the `origin` URL must not end with a slash `/`.

The **trusted certificate authority certificates** are used to validate that the user certificate from the authentication token and the OCSP responder certificate is signed by a trusted certificate authority. Intermediate CA certificates must be used instead of the root CA certificates so that revoked CA certificates can be removed. Trusted certificate authority certificates configuration is described in more detail in section *[4. Add trusted certificate authority certificates](#4-add-trusted-certificate-authority-certificates)*.

Before validation, the previously issued **challenge nonce** must be looked up from the store using an identifier specific to the browser session. The challenge nonce must be passed to the `validate()` method in the corresponding parameter. Setting up the challenge nonce store is described in more detail in section *[2. Configure the challenge nonce store](#2-configure-the-challenge-nonce-store)*. 

The authentication token validator configuration and construction is described in more detail in section *[5. Configure the authentication token validator](#5-configure-the-authentication-token-validator)*. Once the validator object has been constructed, it can be used for validating authentication tokens as follows:

```java  
String challengeNonce = challengeNonceStore.getAndRemove().getBase64EncodedNonce();
WebEidAuthToken token = tokenValidator.parse(tokenString);
X509Certificate userCertificate = tokenValidator.validate(token, challengeNonce);
```

The `validate()` method returns the validated user certificate object if validation is successful or throws an exception as described in section *[Possible validation errors](#possible-validation-errors)* below if validation fails. The `CertificateData` and `TitleCase` classes can be used for extracting user information from the user certificate object:

```java  
import eu.webeid.security.certificate;
import static eu.webeid.security.util.TitleCase.toTitleCase;

...
    
CertificateData.getSubjectCN(userCertificate); // "JÕEORG\\,JAAK-KRISTJAN\\,38001085718"
CertificateData.getSubjectIdCode(userCertificate); // "PNOEE-38001085718"
CertificateData.getSubjectCountryCode(userCertificate); // "EE"

toTitleCase(CertUtil.getSubjectGivenName(userCertificate)); // "Jaak-Kristjan"
toTitleCase(CertUtil.getSubjectSurname(userCertificate)); // "Jõeorg"
```

## Extended configuration  

The following additional configuration options are available in `AuthTokenValidatorBuilder`:  

- `withoutUserCertificateRevocationCheckWithOcsp()` – turns off user certificate revocation check with OCSP. OCSP check is enabled by default and the OCSP responder access location URL is extracted from the user certificate AIA extension unless a designated OCSP service is activated.
- `withDesignatedOcspServiceConfiguration(DesignatedOcspServiceConfiguration serviceConfiguration)` – activates the provided designated OCSP responder service configuration for user certificate revocation check with OCSP. The designated service is only used for checking the status of the certificates whose issuers are supported by the service, for other certificates the default AIA extension service access location will be used. See configuration examples in `testutil.OcspServiceMaker.getDesignatedOcspServiceConfiguration()`.
- `withOcspRequestTimeout(Duration ocspRequestTimeout)` – sets both the connection and response timeout of user certificate revocation check OCSP requests. Default is 5 seconds.
- `withDisallowedCertificatePolicies(ASN1ObjectIdentifier... policies)` – adds the given policies to the list of disallowed user certificate policies. In order for the user certificate to be considered valid, it must not contain any policies present in this list. Contains the Estonian Mobile-ID policies by default as it must not be possible to authenticate with a Mobile-ID certificate when an eID smart card is expected.
- `withNonceDisabledOcspUrls(URI... urls)` – adds the given URLs to the list of OCSP responder access location URLs for which the nonce protocol extension will be disabled. Some OCSP responders don't support the nonce extension. Contains the ESTEID-2015 OCSP responder URL by default.

Extended configuration example:  

```java  
AuthTokenValidator validator = new AuthTokenValidatorBuilder()
    .withSiteOrigin("https://example.org")
    .withTrustedCertificateAuthorities(trustedCertificateAuthorities())
    .withoutUserCertificateRevocationCheckWithOcsp()
    .withDisallowedCertificatePolicies(new ASN1ObjectIdentifier("1.2.3"))
    .withNonceDisabledOcspUrls(URI.create("http://aia.example.org/cert"))
    .build();
```

### Certificates' *Authority Information Access* (AIA) extension

Unless a designated OCSP responder service is in use, it is required that the AIA extension that contains the certificate’s OCSP responder access location is present in the user certificate. The AIA OCSP URL will be used to check the certificate revocation status with OCSP.

Note that there may be limitations to using AIA URLs as the services behind these URLs provide different security and SLA guarantees than dedicated OCSP responder services. In case you need a SLA guarantee, use a designated OCSP responder service.

## Possible validation errors  

The `validate()` method of `AuthTokenValidator` returns the validated user certificate object if validation is successful or throws an exception if validation fails. All exceptions that can occur during validation derive from `AuthTokenException`, the list of available exceptions is available [here](src/main/java/org/webeid/security/exceptions/). Each exception file contains a documentation comment that describes under which conditions the exception is thrown.

## Stateful and stateless authentication

In the code examples above we use the classical stateful Spring Security session cookie-based authentication mechanism, where a cookie that contains the user session ID is set during successful login and session data is stored at sever side. Cookie-based authentication must be protected against cross-site request forgery (CSRF) attacks and extra measures must be taken to secure the cookies by serving them only over HTTPS and setting the _HttpOnly_, _Secure_ and _SameSite_ attributes.

A common alternative to stateful authentication is stateless authentication with JSON Web Tokens (JWT) or secure cookie sessions where the session data resides at the client side browser and is either signed or encrypted. Secure cookie sessions are described in [RFC 6896](https://datatracker.ietf.org/doc/html/rfc6896) and in the following [article about secure cookie-based Spring Security sessions](https://www.innoq.com/en/blog/cookie-based-spring-security-session/). Usage of both an anonymous session and a cache is required to store the challenge nonce and the time it was issued before the user is authenticated. The anonymous session must be used for protection against [forged login attacks](https://en.wikipedia.org/wiki/Cross-site_request_forgery#Forging_login_requests) by guaranteeing that the authentication token is received from the same browser to which the corresponding challenge nonce was issued. The cache must be used for protection against replay attacks by guaranteeing that each authentication token can be used exactly once.


# Challenge nonce generation

The authentication protocol requires support for generating challenge nonces, large random numbers that can be used only once, and storing them for later use during token validation. The validation library uses the *java.security.SecureRandom* API as the secure random source and the `ChallengeNonceStore` interface for storing issued challenge nonces. 

The `-Djava.security.egd=file:/dev/./urandom` command line argument is added to `pom.xml` to avoid the risk of having the code execution blocked unexpectedly during random generation. Without this, the JVM uses `/dev/random`, which can block, to seed the `SecureRandom` class.

The authentication protocol requires a REST endpoint that issues challenge nonces as described in section *[6. Add a REST endpoint for issuing challenge nonces](#6-add-a-rest-endpoint-for-issuing-challenge-nonces)*.

Nonce usage is described in more detail in the [Web eID system architecture document](https://github.com/web-eid/web-eid-system-architecture-doc#authentication-1).

## Basic usage

As described in section *[3. Configure the nonce generator](#3-configure-the-nonce-generator)*, the only mandatory configuration parameter of the challenge nonce generator is the challenge nonce store.

The challenge nonce store is used to save the nonce value along with the nonce expiry time. It must be possible to look up the challenge nonce data structure from the store using an identifier specific to the browser session. The values from the store are used by the token validator as described in the section *[Authentication token validation > Basic usage](#basic-usage)* that also contains recommendations for store usage and configuration.

The nonce generator configuration and construction is described in more detail in section *[3. Configure the nonce generator](#3-configure-the-nonce-generator)*. Once the generator object has been constructed, it can be used for generating nonces as follows:

```java  
ChallengeNonce challengeNonce = nonceGenerator.generateAndStoreNonce();  
```

The `generateAndStoreNonce()` method both generates the nonce and saves it in the store.

## Extended configuration  

The following additional configuration options are available in `NonceGeneratorBuilder`:

- `withNonceTtl(Duration duration)` – overrides the default challenge nonce time-to-live duration. When the time-to-live passes, the nonce is considered to be expired. Default challenge nonce time-to-live is 5 minutes.
- `withSecureRandom(SecureRandom)` - allows to specify a custom `SecureRandom` instance.

Extended configuration example:  
```java  
NonceGenerator generator = new NonceGeneratorBuilder()  
        .withChallengeNonceStore(store)
        .withNonceTtl(Duration.ofMinutes(5))
        .withSecureRandom(customSecureRandom)  
        .build();
```

# Upgrading from version 1 to version 2

Version 2 is a major backwards-incompatible release.

In the `authtoken-validation` library version 1, the generated challenge nonces were stored in a JSR107 compatible cache. The goal of using a cache was to support stateful and stateless authentication with a universal API that uses the same underlying mechanism. However, in case the website had a CSRF vulnerability, this made the solution vulnerable to [forged login attacks](https://en.wikipedia.org/wiki/Cross-site_request_forgery#Forging_login_requests) (the attacker could trick the victim to submit the authentication token with the attacker's challenge nonce to the website using a CSRF attack, so that the victim was authenticated to the website as the attacker). To mitigate this attack, in version 2 the requirement is that the library adopter must guarantee that the authentication token is received from the same browser to which the corresponding challenge nonce was issued. The recommended solution is to use a session-backed challenge nonce store, as in the code examples above. The library no longer uses the JSR107 cache API and provides a `ChallengeNonceStore` interface instead.

A less major backwards-incompatible change was the Maven group ID and package namespace change from `org.webeid` to `eu.webeid` to better reflect the domain of the official project website and focus on European Union eID cards.

In the internal implementation, the Web eID authentication token format changed in version 2. In version 1, the authentication token was in the OpenID X509 ID Token (JWT) format in order to be compatible with the standard OpenID Connect ID Token specification. During independent security review it was pointed out that any similarities of the Web eID authentication token to the JWT format are actually undesirable, as they would imply that the claims presented in the Web eID authentication token can be trusted and processed, while in fact they must be ignored, as they can be manipulated at the client side. The presence of the claims in the authentication token introduces a risk of vulnerabilities in case the authentication implementer decides to rely on any of them for making security critical decisions or decides to apply the same standard validation workflow that is applied to standard JWTs. Since there does not exist a standardized format for an authentication proof that corresponds to the requirements of the Web eID authentication protocol, a special purpose JSON-based format for the Web eID authentication token was adopted in version 2. The format is described in detail in the section *[Authentication token format](#authentication-token-format)*, and the full analysis of the format change is available in [this article](https://web-eid.github.io/web-eid-system-architecture-doc/web-eid-auth-token-v2-format-spec.pdf).

To upgrade from version 1 to version 2,

- replace the library group ID prefix `org.webeid` with `eu.webeid` in the Maven or Gradle project file and upgrade the library version to `2.0.0`,
- replace all code import statements that use `org.webeid` to use `eu.webeid` instead,
- add a session-backed challenge nonce store that implements the `ChallengeNonceStore` interface, as in the code example in the section *[2. Configure the challenge nonce store](#2-configure-the-challenge-nonce-store)* above,
- replace `NonceGenerator` with `ChallengeNonceGenerator` and `NonceGeneratorBuilder` with `ChallengeNonceGeneratorBuilder`,
- replace `withNonceCache(cache)` with `withChallengeNonceStore(store)` in the `ChallengeNonceGenerator` invocation,
- remove `withNonceCache(cache)` from the `AuthTokenValidatorBuilder` invocation,
- to upgrade authentication token validation, as in the code example in the section *[Authentication token validation > Basic usage](#basic-usage)* above,
  - use `challengeNonceStore.getAndRemove().getBase64EncodedNonce()` to retrieve the challenge nonce from the store,
  - use `tokenValidator.parse(tokenString)` to parse the authentication token string into a `WebEidAuthToken` object,
  - pass the token object and challenge nonce string into the `tokenValidator.validate()` method,
- replace `CertUtil` with `CertificateData`.
