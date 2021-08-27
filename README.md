# web-eid-authtoken-validation-java

![European Regional Development Fund](https://github.com/open-eid/DigiDoc4-Client/blob/master/client/images/EL_Regionaalarengu_Fond.png)

*web-eid-authtoken-validation-java* is a Java library for issuing challenge nonces and validating Web eID JWT authentication tokens during secure authentication with electronic ID (eID) smart cards in web applications.

More information about the Web eID project is available on the project [website](https://web-eid.eu/).

# Quickstart

Complete the steps below to add support for secure authentication with eID cards to your Java web application back end. Instructions for the front end are available [here](https://github.com/web-eid/web-eid.js).

A Java web application that uses Maven or Gradle to manage packages is needed for running this quickstart. Examples are for Maven, but they are straightforward to translate to Gradle.

See full example [here](https://github.com/web-eid/web-eid-spring-boot-example).

## 1. Add the library to your project

Add the following lines to Maven `pom.xml` to include the Web eID authentication token validation library in your project:

```xml
<dependencies>
    <dependency>
        <groupId>org.webeid.security</groupId>
        <artifactId>authtoken-validation</artifactId>
        <version>1.0.1</version>
    </dependency>
</dependencies>

<repositories>
    <repository>
        <id>gitlab</id>
        <url>https://gitlab.com/api/v4/projects/19948337/packages/maven</url>
    </repository>
</repositories>
```

## 2. Add cache support

The validation library needs a cache for storing issued challenge nonces. Any JSR107 *javax.cache.Cache* API compatible implementation is suitable, we use [Caffeine](https://github.com/ben-manes/caffeine) here.

Add the following lines to Maven `pom.xml`:

```xml
<properties>
    <caffeine.version>2.8.5</caffeine.version>
    <javaxcache.version>1.1.1</javaxcache.version>
</properties>

<dependencies>
	<dependency>
        <groupId>javax.cache</groupId>
        <artifactId>cache-api</artifactId>
        <version>${javaxcache.version}</version>
    </dependency>
    <dependency>
        <groupId>com.github.ben-manes.caffeine</groupId>
        <artifactId>caffeine</artifactId>
        <version>${caffeine.version}</version>
    </dependency>
    <dependency>
        <groupId>com.github.ben-manes.caffeine</groupId>
        <artifactId>jcache</artifactId>
        <version>${caffeine.version}</version>
    </dependency>
</dependencies>
```

Configure the cache as follows:

```java
import com.github.benmanes.caffeine.jcache.spi.CaffeineCachingProvider;

import javax.cache.Cache;
import javax.cache.CacheManager;
import javax.cache.Caching;
import javax.cache.configuration.CompleteConfiguration;
import javax.cache.configuration.MutableConfiguration;
import javax.cache.expiry.CreatedExpiryPolicy;
import javax.cache.expiry.Duration;
import java.util.concurrent.TimeUnit;

import static javax.cache.configuration.FactoryBuilder.factoryOf;

...
    private static final long NONCE_TTL_MINUTES = 5;
    private static final String CACHE_NAME = "nonceCache";

    private Cache<String, ZonedDateTime> nonceCache() {
        CacheManager cacheManager = Caching.getCachingProvider(CaffeineCachingProvider.class.getName())
            .getCacheManager();
        Cache<String, ZonedDateTime> cache = cacheManager.getCache(CACHE_NAME);

        if (cache == null) {
            cache = createNonceCache(cacheManager);
        }
        return cache;
    }

    private Cache<String, ZonedDateTime> createNonceCache(CacheManager cacheManager) {
        CompleteConfiguration<String, ZonedDateTime> cacheConfig = new MutableConfiguration<String, ZonedDateTime>()
                .setTypes(String.class, ZonedDateTime.class)
                .setExpiryPolicyFactory(factoryOf(new CreatedExpiryPolicy(
                        new Duration(TimeUnit.MINUTES, NONCE_TTL_MINUTES + 1))));
        return cacheManager.createCache(CACHE_NAME, cacheConfig);
    }
...
```

## 3. Configure the nonce generator

The validation library needs to generate authentication challenge nonces and store them in the cache for later validation. Overview of nonce usage is provided in the [Web eID system architecture document](https://github.com/web-eid/web-eid-system-architecture-doc#authentication-1). The nonce generator will be used in the REST endpoint that issues challenges; it is thread-safe and should be scoped as a singleton.

Configure the nonce generator as follows:

```java
import org.webeid.security.nonce.NonceGenerator;
import org.webeid.security.nonce.NonceGeneratorBuilder;

...
    public NonceGenerator nonceGenerator() {
        return new NonceGeneratorBuilder()
                .withNonceCache(nonceCache())
                .build();
    }
...
```

## 4. Add trusted certificate authority certificates

You must explicitly specify which **intermediate** certificate authorities (CAs) are trusted to issue the eID authentication certificates. CA certificates can be loaded from either the truststore file, resources or any stream source. We use the [`CertificateLoader`](https://github.com/web-eid/web-eid-authtoken-validation-java/blob/main/src/test/java/org/webeid/security/testutil/CertificateLoader.java) helper class from [`testutil`](https://github.com/web-eid/web-eid-authtoken-validation-java/tree/main/src/test/java/org/webeid/security/testutil) to load CA certificates from resources here, but consider using [the truststore file](https://github.com/web-eid/web-eid-spring-boot-example/blob/main/src/main/java/org/webeid/example/config/ValidationConfiguration.java#L104-L122) instead.

First, copy the trusted certificates, for example `ESTEID-SK_2015.cer` and `ESTEID2018.cer`, to `resources/cacerts/`, then load the certificates as follows:

```java
import java.security.cert.X509Certificate;

...
    private X509Certificate[] trustedIntermediateCACertificates() {
         return CertificateLoader.loadCertificatesFromResources(
             "cacerts/ESTEID-SK_2015.cer", "cacerts/ESTEID2018.cer");
    }
...
```

## 5. Add trusted OCSP responder certificates

- AIA
- Designated

## 5. Configure the authentication token validator

Once the prerequisites have been met, the authentication token validator itself can be configured.
The mandatory parameters are the website origin (the URL serving the web application), nonce cache and trusted certificate authorities.
The authentication token validator will be used in the login processing component of your web application authentication framework; it is thread-safe and should be scoped as a singleton.

```java
import org.webeid.security.validator.AuthTokenValidator;
import org.webeid.security.validator.AuthTokenValidatorBuilder;

...
    public AuthTokenValidator tokenValidator() throws JceException {
        return new AuthTokenValidatorBuilder()
                .withSiteOrigin("https://example.org")
                .withNonceCache(nonceCache())
                .withTrustedCertificateAuthorities(trustedCertificateAuthorities())
                .build();
    }
...
```

## 6. Add a REST endpoint for issuing challenge nonces

A REST endpoint that issues challenge nonces is required for authentication. The endpoint must support `GET` requests.

In the following example, we are using the [Spring RESTful Web Services framework](https://spring.io/guides/gs/rest-service/) to implement the endpoint, see also full implementation [here](https://github.com/web-eid/web-eid-spring-boot-example/blob/main/src/main/java/org/webeid/example/web/rest/ChallengeController.java).

```java
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
...

@RestController
@RequestMapping("auth")
public class ChallengeController {

    @Autowired // for brevity, prefer constructor dependency injection
    private NonceGenerator nonceGenerator;

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

- implement a custom authentication provider that uses the authentication token validator for authentication as shown [here](https://github.com/web-eid/web-eid-spring-boot-example/blob/main/src/main/java/org/webeid/example/security/AuthTokenDTOAuthenticationProvider.java),
- implement an AJAX authentication processing filter that extracts the authentication token and passes it to the authentication manager as shown [here](https://github.com/web-eid/web-eid-spring-boot-example/blob/main/src/main/java/org/webeid/example/security/WebEidAjaxLoginProcessingFilter.java),
- configure the authentication provider and authentication processing filter in the application configuration as shown [here](https://github.com/web-eid/web-eid-spring-boot-example/blob/main/src/main/java/org/webeid/example/config/ApplicationConfiguration.java).

The gist of the validation is [in the `authenticate()` method](https://github.com/web-eid/web-eid-spring-boot-example/blob/main/src/main/java/org/webeid/example/security/AuthTokenDTOAuthenticationProvider.java#L70-L72) of the authentication provider:

```java
try {
    X509Certificate userCertificate = tokenValidator.validate(token);
    return new PreAuthenticatedAuthenticationToken(
        getPrincipalFromCertificate(userCertificate), null, authorities);
} catch (...) {
    ...
```

# Table of contents

- [Quickstart](#quickstart)
  - [1. Add the library to your project](#1-add-the-library-to-your-project)
  - [2. Add cache support](#2-add-cache-support)
  - [3. Configure the nonce generator](#3-configure-the-nonce-generator)
  - [4. Add trusted certificate authority certificates](#4-add-trusted-certificate-authority-certificates)
  - [5. Configure the authentication token validator](#5-configure-the-authentication-token-validator)
  - [6. Add a REST endpoint for issuing challenge nonces](#6-add-a-rest-endpoint-for-issuing-challenge-nonces)
  - [7. Implement authentication](#7-implement-authentication)
- [Introduction](#introduction)
- [Authentication token validation](#authentication-token-validation)
  - [Basic usage](#basic-usage)
  - [Extended configuration](#extended-configuration)
    - [Certificates' *Authority Information Access* (AIA) extension](#certificates-authority-information-access-aia-extension)
  - [Possible validation errors](#possible-validation-errors)
- [Nonce generation](#nonce-generation)
  - [Basic usage](#basic-usage-1)
  - [Extended configuration](#extended-configuration-1)
- [Frequently asked questions](#frequently-asked-questions)
  - [How can I find the AIA OCSP service URLs?](#how-can-i-find-the-aia-ocsp-service-urls)

# Introduction

The Web eID authentication token validation library for Java contains the  implementation of the Web eID authentication token validation process in its entirety to ensure that the authentication token sent by the Web eID browser extension contains valid, consistent data that has not been modified by a third party. It also implements secure challenge nonce generation as required by the Web eID authentication protocol. It is easy to configure and integrate into your authentication service.

The authentication protocol, validation requirements and nonce usage is described in more detail in the [Web eID system architecture document](https://github.com/web-eid/web-eid-system-architecture-doc#authentication-1).

# Authentication token validation

The authentication token validation process consists of three stages:

- First, the validator parses the **token header** and extracts the user certificate from the *x5c* field. Then it checks the certificate expiration, purpose and policies. Next it checks that the certificate is signed by a trusted CA and checks the certificate status with OCSP.
- Second, the validator validates the **token signature** and parses the **token body**. The signature validator validates that the signature was created using the user certificate that was provided in the header.
- Last, the validator checks the **claims from the token body**. It checks that the token hasn't expired, that the *nonce* field contains a valid challenge nonce that exists in the cache and hasn't expired, and that the *aud* field contains the site origin URL. Optionally, if configured, it also verifies the site TLS certificate fingerprint included in the *aud* field (see *[Extended configuration](#extended-configuration)* below).

The authentication token can be used only once as the corresponding nonce will be removed from the cache during nonce validation. The nonce will also be automatically evicted from the cache when its cache time-to-live expires.

## Basic usage

As described in section *[5. Configure the authentication token validator](#5-configure-the-authentication-token-validator)*, the mandatory configuration parameters are the website origin, nonce cache and trusted certificate authorities.

**Origin** should be the URL serving the web application. Origin URL must be in the form of `"https://" <hostname> [ ":" <port> ]`  as defined in [MDN](https://developer.mozilla.org/en-US/docs/Web/API/Location/origin) and not contain path or query components.

The **nonce cache** instance is used to look up nonce expiry time using its unique value as key. The values in the cache are populated by the nonce generator as described in section *[Nonce generation](#nonce-generation)* below. Consider using [Caffeine](https://github.com/ben-manes/caffeine) or [Ehcache](https://www.ehcache.org/) as the caching provider if your application does not run in a cluster, or [Hazelcast](https://hazelcast.com/), [Infinispan](https://infinispan.org/) or non-Java distributed cahces like [Memcached](https://memcached.org/) or [Redis](https://redis.io/) if it does. Cache configuration is described in more detail in section *[2. Add cache support](#2-add-cache-support)*.

The **trusted certificate authority certificates** are used to validate that the user certificate from the authentication token is signed by a trusted certificate authority. Intermediate CA certificates must be used instead of the root CA certificates so that revoked CA certificates can be detected. Trusted certificate authority certificates configuration is described in more detail in section *[4. Add trusted certificate authority certificates](#4-add-trusted-certificate-authority-certificates)*.

The authentication token validator configuration and construction is described in more detail in section *[5. Configure the authentication token validator](#5-configure-the-authentication-token-validator)*. Once the validator object has been constructed, it can be used for validating authentication tokens as follows:

```java  
X509Certificate userCertificate = tokenValidator.validate(tokenString);  
```

The `validate()` method returns the validated user certificate object if validation is successful or throws an exception as described in section *[Possible validation errors](#possible-validation-errors)* below if validation fails. The `CertUtil` and `TitleCase` classes can be used for extracting user information from the user certificate object:

```java  
import static org.webeid.security.util.TitleCase.toTitleCase;

...
    
CertUtil.getSubjectCN(userCertificate); // "JÕEORG\\,JAAK-KRISTJAN\\,38001085718"
CertUtil.getSubjectIdCode(userCertificate); // "PNOEE-38001085718"
CertUtil.getSubjectCountryCode(userCertificate); // "EE"

toTitleCase(CertUtil.getSubjectGivenName(userCertificate)); // "Jaak-Kristjan"
toTitleCase(CertUtil.getSubjectSurname(userCertificate)); // "Jõeorg"
```

## Extended configuration  

The following additional configuration options are available in `AuthTokenValidatorBuilder`:  

- `withSiteCertificateSha256Fingerprint(String siteCertificateFingerprint)` – turns on origin website certificate fingerprint validation. The validator checks that the site certificate fingerprint from the authentication token matches with the provided site certificate SHA-256 fingerprint. This disables powerful man-in-the-middle attacks where attackers are able to issue falsified certificates for the origin, but also disables TLS proxy usage. Due to the technical limitations of web browsers, certificate fingerprint validation currently works only with Firefox. The provided certificate SHA-256 fingerprint should have the prefix `urn:cert:sha-256:` followed by the hexadecimal encoding of the hash value octets as specified in [URN Namespace for Certificates](https://tools.ietf.org/id/draft-seantek-certspec-01.html). Certificate fingerprint validation is disabled by default.
- `withoutUserCertificateRevocationCheckWithOcsp()` – turns off user certificate revocation check with OCSP. The OCSP URL is extracted from the user certificate AIA extension. OCSP check is enabled by default.
- `withOcspRequestTimeout(Duration ocspRequestTimeout)` – sets both the connection and response timeout of user certificate revocation check OCSP requests. Default is 5 seconds.
- `withAllowedClientClockSkew(Duration allowedClockSkew)` – sets the tolerated clock skew of the client computer when verifying the token expiration. Default value is 3 minutes.
- `withDisallowedCertificatePolicies(ASN1ObjectIdentifier... policies)` – adds the given policies to the list of disallowed user certificate policies. In order for the user certificate to be considered valid, it must not contain any policies present in this list. Contains the Estonian Mobile-ID policies by default as it must not be possible to authenticate with a Mobile-ID certificate when an eID smart card is expected.
- `withNonceDisabledOcspUrls(URI... urls)` – adds the given URLs to the list of OCSP URLs for which the nonce protocol extension will be disabled. Some OCSP services don't support the nonce extension. Contains the ESTEID-2015 OCSP URL by default.

Extended configuration example:  

```java  
AuthTokenValidator validator = new AuthTokenValidatorBuilder()
    .withSiteOrigin("https://example.org")
    .withNonceCache(nonceCache())
    .withTrustedCertificateAuthorities(trustedCertificateAuthorities())
    .withSiteCertificateSha256Fingerprint("urn:cert:sha-256:cert-hash-hex")
    .withoutUserCertificateRevocationCheckWithOcsp()
    .withAllowedClientClockSkew(Duration.ofMinutes(3))
    .withDisallowedCertificatePolicies(new ASN1ObjectIdentifier("1.2.3"))
    .withNonceDisabledOcspUrls(URI.create("http://aia.example.org/cert"))
    .build();
```

### Certificates' *Authority Information Access* (AIA) extension

It is assumed that the AIA extension that contains the certificates’ OCSP service location, is part of both the user and CA certificates. The AIA OCSP URL will be used to check the certificate revocation status with OCSP.

**Note that there may be legal limitations to using AIA URLs during signing** as the services behind these URLs provide different security and SLA guarantees than dedicated OCSP services. For digital signing, OCSP responder certificate validation is additionally needed. Using AIA URLs during authentication is sufficient, however.

## Possible validation errors  

The `validate()` method of `AuthTokenValidator` returns the validated user certificate object if validation is successful or throws an exception if validation fails. All exceptions that can occur during validation derive from `TokenValidationException`, the list of available exceptions is available [here](src/main/java/org/webeid/security/exceptions/). Each exception file contains a documentation comment under which conditions the exception is thrown.

# Nonce generation
The authentication protocol requires support for generating challenge nonces,  large random numbers that can be used only once, and storing them for later use during token validation. The validation library uses the *java.security.SecureRandom* API as the secure random source and the JSR107 *javax.cache.Cache* API for storing issued challenge nonces. 

The `-Djava.security.egd=file:/dev/./urandom` command line argument is added to `pom.xml` to avoid the risk of having the code blocked unexpectedly during random generation. Without this, the JVM uses `/dev/random`, which can block, to seed the `SecureRandom` class.

The authentication protocol requires a REST endpoint that issues challenge nonces as described in section *[6. Add a REST endpoint for issuing challenge nonces](#6-add-a-rest-endpoint-for-issuing-challenge-nonces)*.

Nonce usage is described in more detail in the [Web eID system architecture document](https://github.com/web-eid/web-eid-system-architecture-doc#authentication-1).

## Basic usage  

As described in section *[3. Configure the nonce generator](#3-configure-the-nonce-generator)*, the only mandatory configuration parameter of the nonce generator is the nonce cache.

The nonce cache instance is used to store the nonce expiry time using the nonce value as key. The values in the cache are used by the token validator as described in the section *[Authentication token validation > Basic usage](#basic-usage)* that also contains recommendations for cache usage and configuration.

The nonce generator configuration and construction is described in more detail in section *[3. Configure the nonce generator](#3-configure-the-nonce-generator)*. Once the generator object has been constructed, it can be used for generating nonces as follows:

```java  
String nonce = nonceGenerator.generateAndStoreNonce();  
```

The `generateAndStoreNonce()` method both generates the nonce and stores it in the cache.

## Extended configuration  
The following additional configuration options are available in `NonceGeneratorBuilder`:

- `withNonceTtl(Duration duration)` – overrides the default nonce time-to-live duration. When the time-to-live passes, the nonce is considered to be expired. Default nonce time-to-live is 5 minutes.
- `withSecureRandom(SecureRandom)` - allows to specify a custom `SecureRandom` instance.

Extended configuration example:  
```java  
NonceGenerator generator = new NonceGeneratorBuilder()  
        .withNonceCache(cache)
        .withNonceTtl(Duration.ofMinutes(5))
        .withSecureRandom(customSecureRandom)  
        .build();
```

## Frequently asked questions

### How can I find the AIA OCSP service URLs?

You can find the AIA OCSP service URLs from the electronic ID certificate profile documents, in the section that describes certificate extensions.
The AIA OCSP extension OID is 1.3.6.1.5.5.7.48.1.

For example, the EstEID AIA URLs are specified in the documents
[*Certificate, CRL and OCSP Profile for identification documents of the Republic of Estonia*](https://www.skidsolutions.eu/upload/files/SK-CPR-ESTEID-EN-v8_4-20200630.pdf) and
[*Certificate, CRL and OCSP Profile for ID-1 Format Identity Documents Issued by the Republic of Estonia*](https://www.skidsolutions.eu/upload/files/SK-CPR-ESTEID2018-EN-v1_2_20200630.pdf).
