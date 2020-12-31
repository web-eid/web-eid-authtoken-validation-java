<!-- @import "[TOC]" {cmd="toc" depthFrom=2 depthTo=6 orderedList=false} -->  
  
# web-eid-authtoken-validation-java

![European Regional Development Fund](https://github.com/e-gov/RIHA-Frontend/raw/master/logo/EU/EU.png)

The Web eID authentication token validation library for Java allows issuing challenge nonces and validating
Web eID JWT authentication tokens during authentication in web applications.

# Quickstart

Complete the steps below to add strong authentication support to your web application back end. Instructions for the font end are available [here](https://github.com/web-eid/web-eid.js).

A Java web application that uses Maven or Gradle to manage packages is needed for running this quickstart.
Examples are for Maven, but they are straightforward to translate to Gradle.

See full example [here](https://github.com/web-eid/web-eid-spring-boot-example).

## 1. Add the library to your project

Add the following lines to Maven `pom.xml` to include the Web eID authentication token validation library in your project:

```xml
    <dependency>
        <groupId>org.webeid.security</groupId>
        <artifactId>authtoken-validation</artifactId>
        <version>1.0.0-SNAPSHOT</version>
    </dependency>

    <repositories>
        <repository>
            <id>gitlab-maven</id>
            <url>https://gitlab.com/api/v4/projects/19948337/packages/maven</url>
        </repository>
    </repositories>
```

## 2. Add cache support

The validation library needs a cache for storing issued authentication tokens. Any *javax.cache.Cache* JSR107 API compatible implementation is suitable, we use Hazelcast here.

Add the following lines to Maven `pom.xml`:

```xml
    <dependency>
        <groupId>javax.cache</groupId>
        <artifactId>cache-api</artifactId>
        <version>1.1.1</version>
    </dependency>
    <dependency>
        <groupId>com.hazelcast</groupId>
        <artifactId>hazelcast</artifactId>
    </dependency>
```

Configure the cache as follows:

```java
import javax.cache.Cache;
import javax.cache.CacheManager;
import javax.cache.Caching;
import javax.cache.configuration.CompleteConfiguration;
import javax.cache.configuration.MutableConfiguration;

...
    private Cache<String, LocalDateTime> nonceCache() {
        CacheManager cacheManager = Caching.getCachingProvider().getCacheManager();
        Cache<String, LocalDateTime> cache = cacheManager.getCache("nonceCache");

        if (cache == null) {
            CompleteConfiguration<String, LocalDateTime> cacheConfig =
                    new MutableConfiguration<String, LocalDateTime>().setTypes(String.class, LocalDateTime.class);
            cache = cacheManager.createCache(CACHE_NAME, cacheConfig);
        }
        return cache;
    }
...
```

## 3. Configure the nonce generator

The validation library needs to generate authentication challenge nonces and store them in the cache when issuing tokens.
The nonce generator will be used in the REST endpoint that issues challenges; it is thread-safe and should be scoped as a singleton.

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

You must explicitly specify which certificate authorities (CAs) are trusted to issue the eID certificates for authentication.
CA certificates can be loaded from either the truststore file or any stream source.
We use the [`CertificateLoader`](https://github.com/web-eid/web-eid-authtoken-validation-java/blob/main/src/test/java/org/webeid/security/testutil/CertificateLoader.java) helper class from [`testutil`](https://github.com/web-eid/web-eid-authtoken-validation-java/tree/main/src/test/java/org/webeid/security/testutil) to load CA certificates from resouces here, but consider using [the truststore file](https://github.com/web-eid/web-eid-spring-boot-example/blob/main/src/main/java/org/webeid/example/config/ValidationConfiguration.java#L104-L122) instead.

First, copy the trusted certificates, for example `ESTEID-SK_2015.cer` and `ESTEID2018.cer`, to `resources/cacerts/`, then load the certificates as follows:

```java
import java.security.cert.X509Certificate;

...
    private X509Certificate[] trustedCertificateAuthorities() {
         return CertificateLoader.loadCertificatesFromResources("cacerts/ESTEID-SK_2015.cer",
                                                                "cacerts/ESTEID2018.cer");
    }
...
```

## 5. Configure the authentication token validator

Once the prerequisites have been met, the authentication token validator itself can be configured.
The minimum parameters are the website origin (the URL where the application is served from), nonce cache and trusted certificate authorities.
The authentication token validator will be used in the login processing component of your web application authentication framework;
it is thread-safe and should be scoped as a singleton.

```java
import org.webeid.security.validator.AuthTokenValidator;
import org.webeid.security.validator.AuthTokenValidatorBuilder;

...
    public AuthTokenValidator validator() {
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

    @Autowired // for brevity
    private NonceGenerator nonceGenerator;

    @GetMapping("challenge")
    public ChallengeDTO challenge() {
        final ChallengeDTO challenge = new ChallengeDTO(); // a simple DTO with a single 'challenge' field
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
    return new PreAuthenticatedAuthenticationToken(getPrincipalFromCertificate(userCertificate), null, authorities);
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
- [Token validation](#token-validation)
  - [Basic usage](#basic-usage)
  - [Configuration](#configuration)
    - [Certificate fingerprint](#certificate-fingerprint)
  - [What gets validated](#what-gets-validated)
  - [Possible validation errors](#possible-validation-errors)
      - [NonceNotFoundException](#noncenotfoundexception)
      - [NonceExpiredException](#nonceexpiredexception)
      - [OriginMismatchException](#originmismatchexception)
      - [ServiceCertificateFingerprintValidationException](#servicecertificatefingerprintvalidationexception)
      - [TokenExpiredException](#tokenexpiredexception)
      - [TokenParseException](#tokenparseexception)
      - [TokenSignatureValidationException](#tokensignaturevalidationexception)
      - [UserCertificateExpiredException](#usercertificateexpiredexception)
      - [UserCertificateMissingPurposeException](#usercertificatemissingpurposeexception)
      - [UserCertificateNotTrustedException](#usercertificatenottrustedexception)
      - [UserCertificateNotYetValidException](#usercertificatenotyetvalidexception)
      - [UserCertificateParseException](#usercertificateparseexception)
      - [UserCertificateRevocationCheckFailException](#usercertificaterevocationcheckfailexception)
      - [UserCertificateRevokedException](#usercertificaterevokedexception)
      - [UserCertificateWrongPurposeException](#usercertificatewrongpurposeexception)
  - [Create your own validator implementation](#create-your-own-validator-implementation)
- [Nonce generation](#nonce-generation)
  - [Basic usage](#basic-usage-1)
  - [Configuration](#configuration-1)
  - [How it works](#how-it-works)

# Introduction

This library has everything that it takes to ensure that the authentication token sent by the Web-eID browser extension contains valid data. And that this data is consistent and was not modified in-between by the third party. It is easy to configure and to integrate into your authentication service.  
  
The library is designed to take advantage of the so-called "builder" pattern to separate the configuration and execution parts from each other.  
  
# Token validation

The token validation process consists of three stages:  
  
- Firstly, the **token header** gets parsed and the user certificate is extracted from the *x5c* field. Then the certificate is checked for validity, expiration and purpose. Also, an optional OCSP check is executed.  
- Secondly, if the user certificate is valid and has a suitable purpose, the **token signature** is checked for validity.  
- Lastly, the **token body** gets parsed. *Nonce* and *Origin* fields get validated. Also, an optional service certificate fingerprint check is executed.   
  
## Basic usage

The builder class need a *javax.cache.Cache* instance (use *Hazelcast* or *Infinispan* if you do use a cluster, or *Caffeine* if you don't):  
```java  
Cache<String, Nonce> cache = // TODO: create new cache instance here  
```  
You will also need to provide issuer certificates:  
```java  
X509Certificate[] trustedCertificateAuthorities = // TODO: load trusted issuer certs  
```  
The **cache** instance is used to look up the nonce object using its unique value as a search key. The values in the cache are populated by the nonce generator (which is described in detail in the *Nonce generation* chapter), while the **trustedCertificateAuthorities** certificates are used to validate the user certificate's trust chain.
  
The simplest way to create a validator instance is to use the builder class with a minimal set of mandatory parameters:  
```java  
AuthTokenValidator validator = new AuthTokenValidatorBuilder("https://my.origin.address")      
        .withNonceCache(cache)    
        .withTrustedCertificateAuthorities(trustedCertificateAuthorities)   
        .build();  
  X509Certificate userCertificate = tokenValidator.validate(myTokenString);  
```  
  
## Configuration  
Additional configuration is possible for the builder class:  
  
- `withCertificateFingerprint(String)` - certificate fingerprint validation is disabled by default, but can be enabled.  
- `withoutCertificateRevocationValidation()` - disables certificate OCSP validation, which is enabled by default.  
- `withAllowedClockSkew(Long)` - allows clock skew in seconds during token parsing process. Default value is **180L**, which corresponds to 3 minutes.  
  
Example:  
```java  
AuthTokenValidator validator = new AuthTokenValidatorBuilder("https://my.origin.address")     
        .withNonceCache(cache)    
        .withTrustedCertificateAuthorities(trustedCertificateAuthorities)   
        .withCertificateFingerprint("urn:cert:sha-256:fingerprint-hash-goes-here")   
        .withoutCertificateRevocationValidation()  
        .withAllowedClockSkew(3600L)
        .build();

X509Certificate userCertificate = tokenValidator.validate(myTokenString);  
```  
  
### Certificate fingerprint  
Due to the technical limitation of Web Browsers, certificate fingerprint validation currently works only when Firefox browser is used.  
  
## What gets validated  
The token validation process covers different aspects. It ensures, that:  
  
- **token header** is valid, contains a valid and trusted certificate, which has not expired and has a proper purpose.  
- **token signature** is not empty, is valid and was created using the certificate, that was specified in the header.  
- **token body** is not empty and has meaningful data.  
- **token** has not expired.  
- **nonce value**, received from the client-side, has the corresponding nonce object in the cache, which has not expired.  
- **Origin URL** is valid and matches the *expected Origin URL* set in builder class. 

**NB!** `Nonce object` is a `Nonce value` plus `metadata` . To know more about it please refer to the *Nonce generation* chapter.
  
## Possible validation errors  
There is a set of possible errors that can occur during the validation process:  
  
#### NonceNotFoundException  
Is thrown if the nonce object is not found from the nonce cache using provided nonce value.  
#### NonceExpiredException  
Is thrown if the nonce object is found but has expired.  
#### OriginMismatchException  
Is thrown if origin URL does not match the *expected origin URL* which was set in builder class.  
#### ServiceCertificateFingerprintValidationException  
Is thrown if the service certificate fingerprint validation is enabled, however, the actual fingerprint does not match the *expected certificate fingerprint* which was set in builder class.  
#### TokenExpiredException  
Is thrown if an expired token is detected and the `withAllowedClockSkew` configuration option does not cover the time difference.
#### TokenParseException  
Is thrown if the token has an invalid format and cannot be parsed.  
#### TokenSignatureValidationException  
Is thrown if the token signature is missing or has an invalid format.  
#### UserCertificateExpiredException  
Is thrown if the user certificate's validity period end date is in the past. 
#### UserCertificateMissingPurposeException
Is thrown if the purpose of the user certificate is not defined.
#### UserCertificateNotTrustedException  
Is thrown if the user certificate is not trusted.  
#### UserCertificateNotYetValidException  
Is thrown if the user certificate's validity period start date is in the future.  
#### UserCertificateParseException  
Is thrown if the user certificate cannot be parsed from the token's x5c field.  
#### UserCertificateRevocationCheckFailException  
Is thrown if the user certificate OCSP check has failed.  
#### UserCertificateRevokedException  
Is thrown if the user certificate OCSP check's result is not GOOD.  
#### UserCertificateWrongPurposeException  
Is thrown if according to the user certificate's purpose is not meant to be used for authentication.  
  
## Create your own validator implementation  
It is possible to create a custom implementation of the token validator. To achieve this, you have to:

- Create a new validator class, which extends the `AuthTokenValidator` interface.
- Create a new builder class, which extends the `AuthTokenValidatorBuilder` class and overrides the `build()` method to create an instance of your new validator class.

**MyCustomTokenValidator.java**
```java
class MyCustomTokenValidator implements AuthTokenValidator {
    ...
}
```
**MyCustomBuilder.java**
```java
class MyCustomBuilder extends AuthTokenValidatorBuilder {
    @Override
    public AuthTokenValidator build() {
        ...
        validateParameters();
        return new MyCustomTokenValidator(...);
    }
    ...
}
```

Additionally, you can override the `validateParameters()` method in case you need to add new fields and validate them:


**MyCustomBuilder.java**
```java
class MyCustomBuilder extends AuthTokenValidatorBuilder {
    
    private String myNewField = "";
    
    private MyCustomBuilder withMyNewField(String myNewField) {
        this.myNewField = myNewField;
    }

    @Override
    public AuthTokenValidator build() {
        validateParameters();
        return new MyCustomTokenValidator(..., myNewField);
    }
    
    @Override  
    protected void validateParameters() {  
        super.validateParameters();  
        Objects.requireNonNull(myNewField, "My new field must not be null");
    }
    ...
}
```
Then use it in your application:
```java
MyCustomTokenValidator validator = new MyCustomBuilder("https://my.origin.address")      
        .withNonceCache(cache)    
        .withTrustedCertificateAuthorities(trustedCertificateAuthorities) 
        .withMyNewField("My new field value")
        .build();  

X509Certificate certificate = validator.validate(myTokenString);
```

# Nonce generation
Nonce value generation is implemented similarly to the token validation - it also uses the builder pattern and also requires the cache instance. 

## Basic usage  
  
The builder class will need a *javax.cache.Cache* instance (use *Hazelcast* or *Infinispan* if you do use a cluster, or *Caffeine* if you don't):  
```java  
Cache<String, Nonce> cache = // TODO: create new cache instance here  
```  

The **cache** is used store nonce objects. 
  
The simplest way to create a generator instance is to use the builder class with a minimal set of mandatory parameters:  

```java
NonceGenerator generator = new NonceGeneratorBuilder()  
        .withNonceCache(cache)  
        .build();

byte[] nonceKey = nonceGenerator.generate();
```
The`generate()` method also puts the generated nonce object into the provided cache.

## Configuration  
Additional configuration is possible for the builder class:  
  
- `withNonceTtl(int)` - specifies the time-to-live in minutes. Default value is 5.
- `withSecureRandom(SecureRandom)` - allows to specify a custom [SecureRandom](https://docs.oracle.com/javase/8/docs/api/java/security/SecureRandom.html) class instance.
  
Example:  
```java  
NonceGenerator generator = new NonceGeneratorBuilder()  
        .withNonceCache(cache)
        .withNonceTtl(10)
        .withSecureRandom(myCustomSecureRandomInstance)  
        .build();

byte[] nonceKey = nonceGenerator.generate();  
```  
## How it works
Here are some useful facts:

- Nonce objects are stored into the cache on the server-side and later are looked up from the same cache using the nonce values as keys.
- Nonce values are sent to the client-side, nonce objects are not.
- Every nonce value is meant to be unique and as less likely reproducible as possible.
- Every nonce object is meant to be used only once.
- Every nonce object is meant to be used before it expires.
