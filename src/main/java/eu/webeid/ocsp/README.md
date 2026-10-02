# Advanced OCSP configuration

[Back to the main README](../../../../../../README.md#authentication-token-validation)

The default validator uses platform OCSP and needs no additional OCSP configuration. This guide is for applications that need control over responder selection, HTTP transport, nonce handling, response freshness or a different revocation-checking implementation.

Use `withCertificateRevocationChecker(...)` to supply your own implementation or configure the bundled `eu.webeid.ocsp.OcspCertificateRevocationChecker`. Use `withPKIXRevocationChecker(...)` when you need to configure a JDK PKIX checker directly.

## Contents

- [Choosing a revocation checker](#choosing-a-revocation-checker)
- [Implementing CertificateRevocationChecker](#implementing-certificaterevocationchecker)
- [Custom OCSP checker](#custom-ocsp-checker)
- [Custom PKIX revocation checker](#custom-pkix-revocation-checker)
- [Platform OCSP timeouts](#platform-ocsp-timeouts)
- [Platform OCSP nonce configuration](#platform-ocsp-nonce-configuration)
- [Certificates' Authority Information Access (AIA) extension](#certificates-authority-information-access-aia-extension)
- [Revocation information](#revocation-information)
- [Errors and diagnostics](#errors-and-diagnostics)

## Choosing a revocation checker

The default mode is `PLATFORM_OCSP`: the library uses the platform PKIX revocation checker to check the subject certificate with OCSP, with no fallback to CRLs and no soft-fail option. Trust is validated before revocation checking.

`PLATFORM_OCSP` checks only the subject certificate's revocation status. In `CUSTOM_CHECKER` mode, the library invokes the supplied checker once for the subject certificate. Neither mode automatically checks intermediate CA certificates for revocation, although both validate the certification path. A custom PKIX checker follows its own configured options.

The following additional configuration options are available in `AuthTokenValidatorBuilder`:

- `withPlatformOcspNonceEnabled(boolean enabled)` – controls the library's default nonce generation for `PLATFORM_OCSP`. Enabled by default; an explicit JVM nonce property takes precedence. See [Platform OCSP nonce configuration](#platform-ocsp-nonce-configuration).
- `withPKIXRevocationChecker(PKIXRevocationChecker checker)` – selects `CUSTOM_PKIX` and uses the supplied checker with its configured options.
- `withCertificateRevocationChecker(CertificateRevocationChecker checker)` – selects `CUSTOM_CHECKER` and delegates revocation checking to the supplied implementation after validating certificate trust.
- `withoutUserCertificateRevocationCheck()` – selects `DISABLED`. Certificate trust, validity, purpose, policies and token signatures are still checked, but revocation status is not, so revoked certificates may be accepted. Use only in exceptional circumstances.

The two custom checker options and `withoutUserCertificateRevocationCheck()` are mutually exclusive. Combining them causes `build()` to throw `IllegalArgumentException`. Custom checker implementations must support concurrent validation calls.

Platform OCSP networking and response freshness are controlled by the JDK provider; see [Platform OCSP timeouts](#platform-ocsp-timeouts). The v3 API builder-level OCSP client, timeout, designated-service and response-age options are no longer available; use the custom OCSP checker below when those controls are needed. Its timing constants do not configure the platform checker.

## Implementing CertificateRevocationChecker

Implement [CertificateRevocationChecker](../security/validator/revocationcheck/CertificateRevocationChecker.java) and supply it through `AuthTokenValidatorBuilder.withCertificateRevocationChecker(...)`. This extension point can use your own revocation service, transport or validation policy.

The library calls `validateCertificateNotRevoked(subjectCertificate, issuerCertificate)` after validating the subject certificate's trust, validity, purpose and policies. The issuer argument is the subject certificate's direct issuer from the validated certification path. With `AuthTokenValidatorBuilder`, every configured trusted CA is also a trust anchor, so a trusted direct issuer terminates the path. Applications calling `CertificateValidator` directly can supply separate anchors and intermediate certificates, giving a direct issuer below the trust anchor. The library validates token signature after revocation check.

Your checker must:

- Validate revocation status according to your application's policy, including the authenticity and freshness of any status information it uses.
- Throw `CertificateRevokedException` when the certificate is revoked, or `CertificateRevocationCheckFailedException` when the status cannot be established. Both extend `AuthTokenException`; retain the underlying cause when available.
- Return a non-null `List<RevocationInfo>` on success. Use an empty list when there is no additional information to return.
- Support concurrent calls when the validator is shared across threads.

The platform nonce setting does not configure your implementation. The bundled checker below is available when you want OCSP-specific controls without implementing the protocol yourself.

## Custom OCSP checker

The examples use `trustedIntermediateCACertificates()` from the [main quickstart](../../../../../../README.md#4-add-trusted-certificate-authority-certificates). Run configuration code during application startup and handle its checked exceptions there.

The Bouncy Castle-based implementation is available under `eu.webeid.ocsp`. Construct it explicitly and pass it to `withCertificateRevocationChecker(...)`:

```java
import java.net.URI;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import eu.webeid.ocsp.OcspCertificateRevocationChecker;
import eu.webeid.ocsp.client.OcspClientImpl;
import eu.webeid.ocsp.service.AiaOcspServiceConfiguration;
import eu.webeid.ocsp.service.OcspServiceProvider;
import eu.webeid.security.certificate.CertificateValidator;
import eu.webeid.security.validator.AuthTokenValidator;
import eu.webeid.security.validator.AuthTokenValidatorBuilder;

...
List<X509Certificate> trustedCAs = List.of(trustedIntermediateCACertificates());
AiaOcspServiceConfiguration aiaConfiguration = new AiaOcspServiceConfiguration(
    Set.of(), // AIA responder URLs for which request and response nonce checks are disabled.
    CertificateValidator.buildTrustAnchorsFromCertificates(trustedCAs),
    CertificateValidator.buildCertStoreFromCertificates(trustedCAs),
    OcspCertificateRevocationChecker.DEFAULT_THIS_UPDATE_AGE,
    OcspCertificateRevocationChecker.DEFAULT_NEXT_UPDATE_AGE
);
OcspServiceProvider services = new OcspServiceProvider(null, aiaConfiguration);
OcspCertificateRevocationChecker checker = new OcspCertificateRevocationChecker(
    OcspClientImpl.build(Duration.ofSeconds(5)),
    services,
    OcspCertificateRevocationChecker.DEFAULT_TIME_SKEW
);

AuthTokenValidator validator = new AuthTokenValidatorBuilder()
    .withSiteOrigin(URI.create("https://example.org"))
    .withTrustedCertificateAuthorities(trustedCAs.toArray(X509Certificate[]::new))
    .withCertificateRevocationChecker(checker)
    .build();
```

The five-second connection and response timeout above is an explicit example setting. For a custom Java `HttpClient`, use `new OcspClientImpl(httpClient, responseTimeout)` and configure the connection timeout on that client. Alternatively, supply your own `OcspClient` implementation. See [OcspClientOverrideTest](../../../../../test/java/eu/webeid/ocsp/client/OcspClientOverrideTest.java).

The custom checker's suggested constant for clock/update skew is 15 minutes; pass a different positive duration to its constructor to change it.

The maximum ages of the OCSP response's `thisUpdate` and `nextUpdate` times are configured per OCSP service, via the constructor of `AiaOcspServiceConfiguration`, `DesignatedOcspServiceConfiguration` or `FallbackOcspServiceConfiguration`:

- `maxThisUpdateAge` – the maximum age of the OCSP response's `thisUpdate` time before the response is too old to rely on. `OcspCertificateRevocationChecker.DEFAULT_THIS_UPDATE_AGE` is 2 minutes.
- `maxNextUpdateAge` – the maximum age of the OCSP response's `nextUpdate` time before the response is too old to rely on. `OcspCertificateRevocationChecker.DEFAULT_NEXT_UPDATE_AGE` is 15 minutes, which is equal to the default allowed time skew.

These checks are implemented by [OcspResponseValidator](protocol/OcspResponseValidator.java).

For a designated responder, replace the `services` definition above with the following configuration. `responderCertificate` must be the service's trusted signing certificate and `supportedIssuers` the collection of issuer certificates served by it:

```java
import eu.webeid.ocsp.service.DesignatedOcspServiceConfiguration;

...
DesignatedOcspServiceConfiguration designated = new DesignatedOcspServiceConfiguration(
    URI.create("https://ocsp.example.org"),
    responderCertificate,
    supportedIssuers,
    true, // This service supports nonces.
    OcspCertificateRevocationChecker.DEFAULT_THIS_UPDATE_AGE,
    OcspCertificateRevocationChecker.DEFAULT_NEXT_UPDATE_AGE
);
OcspServiceProvider services = new OcspServiceProvider(designated, aiaConfiguration);
```

The provider selects the designated service only when the validated direct issuer certificate equals one of its configured `supportedIssuers`. Supply the same encoded issuer certificates that validation may select as direct issuers; a reissued CA certificate with the same name and key does not match. On a mismatch, the provider uses the certificate's AIA OCSP URL. The designated responder certificate is pinned locally and need not be issued by the CAs it serves.

For AIA services, the response may be signed by the certificate's direct issuer CA itself, or by a delegated responder certificate signed directly by that CA with the OCSP-signing extended key usage. Nonce support is enabled unless the URL appears in the first argument of `AiaOcspServiceConfiguration`. When nonce support is enabled, this custom checker requires a matching response nonce and rejects its absence. Its nonce policy is independent of the platform builder setting and JVM nonce property.

## Custom PKIX revocation checker

Configure the checker explicitly, including its fallback policy. For example, to use a fixed responder while retaining OCSP-only checking of the subject certificate:

```java
import java.net.URI;
import java.security.cert.CertPathValidator;
import java.security.cert.PKIXRevocationChecker;
import java.util.EnumSet;
import eu.webeid.security.validator.AuthTokenValidator;
import eu.webeid.security.validator.AuthTokenValidatorBuilder;

...
PKIXRevocationChecker checker = (PKIXRevocationChecker)
    CertPathValidator.getInstance("PKIX").getRevocationChecker();
checker.setOptions(EnumSet.of(
    PKIXRevocationChecker.Option.ONLY_END_ENTITY,
    PKIXRevocationChecker.Option.NO_FALLBACK
));
checker.setOcspResponder(URI.create("https://ocsp.example.org"));

AuthTokenValidator validator = new AuthTokenValidatorBuilder()
    .withSiteOrigin(URI.create("https://example.org"))
    .withTrustedCertificateAuthorities(trustedIntermediateCACertificates())
    .withPKIXRevocationChecker(checker)
    .build();
```

The library does not add options or nonce extensions to a custom PKIX checker. `withPlatformOcspNonceEnabled(...)` does not apply to it. A responder set with `setOcspResponder()` overrides AIA discovery for certificates checked by that checker; it does not perform issuer-based responder selection. Use the [custom OCSP service provider](#custom-ocsp-checker) for that policy.

## Platform OCSP timeouts

On current OpenJDK/Oracle JDK 17, set connection and read timeouts through JVM system properties at application startup, for example:

```text
-Dcom.sun.security.ocsp.timeout=5s
-Dcom.sun.security.ocsp.readtimeout=5s
```

`com.sun.security.ocsp.timeout` controls connection establishment; `com.sun.security.ocsp.readtimeout` controls reads after connecting. A bare number or a value ending in `s` means seconds; `ms` means milliseconds. For example, `3`, `3s`, and `3000ms` all mean three seconds, while `3000` means 50 minutes. The default connection timeout is 15 seconds, and the read timeout defaults to the connection timeout. Zero means an infinite timeout.

These settings apply JVM-wide to the JDK OCSP implementation, including custom PKIX checkers using that provider. They are read when the JDK OCSP classes initialize and are not an overall deadline for authentication. They do not configure the bundled custom OCSP client's timeouts.

## Platform OCSP nonce configuration

By default, the library includes a fresh 32-byte nonce in each platform OCSP request. To disable this default for a validator, use:

```java
AuthTokenValidator validator = new AuthTokenValidatorBuilder()
    .withSiteOrigin(URI.create("https://example.org"))
    .withTrustedCertificateAuthorities(trustedIntermediateCACertificates())
    .withPlatformOcspNonceEnabled(false)
    .build();
```

An explicitly configured `jdk.security.certpath.ocspNonce` JVM system property takes precedence over the builder setting:

| Builder setting | JVM property unset | JVM property `true` | JVM property `false` |
| --- | --- | --- | --- |
| Enabled (default) | Library supplies a fresh 32-byte nonce | JDK supplies the nonce | No nonce |
| Disabled | No nonce | JDK supplies the nonce | No nonce |

For example, `-Djdk.security.certpath.ocspNonce=false` disables nonces for this library's platform OCSP requests regardless of the builder setting. The JVM property also affects other users of the JDK OCSP implementation in the same process. The library reads this property without modifying it.

The builder setting applies only to `PLATFORM_OCSP`; it does not configure custom revocation checkers. Enabling a nonce controls the request, not strict response nonce enforcement: the JDK may accept a response without a nonce. This OCSP setting is separate from the authentication challenge nonce.

## Certificates' *Authority Information Access* (AIA) extension

The default platform checker obtains the OCSP responder URL from the subject certificate’s AIA extension unless a JDK responder override is configured. A custom PKIX checker can override the URL with `setOcspResponder()`. The bundled custom OCSP checker requires an AIA OCSP URL unless its designated service supports the certificate’s issuer.

Note that there may be limitations to using AIA URLs as the services behind these URLs provide different security and SLA guarantees than dedicated OCSP responder services. In case you need a SLA guarantee, use a designated OCSP responder service.

## Revocation information

The `validate()` method returns a `ValidationInfo` object on success and throws an exception on failure, as described in [Errors and diagnostics](#errors-and-diagnostics). Its `subjectCertificate()` accessor returns the validated certificate. Its `revocationInfoList()` accessor returns information supplied by the selected revocation checker:

- `PLATFORM_OCSP` and `DISABLED` return an empty list. An empty list does not mean that validation failed or, in platform mode, that revocation checking was skipped.
- `CUSTOM_PKIX` returns the configured responder URI when `getOcspResponder()` is non-null; response attributes are not populated.
- `CUSTOM_CHECKER` returns the custom checker's result. The bundled `OcspCertificateRevocationChecker` includes the responder URI and the Bouncy Castle `OCSPResp` under `RevocationInfo.KEY_OCSP_RESPONSE`.

## Errors and diagnostics

The `validate()` method returns `ValidationInfo` on success. Certificate and token validation failures are reported through `AuthTokenException` subclasses. In particular:

| Exception | Meaning |
| --- | --- |
| `CertificateNotTrustedException` | Certificate trust/path validation failed. |
| `CertificateRevokedException` | The checker reported that the certificate is revoked. |
| `CertificateRevocationCheckFailedException` | The revocation status could not be established, for example because of an OCSP service or network failure. |

These classes are in `eu.webeid.security.exceptions`. The bundled custom checker's `UserCertificateRevokedException` and `UserCertificateOCSPCheckFailedException` extend the corresponding common classes. Other validation errors, including expired certificates and invalid token signatures, are documented in the [exception classes](../security/exceptions).

During revocation checking, invalid responder certificates (including an unexpected designated responder, missing OCSP signing usage, expiry, or untrusted certificates) produce `UserCertificateOCSPCheckFailedException`, with the detailed certificate error retained as its cause. Invalid certificates supplied during designated-service configuration can instead throw `OCSPCertificateException` at application startup, before any revocation check runs.

Log the exception itself to retain the cause chain, including the JDK's revocation failure details:

```java
try {
    ValidationInfo validationInfo = tokenValidator.validate(token, challengeNonce);
    // Continue authentication using validationInfo.subjectCertificate().
} catch (AuthTokenException e) {
    LOG.warn("Web eID authentication failed", e);
    throw e;
}
```

Preserve the cause when wrapping the exception, for example with `new AuthenticationServiceException("Web eID token validation failed", e)`. Return a generic authentication failure to the client; keep diagnostic details in server logs.
