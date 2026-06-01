# Project Overview

Apache Sling Auth Core (`org.apache.sling.auth.core`) is an OSGi bundle that provides the Sling Authentication Service. It authenticates HTTP requests against a JCR repository via a pluggable `AuthenticationHandler`/`JakartaAuthenticationHandler` SPI. The core component is `SlingAuthenticator`, which delegates to registered handlers matched by path prefix. The bundle supports both legacy `javax.servlet` and Jakarta EE APIs. OSGi components use `org.osgi.service.component.annotations` (DS annotations). Requires Java 17+.

# Core Commands

```bash
# Build and package the OSGi bundle
mvn package

# Build skipping tests
mvn package -DskipTests

# Run full test suite
mvn test

# Run a single test class
mvn test -Dtest=SlingAuthenticatorTest

# Run a single test method
mvn test -Dtest=SlingAuthenticatorTest#testSomeMethod

# Verify (build + test + integration checks)
mvn verify

# Install to local Maven repo
mvn install

# Clean build artifacts
mvn clean package
```

> No dev server — this is an OSGi bundle deployed into a Sling instance. See https://sling.apache.org/documentation/development/sling.html for runtime setup.

# Project Layout

```
pom.xml                          # Maven build descriptor; inherits sling-bundle-parent
bnd.bnd                          # OSGi bundle manifest overrides (optional imports)
src/
  main/java/
    org/apache/sling/auth/core/
      AuthConstants.java         # Shared constants
      AuthUtil.java              # Static utility methods for auth requests
      AuthenticationSupport.java # Service interface for Sling engine integration
      spi/                       # Public SPI: AuthenticationHandler, AuthenticationInfo, etc.
      impl/                      # Internal OSGi components (not part of public API)
        SlingAuthenticator.java  # Core DS component; main authentication logic
        AuthenticationHandlersManager.java
        AuthenticationRequirementsManager.java
        LoginServlet.java
        LogoutServlet.java
        engine/                  # Wrappers for Sling engine (Jakarta) integration
        hc/                      # Felix Health Check integration
    org/apache/sling/engine/auth/ # Deprecated legacy API (kept for compatibility)
  test/java/
    org/apache/sling/auth/core/  # Unit tests mirror main package structure
target/                          # Build output (ignored by git)
```

# Development Patterns & Constraints

- **Java 17**, no preview features.
- **OSGi DS R7** annotations only (`org.osgi.service.component.annotations`). Do not use Felix SCR annotations.
- **No public API in `impl`** packages — `impl.*` is excluded from Javadoc and must not be referenced externally.
- The `spi` package is the stable public API; follow OSGi semantic versioning when changing it (`package-info.java` carries `@Version`).
- Both `javax.servlet` (legacy) and `jakarta.servlet` (Jakarta EE) APIs are supported. New handler code should prefer the Jakarta variants (`JakartaAuthenticationHandler`, etc.).
- Optional OSGi imports declared in `bnd.bnd` (Felix HC, Sling Metrics, JCR) — guard usage with null checks.
- 4-space indentation, no tabs. Follow the existing code style (no Spotless/Checkstyle plugin currently configured; match surrounding code).
- Commit message prefix with Jira issue key: `SLING-XXXXX Description of change`.

# Git Workflow

- Default branch: `master`.
- Feature branches: create from `master`, name with Jira issue key (e.g., `SLING-12345-fix-auth-redirect`).
- PRs are submitted via GitHub to the Apache mirror; upstream is https://gitbox.apache.org/repos/asf/sling-org-apache-sling-auth-core.git.
- Commits must reference an ASF Jira issue. See https://sling.apache.org/contributing.html for the full contribution process.
- Do not push directly to `master`.

# Testing Guidelines

- **Framework**: JUnit 4 + Mockito + `org.apache.sling.testing.osgi-mock` (JUnit 4 variant).
- Test files live under `src/test/java/` mirroring the main source tree.
- OSGi component tests use `OsgiContext` from `osgi-mock` to wire DS components without a real OSGi runtime.
- Run a single class: `mvn test -Dtest=ClassName`.
- Run a single method: `mvn test -Dtest=ClassName#methodName`.
- Coverage report: `mvn test jacoco:report` (if jacoco is inherited from parent POM).
- `impl` classes are internal — test them directly; no need to go through public interfaces.

# Gotchas

- **Optional imports**: `javax.jcr`, Felix HC (`org.apache.felix.hc.api`), and Sling Metrics (`org.apache.sling.commons.metrics`) are optional per `bnd.bnd`. Code using them must handle `NoClassDefFoundError` or check service availability at runtime.
- **Dual servlet API**: Some classes have parallel `javax` and `jakarta` variants. When modifying behavior, check both. The `engine/` subpackage bridges the two.
- **`sling-bundle-parent` POM** (version 66) governs dependency versions and plugin config — do not re-declare managed versions unless overriding intentionally.
- `target/spotless-index` may appear even without explicit Spotless config — it comes from the parent POM; run `mvn spotless:apply` if formatting checks fail in CI.
- The `org.apache.sling.engine.auth` package is a deprecated compatibility shim — do not add new code there.
