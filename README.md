[![Apache Sling](https://sling.apache.org/res/logos/sling.png)](https://sling.apache.org)

&#32;[![Build Status](https://ci-builds.apache.org/job/Sling/job/modules/job/sling-org-apache-sling-auth-core/job/master/badge/icon)](https://ci-builds.apache.org/job/Sling/job/modules/job/sling-org-apache-sling-auth-core/job/master/)&#32;[![Test Status](https://img.shields.io/jenkins/tests.svg?jobUrl=https://ci-builds.apache.org/job/Sling/job/modules/job/sling-org-apache-sling-auth-core/job/master/)](https://ci-builds.apache.org/job/Sling/job/modules/job/sling-org-apache-sling-auth-core/job/master/test/?width=800&height=600)&#32;[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=apache_sling-org-apache-sling-auth-core&metric=coverage)](https://sonarcloud.io/dashboard?id=apache_sling-org-apache-sling-auth-core)&#32;[![Sonarcloud Status](https://sonarcloud.io/api/project_badges/measure?project=apache_sling-org-apache-sling-auth-core&metric=alert_status)](https://sonarcloud.io/dashboard?id=apache_sling-org-apache-sling-auth-core)&#32;[![JavaDoc](https://www.javadoc.io/badge/org.apache.sling/org.apache.sling.auth.core.svg)](https://www.javadoc.io/doc/org.apache.sling/org.apache.sling.auth.core)&#32;[![Maven Central](https://maven-badges.herokuapp.com/maven-central/org.apache.sling/org.apache.sling.auth.core/badge.svg)](https://search.maven.org/#search%7Cga%7C1%7Cg%3A%22org.apache.sling%22%20a%3A%22org.apache.sling.auth.core%22)&#32;[![auth](https://sling.apache.org/badges/group-auth.svg)](https://github.com/apache/sling-aggregator/blob/master/docs/groups/auth.md) [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

# Apache Sling Authentication Service

This module is part of the [Apache Sling](https://sling.apache.org) project.

The Sling Authentication Service bundle provides the basic mechanisms to authenticate HTTP requests with a JCR repository. Authentication detail extraction is extensible through the Authentication Handler SPI (`AuthenticationHandler` and `JakartaAuthenticationHandler`).

This module targets Java 17+ and OSGi Declarative Services (R7 annotations).

## Installation

This bundle should be installed into an OSGi framework together with the Apache Sling Framework.
Beyond Apache Sling it requires:
- Apache Commons Codec 1.13+

Optional integrations (if available in the runtime):
- Apache Sling Commons Metrics 1.2.8+
- Apache Felix Health Check API 2.0.0+
- Apache Sling JCR API 2.0.4+

## Build

```bash
mvn package
```

Useful commands:

```bash
mvn test
mvn verify
mvn package -DskipTests
mvn clean package
mvn install
```

## API and Runtime Notes

- Supports both legacy `javax.servlet` (4.0.1) and Jakarta Servlet (`jakarta.servlet` 6.1.0) based authentication handlers.
- Internal implementation classes live in `org.apache.sling.auth.core.impl`; public SPI is in `org.apache.sling.auth.core.spi`.
- Metrics, health check, and some JCR-related packages are imported as optional OSGi dependencies.

## Project Structure

```text
pom.xml
bnd.bnd
src/
  main/java/org/apache/sling/auth/core/
    spi/
    impl/
      engine/
      hc/
  test/java/org/apache/sling/auth/core/
```
