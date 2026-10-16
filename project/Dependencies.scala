import sbt.*

object Dependencies {

  private object Versions {

    // --- ZIO ecosystem ---
    val zio        = "2.1.26"
    val zioJson    = "1.1.0"
    val zioHttp    = "3.11.6"
    val zioLogging = "2.5.3"
    val zioConfig  = "4.1.0"
    val zioSchema  = "1.9.0"
    val zioKafka   = "3.8.0"

    // --- HTTP ---
    val http4s  = "0.23.38"
    val sttp4   = "4.0.25"
    val tapir   = "1.13.18"
    val jsonRpc = "0.2.0"

    // --- JSON ---
    val jsoniter = "2.41.2"
    val circe    = "0.14.16"
    val jackson3 = "3.2.2"

    // --- FP ---
    val catsEffect      = "3.7.1"
    val fs2             = "3.14.0"
    val fs2Kafka        = "4.1.1"
    val chimney         = "2.0.0"
    val iron            = "3.3.2"
    val hedgehog        = "0.13.0"
    val scalacheck      = "1.20.0"
    val munit           = "1.3.6"
    val munitCatsEffect = "2.2.1"

    // --- DB ---
    val quill    = "4.8.6"
    val magnum   = "2.0.0-M3"
    val skunk    = "2.0.0-RC3"
    val hikaricp = "7.1.0"
    val flyway   = "13.8.0"
    val postgres = "42.7.13"

    // --- Security ---
    val jwtScala         = "11.0.4"
    val bouncycastle     = "1.84"
    val password4j       = "1.8.4"
    val auth0            = "4.6.1"
    val nimbusJoseJwt    = "10.10"
    val nimbusOauth2Oidc = "11.38.2"
    val vault            = "5.1.0"
    val webauthn         = "2.10.0"
    val authlete         = "4.48"

    // --- Logging ---
    val scribe  = "3.19.0"
    val slf4j   = "2.0.20"
    val logback = "1.6.4"

    // --- Cache ---
    val caffeine = "3.3.0"
    val jedis    = "8.0.1"

    // --- Directory ---
    val unboundid = "7.0.5"

    val zxing = "3.5.4"

    // --- Mail ---
    val angusMail   = "2.0.5"
    val jakartaMail = "2.1.5"

    // --- Observability ---
    val micrometer = "1.17.1"
    val datadog    = "2.60.0"
    val kamon      = "2.8.1"
    val otel4s     = "1.1.0"

    // --- Config ---
    val pureconfig = "0.17.10"

    // --- Cloud ---
    val awsV2         = "2.26.15"
    val azureIdentity = "1.18.6"
    val azureKv       = "4.9.4"

  }

  // Helpers
  private def http4s(a: String) =
    "org.http4s" %% s"http4s-$a" % Versions.http4s

  private def tapirDep(a: String) =
    "com.softwaremill.sttp.tapir" %% s"tapir-$a" % Versions.tapir

  private def sttpDep(a: String) =
    "com.softwaremill.sttp.client4" %% a % Versions.sttp4

  private def circeDep(a: String) =
    "io.circe" %% s"circe-$a" % Versions.circe

  // Reusable across modules as-is
  val catsEffect = Seq("org.typelevel" %% "cats-effect" % Versions.catsEffect)
  val fs2        = Seq("co.fs2" %% "fs2-core" % Versions.fs2)
  val fs2Kafka   = Seq("org.typelevel" %% "fs2-kafka" % Versions.fs2Kafka)
  val chimney    = Seq("io.scalaland" %% "chimney" % Versions.chimney)
  val caffeine   = Seq("com.github.ben-manes.caffeine" % "caffeine" % Versions.caffeine)
  val jedis      = Seq("redis.clients" % "jedis" % Versions.jedis)
  val jsonRpc    = Seq("tech.neander" %% "jsonrpclib-fs2" % Versions.jsonRpc)
  val unboundid  = Seq("com.unboundid" % "unboundid-ldapsdk" % Versions.unboundid)
  val zxing      = Seq("com.google.zxing" % "core" % Versions.zxing)

  // Small libraries the app uses directly
  val misc = Seq(
    "net.minidev"       % "json-smart"        % "2.6.0",
    "com.cronutils"     % "cron-utils"        % "9.2.1",
    "org.yaml"          % "snakeyaml"         % "2.7",
    "javax.validation"  % "validation-api"    % "2.0.1.Final",
    "commons-validator" % "commons-validator" % "1.11.0"
  )

  object zio {

    val core = Seq(
      "dev.zio" %% "zio"          % Versions.zio,
      "dev.zio" %% "zio-test"     % Versions.zio % Test,
      "dev.zio" %% "zio-test-sbt" % Versions.zio % Test
    )

    val json = Seq(
      "dev.zio" %% "zio-json"        % Versions.zioJson,
      "dev.zio" %% "zio-json-golden" % Versions.zioJson % Test
    )

    val http = Seq("dev.zio" %% "zio-http" % Versions.zioHttp)

    val logging = Seq(
      "dev.zio" %% "zio-logging"       % Versions.zioLogging,
      "dev.zio" %% "zio-logging-slf4j" % Versions.zioLogging
    )

    val config = Seq(
      "dev.zio" %% "zio-config"          % Versions.zioConfig,
      "dev.zio" %% "zio-config-magnolia" % Versions.zioConfig,
      "dev.zio" %% "zio-config-typesafe" % Versions.zioConfig
    )

    val schema = Seq(
      "dev.zio" %% "zio-schema"            % Versions.zioSchema,
      "dev.zio" %% "zio-schema-json"       % Versions.zioSchema,
      "dev.zio" %% "zio-schema-derivation" % Versions.zioSchema,
      "dev.zio" %% "zio-schema-protobuf"   % Versions.zioSchema
    )

    val kafka = Seq("dev.zio" %% "zio-kafka" % Versions.zioKafka)

  }

  object http4s {

    val core  = Seq(http4s("dsl"), http4s("ember-server"), http4s("ember-client"))
    val circe = Seq(http4s("circe"))

  }

  object sttp {

    val core     = Seq(sttpDep("core"))
    val cats     = Seq(sttpDep("cats"))
    val fs2      = Seq(sttpDep("fs2"))
    val jsoniter = Seq(sttpDep("jsoniter"))
    val circe    = Seq(sttpDep("circe"))

    val backends = Seq(
      sttpDep("slf4j-backend"),
      sttpDep("okhttp-backend"),
      sttpDep("prometheus-backend"),
      sttpDep("scribe-backend"),
      sttpDep("async-http-client-backend-fs2"),
      sttpDep("http4s-backend"),
      sttpDep("zio")
    )

  }

  object tapir {

    val core = Seq(
      tapirDep("core"),
      tapirDep("http4s-server"),
      tapirDep("jsoniter-scala"),
      tapirDep("openapi-docs")
    )

    val extras = Seq(tapirDep("swagger-ui-bundle"), tapirDep("iron"))

  }

  object json {

    val jsoniter = Seq(
      "com.github.plokhotnyuk.jsoniter-scala" %% "jsoniter-scala-core"   % Versions.jsoniter,
      "com.github.plokhotnyuk.jsoniter-scala" %% "jsoniter-scala-macros" % Versions.jsoniter % Provided
    )

    val jsoniterCirce = Seq(
      "com.github.plokhotnyuk.jsoniter-scala" %% "jsoniter-scala-circe" % Versions.jsoniter
    )

    val circe = Seq(circeDep("core"), circeDep("generic"), circeDep("parser"))

    // Jackson 3 lives under tools.jackson.*; the Jackson 2 pins stay in build.sbt.
    val jackson3 = Seq(
      "tools.jackson.core"       % "jackson-core"           % Versions.jackson3,
      "tools.jackson.core"       % "jackson-databind"       % Versions.jackson3,
      "tools.jackson.dataformat" % "jackson-dataformat-xml" % Versions.jackson3
    )

  }

  object iron {

    val core       = Seq("io.github.iltotore" %% "iron" % Versions.iron)
    val zioJson    = Seq("io.github.iltotore" %% "iron-zio-json" % Versions.iron)
    val jsoniter   = Seq("io.github.iltotore" %% "iron-jsoniter" % Versions.iron)
    val chimney    = Seq("io.github.iltotore" %% "iron-chimney" % Versions.iron)
    val doobie     = Seq("io.github.iltotore" %% "iron-doobie" % Versions.iron)
    val skunk      = Seq("io.github.iltotore" %% "iron-skunk" % Versions.iron)
    val pureconfig = Seq("io.github.iltotore" %% "iron-pureconfig" % Versions.iron)

  }

  object database {

    // Flyway 10+ ships database support separately; flyway-database-postgresql is the PostgreSQL one.
    val postgres = Seq(
      "org.postgresql" % "postgresql"                 % Versions.postgres,
      "org.flywaydb"   % "flyway-core"                % Versions.flyway,
      "org.flywaydb"   % "flyway-database-postgresql" % Versions.flyway,
      "com.zaxxer"     % "HikariCP"                   % Versions.hikaricp
    )

    val skunk  = Seq("org.tpolecat" %% "skunk-core" % Versions.skunk)
    val quill  = Seq("io.getquill" %% "quill-jdbc-zio" % Versions.quill)
    val magnum = Seq("com.augustnagro" %% "magnum" % Versions.magnum)

  }

  object aws {

    val core = Seq(
      "software.amazon.awssdk" % "ec2"            % Versions.awsV2,
      "software.amazon.awssdk" % "iam"            % Versions.awsV2,
      "software.amazon.awssdk" % "rds"            % Versions.awsV2,
      "software.amazon.awssdk" % "kms"            % Versions.awsV2,
      "software.amazon.awssdk" % "secretsmanager" % Versions.awsV2,
      "software.amazon.awssdk" % "sts"            % Versions.awsV2
    )

  }

  object azure {

    val core = Seq(
      "com.azure" % "azure-identity"                  % Versions.azureIdentity,
      "com.azure" % "azure-security-keyvault-keys"    % Versions.azureKv,
      "com.azure" % "azure-security-keyvault-secrets" % Versions.azureKv
    )

  }

  object security {

    val core = Seq(
      "org.bouncycastle" % "bcpkix-jdk18on"       % Versions.bouncycastle,
      "com.nimbusds"     % "oauth2-oidc-sdk"      % Versions.nimbusOauth2Oidc,
      "com.yubico"       % "webauthn-server-core" % Versions.webauthn,
      "com.authlete"     % "authlete-java-common" % Versions.authlete
    )

    // Only the tests use it: the independent check that Argon2 hashes still verify.
    val password4j = Seq("com.password4j" % "password4j" % Versions.password4j % Test)

    val nimbusJoseJwt        = Seq("com.nimbusds" % "nimbus-jose-jwt" % Versions.nimbusJoseJwt)
    val bouncycastleProvider = Seq("org.bouncycastle" % "bcprov-jdk18on" % Versions.bouncycastle)
    val pemKeystore          = Seq("de.dentrassi.crypto" % "pem-keystore" % "3.0.0")
    val vault                = Seq("com.bettercloud" % "vault-java-driver" % Versions.vault)
    val auth0                = Seq("com.auth0" % "java-jwt" % Versions.auth0)

    val jwt = Seq(
      "com.github.jwt-scala" %% "jwt-zio-json" % Versions.jwtScala,
      "com.github.jwt-scala" %% "jwt-circe"    % Versions.jwtScala
    )

  }

  object mail {

    val core = Seq(
      "org.eclipse.angus" % "angus-mail"       % Versions.angusMail,
      "jakarta.mail"      % "jakarta.mail-api" % Versions.jakartaMail,
      "org.eclipse.angus" % "jakarta.mail"     % Versions.angusMail
    )

  }

  object observability {

    val micrometer = Seq(
      "io.micrometer" % "micrometer-registry-prometheus" % Versions.micrometer
    )

    val datadog = Seq(
      ("com.datadoghq" % "datadog-api-client" % Versions.datadog).classifier("shaded-jar")
    )

    val kamon = Seq(
      "io.kamon" %% "kamon-bundle"     % Versions.kamon,
      "io.kamon" %% "kamon-prometheus" % Versions.kamon
    )

    val otel = Seq(
      "org.typelevel" %% "otel4s-core"     % Versions.otel4s,
      "org.typelevel" %% "otel4s-otlp"     % Versions.otel4s,
      "org.typelevel" %% "otel4s-otelJava" % Versions.otel4s
    )

  }

  object logging {

    // The compile-time API; Play supplies the Logback runtime.
    val api = Seq("org.slf4j" % "slf4j-api" % Versions.slf4j)

    val runtime = Seq(
      "org.slf4j"      % "slf4j-api"       % Versions.slf4j,
      "ch.qos.logback" % "logback-classic" % Versions.logback % Runtime
    )

    val test = Seq(
      "org.slf4j"      % "slf4j-api"       % Versions.slf4j   % Test,
      "ch.qos.logback" % "logback-classic" % Versions.logback % Test
    )

    val scribe = Seq(
      "com.outr" %% "scribe"       % Versions.scribe,
      "com.outr" %% "scribe-slf4j" % Versions.scribe,
      "com.outr" %% "scribe-cats"  % Versions.scribe
    )

  }

  object config {

    val pureconfig = Seq("com.github.pureconfig" %% "pureconfig-core" % Versions.pureconfig)

    val pureconfigGeneric = Seq(
      "com.github.pureconfig" %% "pureconfig-generic-scala3" % Versions.pureconfig
    )

  }

  object testing {

    val munit = Seq("org.scalameta" %% "munit" % Versions.munit % Test)

    val munitCatsEffect = Seq(
      "org.typelevel" %% "munit-cats-effect" % Versions.munitCatsEffect % Test
    )

    val hedgehog = Seq(
      "qa.hedgehog" %% "hedgehog-core" % Versions.hedgehog % Test,
      "qa.hedgehog" %% "hedgehog-sbt"  % Versions.hedgehog % Test
    )

    val scalacheck = Seq("org.scalacheck" %% "scalacheck" % Versions.scalacheck % Test)

  }

}
