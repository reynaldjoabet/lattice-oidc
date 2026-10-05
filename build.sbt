import Dependencies.{
  angusMail,
  bouncycastle,
  flyway,
  flywayPostgres,
  hikaricp,
  jedis,
  micrometerPrometheus,
  nimbusOauth2Oidc,
  password4j,
  postgres,
  slf4j,
  unboundid,
  webauthn,
  zxing
}

ThisBuild / organization := "com.lattice"

ThisBuild / scalaVersion := "3.3.8"
ThisBuild / version      := "0.1.0-SNAPSHOT"

//ThisBuild / crossScalaVersions := Seq("3.3.8", "3.9.0")

ThisBuild / scalacOptions := Seq(
  "-encoding",
  "UTF-8",
  "-no-indent",
  "-deprecation",
  "-feature",
  "-unchecked",
  // "-Werror",
  // "-Wunused:all",
  "-Wvalue-discard",
  "-Wnonunit-statement",
  "-language:strictEquality",
  "-Xcheck-macros",
  "-Xmax-inlines:64"
)

val jacksonVersion = "2.19.4"

// Jackson 3 moved to the tools.jackson.* org. It coexists with the Jackson 2 family above, which
// stays pinned because Play and Pekko are still Jackson 2 libraries.
val jackson3Version = "3.2.2"

val jacksonLibs = Seq(
  "com.fasterxml.jackson.core"       % "jackson-core",
  "com.fasterxml.jackson.core"       % "jackson-databind",
  "com.fasterxml.jackson.datatype"   % "jackson-datatype-jdk8",
  "com.fasterxml.jackson.datatype"   % "jackson-datatype-jsr310",
  "com.fasterxml.jackson.dataformat" % "jackson-dataformat-cbor",
  "com.fasterxml.jackson.dataformat" % "jackson-dataformat-xml",
  "com.fasterxml.jackson.dataformat" % "jackson-dataformat-yaml",
  "com.fasterxml.jackson.module"     % "jackson-module-parameter-names",
  "com.fasterxml.jackson.module"    %% "jackson-module-scala"
)

// jackson-annotations is shared by both lines: Jackson 3 needs the 2.22 annotations, which stay
// backward compatible with the 2.19 databind used by Play and Pekko.
val jacksonAnnotationsVersion = "2.22"

val jacksonOverrides =
  jacksonLibs.map(_ % jacksonVersion) :+
    ("com.fasterxml.jackson.core" % "jackson-annotations" % jacksonAnnotationsVersion)

ThisBuild / dependencyOverrides ++= jacksonOverrides

ThisBuild / libraryDependencies ++= Seq(
  javaForms,
  jodaForms,
  guice,
  javaWs,
  javaJdbc,
  javaCore,
  javaClusterSharding,
  logback,
  slf4j,
  caffeine,
  jedis,
  micrometerPrometheus,
  unboundid,
  bouncycastle,
  password4j,
  hikaricp,
  flyway,
  flywayPostgres,
  postgres,
  nimbusOauth2Oidc,
  zxing,
  webauthn,
  angusMail,
  "net.minidev"              % "json-smart"             % "2.6.0",
  "com.cronutils"            % "cron-utils"             % "9.2.1",
  "org.yaml"                 % "snakeyaml"              % "2.7",
  "jakarta.mail"             % "jakarta.mail-api"       % "2.1.5",
  "org.eclipse.angus"        % "jakarta.mail"           % "2.0.5",
  "javax.validation"         % "validation-api"         % "2.0.1.Final",
  "commons-validator"        % "commons-validator"      % "1.11.0",
  "tools.jackson.core"       % "jackson-core"           % jackson3Version,
  "tools.jackson.core"       % "jackson-databind"       % jackson3Version,
  "tools.jackson.dataformat" % "jackson-dataformat-xml" % jackson3Version,
  "io.kamon"                %% "kamon-bundle"           % "2.8.1",
  "io.kamon"                %% "kamon-prometheus"       % "2.8.1",
  "com.authlete"             % "authlete-java-common"   % "4.48"
)

lazy val root = (project in file("."))
  .enablePlugins(PlayJava)
  .settings(name := "lattice-oidc")

addCommandAlias("fmt", "scalafmtAll; scalafmtSbt")
addCommandAlias("fmtCheck", "scalafmtCheckAll; scalafmtSbtCheck")
