import com.typesafe.sbt.packager.docker.{Cmd, DockerChmodType}
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

ThisBuild / scalaVersion := "3.9.0"
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

Global / mcpEnabled     := true        // default: false
Global / mcpDisableInCI := true        // default: true; set false to allow startup in CI/Heroku
Global / mcpPort        := 5010        // default: 5010
Global / mcpHost        := "127.0.0.1" // default: loopback only

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

// Compile Java for the oldest JDK CI tests (21), whichever JDK runs sbt, so the classes also run
// on the newer JRE in the Docker image.
ThisBuild / javacOptions ++= Seq("--release", "21")

lazy val root = (project in file("."))
  // PlayJava already brings JavaServerAppPackaging (the start script and `stage`/`dist`).
  .enablePlugins(PlayJava, DockerPlugin)
  .settings(
    name := "lattice-oidc",

    // Nothing reads the Scaladoc/Javadoc jar, so don't build it for `stage`, `dist` or the image.
    Compile / doc / sources                := Seq.empty,
    Compile / packageDoc / publishArtifact := false,

    // `Docker/publishLocal` builds the image, `Docker/stage` writes only the Dockerfile and files.

    // Ubuntu (glibc) rather than Alpine (musl): it's the variant the JDK is built and tested on.
    // For a release, pin it to a digest: "eclipse-temurin:25-jre-noble@sha256:...".
    dockerBaseImage := "eclipse-temurin:25-jre-noble",

    // Runs as a numeric, non-root user (USER 1001:0), so Kubernetes' runAsNonRoot can verify it.
    // The app's files are read-only (u=rX,g=rX). For files nobody in the container can change, also
    // run with a read-only root filesystem (readOnlyRootFilesystem in Kubernetes).
    Docker / daemonUser    := "lattice",
    Docker / daemonUserUid := Some("1001"),
    dockerChmodType        := DockerChmodType.UserGroupReadExecute,

    dockerExposedPorts := Seq(9000),

    // The start script's version check runs `java -version` first, an extra JVM on every start,
    // only to reject Java older than 8. The classes need 21, so it can never help.
    bashScriptExtraDefines += "no_version_check=1",

    // tini as PID 1, as the native-packager docs recommend: the JVM then responds to the signals
    // used for thread and heap dumps, and tini reaps any orphaned processes. It is installed in
    // the final stage, as root, before the user is created.
    dockerCommands := {
      val commands  = dockerCommands.value
      val mainStage = commands.indexWhere {
        case Cmd("FROM", args @ _*) => args.lastOption.contains("mainstage")
        case _                      => false
      }
      // Without it, the RUN would land in the discarded stage0 and the image would have no tini.
      require(mainStage >= 0, "no 'FROM ... AS mainstage' in dockerCommands")
      // Insert right after "FROM ... AS mainstage", switching to root explicitly rather than relying
      // on what the plugin writes next. The final "USER 1001:0" still comes later.
      val (before, after) = commands.splitAt(mainStage + 1)
      before ++ Seq(
        Cmd("USER", "root"),
        Cmd(
          "RUN",
          "apt-get update && apt-get install -y --no-install-recommends tini" +
            " && rm -rf /var/lib/apt/lists/*"
        )
      ) ++ after
    },
    dockerEntrypoint := "/usr/bin/tini" +: "--" +: dockerEntrypoint.value,

    dockerEnvVars := Map(
      // Always applied: the java launcher reads it, whatever JAVA_OPTS says. The app directory is
      // read-only, so Play writes no RUNNING_PID file, and logs go to stdout only.
      "JDK_JAVA_OPTIONS" -> "-Dpidfile.path=/dev/null -Dlogger.resource=logback-container.xml",
      // Defaults an operator can replace by setting JAVA_OPTS. The heap follows the container's
      // memory limit, and an OutOfMemoryError exits so the orchestrator restarts the container.
      "JAVA_OPTS" -> "-XX:MaxRAMPercentage=75 -XX:+ExitOnOutOfMemoryError"
    ),

    // Image name and tags: [DOCKER_REGISTRY/][DOCKER_USERNAME/]lattice-oidc:<version>, plus the
    // short commit in GitHub Actions. No "latest": a deployment names the exact image it runs.
    dockerRepository   := sys.env.get("DOCKER_REGISTRY"),
    dockerUsername     := sys.env.get("DOCKER_USERNAME"),
    dockerUpdateLatest := false,
    dockerAliases     ++= {
      val alias = dockerAlias.value
      sys.env.get("GITHUB_SHA").map(sha => alias.withTag(Some(sha.take(12)))).toSeq
    },

    // `Docker/publish` builds and pushes both architectures with buildx.
    dockerBuildxPlatforms := Seq("linux/amd64", "linux/arm64"),

    dockerLabels := Map(
      "org.opencontainers.image.title"   -> name.value,
      "org.opencontainers.image.version" -> version.value,
      "org.opencontainers.image.source"  -> "https://github.com/reynaldjoabet/lattice-oidc"
    ) ++ sys.env.get("GITHUB_SHA").map("org.opencontainers.image.revision" -> _)
  )

addCommandAlias("fmt", "scalafmtAll; scalafmtSbt")
addCommandAlias("fmtCheck", "scalafmtCheckAll; scalafmtSbtCheck")
