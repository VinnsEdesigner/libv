// libv — Kotlin/JVM build.
//
// JVM rather than Android: the parser is pure logic with no Android API, so it
// runs anywhere and its tests need no emulator. An Android consumer adds it as a
// JVM library, which is what a Kotlin Multiplatform or plain Android project does
// with any pure-Kotlin dependency.
plugins {
    kotlin("jvm") version "1.9.23"
    `maven-publish`
}

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(kotlin("test"))
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

kotlin {
    // 21 rather than 17: the toolchain must match an installed JDK, and this repo
    // has no auto-download configured. The library targets JVM 17 bytecode, so a
    // consumer on 17 or 21 both work.
    jvmToolchain(21)
}

tasks.test {
    useJUnitPlatform()

    // The vectors live at the repo root; the test reads them relative to the
    // module, so run from the module directory.
    workingDir = file("${projectDir}")
}

// Publishing exists for one consumer: the Android device, which adds this as
// `com.github.VinnsEdesigner.libv:libv:<tag>` from JitPack. JitPack builds from a
// git tag and reads the coordinates from this publication, so the groupId must be
// the JitPack coordinate — `com.github.<owner>.<repo>` — not the source package
// (`com.vyzorix.libv`). Getting that wrong produces an artifact nothing can
// resolve, which is silent until a consumer build fails.
publishing {
    publications {
        create<MavenPublication>("maven") {
            groupId = "com.github.VinnsEdesigner.libv"
            artifactId = "libv"
            // The tag drives the version on JitPack; locally it is a placeholder.
            version = "1.0.0"
            from(components["java"])
        }
    }
}
