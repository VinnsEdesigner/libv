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
// `com.github.VinnsEdesigner:libv:<tag>` from JitPack. JitPack builds from a git
// tag and serves the artifact under `com.github.<owner>` with the repository name
// as the artifactId — it rewrites the groupId to that, so a publication group of
// `com.github.<owner>.<repo>` would resolve nowhere. Matching JitPack's own
// coordinate here keeps a local `publishToMavenLocal` resolving the same way a
// JitPack fetch does, so the two paths cannot disagree.
publishing {
    publications {
        create<MavenPublication>("maven") {
            groupId = "com.github.VinnsEdesigner"
            artifactId = "libv"
            // The tag drives the version on JitPack; locally it is a placeholder.
            version = "1.0.0"
            from(components["java"])
        }
    }
}
