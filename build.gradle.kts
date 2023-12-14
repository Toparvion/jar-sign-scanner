plugins {
    id("java")
}

group = "pro.toparvion.util.jarscan"
version = "1.1"

java.sourceCompatibility = JavaVersion.VERSION_21
java.targetCompatibility = JavaVersion.VERSION_21

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.9.2"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.9.2")
}

tasks.named<Jar>("jar") {
    manifest {
        attributes(mapOf(
            "Implementation-Title" to project.name,
            "Implementation-Version" to project.version,
            "Main-Class" to "pro.toparvion.util.jarscan.Scanner"))
    }
    
    archiveFileName.set("scanner.jar")
}

tasks.test {
    useJUnitPlatform()
}