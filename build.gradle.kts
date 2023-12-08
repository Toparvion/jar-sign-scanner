plugins {
    id("java")
}

group = "com.tibbo.aggregate.dev.jarscan"
version = "1.0"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.9.1"))
    testImplementation("org.junit.jupiter:junit-jupiter")
}

tasks.named<Jar>("jar") {
    manifest {
        attributes(mapOf(
            "Implementation-Title" to project.name,
            "Implementation-Version" to project.version,
            "Main-Class" to "com.tibbo.aggregate.dev.jarscan.Scanner"))
    }
    
    archiveFileName.set("scanner.jar")
}

tasks.test {
    useJUnitPlatform()
}