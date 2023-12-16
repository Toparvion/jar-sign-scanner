# JAR Sign Scanner

A small CLI utility to get signature information from many JAR files at once. 

Key features:

* **bulk scanning** of files and directories (with controllable recursion)
* **multiple signatures** recognition per JAR file
* **customizable output**: signed, unsigned, unknown entries 
* **export to JSON** for automated analysis
* **progress monitor** with ETA for very large scans
* **self-signed** certificate markers for easy identification
* shipped as **single JAR** file with no external dependencies

The utility needs only **JRE 21+** to run, i.e. neither `jarsigner` nor other JDK tools are required.



## Download

* https://github.com/Toparvion/jar-sign-scanner/releases/download/v1.1/scanner.jar

* Or head to the [latest release](https://github.com/toparvion/jar-sign-viewer/releases/latest) page and download the attached `scanner.jar`



## Usage

```bash
$ java -jar scanner.jar --help
Usage: scanner [-hnpvV] [-o=<output>] [-s=option[,option...]]... [paths...]
      [paths...]          JAR files and folders to scan.
  -h, --help              Show this help message and exit.
  -n, --no-recurse        Deny recursive directory traversing.
  -o, --output=<output>   Output format: text/json. Defaults to text.
  -p, --pretty            Pretty print JSON output.
  -s, --show=option[,option...]
                          Output filter: signed/unsigned/unknown (default: all).
  -v, --verbose           Print process details (including stack traces).
  -V, --version           Print version information and exit.
```

The scanner uses its own working directory as:

* base path to resolve relative `paths`,
* default argument if no `paths` specified.

The last allows you to simply put the scanner into the root of an application to scan and run it as `java -jar scanner.jar` without any arguments.



## Examples

### Commands

To get signature statuses of **all kinds** for all the JAR files in the specified directory:

```bash
$ java -jar scanner.jar /path/to/the/dir/
```

To list only the **signed** JARs among specified ones:

```bash
$ java -jar scanner.jar --show=signed /absolute/path/to/lib1.jar relative/path/to/lib2.jar lib3.jar
```

To gather the list of **unsigned** JARs of current directory tree in pretty-printed JSON format:

```bash
$ java -jar scanner.jar --output=json --pretty .
```

To export the list of **unknown** (usually corrupted) JARs of current directory only to JSON file for further processing:

```bash
$ java -jar scanner.jar --output=json --no-recurse > unknowns.json
```



### Output

Plain text result samples:

```
Certificate scan results:
.\plugins\org.openjdk.jmc.ui.jar   | [UNSIGNED]
.\plugins\org.owasp.encoder.jar    | [UNSIGNED]
...
plugins\deploy\alerting.jar        | Signed: CN=General Sign Dep, O=MacroSoft Inc., C=TW (self-signed)
...
libs\bcpkix-jdk15on-1.60.jar       | Signed: CN=Legion of the Bouncy Castle Inc., OU=Java Software Code Signing, O=Oracle Corporation (issued by: CN=JCE Code Signing CA, OU=Java Software Code Signing, O=Oracle Corporation)
  \-->                             | Signed: CN=JCE Code Signing CA, OU=Java Software Code Signing, O=Oracle Corporation (self-signed)
...
jar\freq.jar                       | ERROR: zip END header not found

Total 82 JAR files scanned: 34 signed, 48 not signed, 0 unknown (took 2909 ms).
```

JSON result sample (for integrating into CI and/or tests):

```json
[  
  {
    "path": ".\\plugins\\org.sat4j.core_2.3.5.v201308161310.jar",
    "certs": [
      {
        "subject": "CN=DigiCert SHA2 Assured ID Code Signing CA, OU=www.digicert.com, O=DigiCert Inc, C=US",
        "issuer": "CN=DigiCert Assured ID Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US"
      },
      {
        "subject": "CN=DigiCert Assured ID Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US"
      },
      {
        "subject": "CN=\"Eclipse Foundation, Inc.\", OU=IT, O=\"Eclipse Foundation, Inc.\", L=Ottawa, ST=Ontario, C=CA",
        "issuer": "CN=DigiCert SHA2 Assured ID Code Signing CA, OU=www.digicert.com, O=DigiCert Inc, C=US"
      }
    ],
    "valid": true
  },
  {
    "path": ".\\plugins\\org.openjdk.jmc.docs_7.1.1.202004231814.jar",
    "certs": [],
    "valid": true
  }
]
```



## Acknowledgments

To stay small, simple yet capable, JarSignScanner incorporates the following great open source tools:

* [Picocli](https://github.com/remkop/picocli) command line interface framework ([Apache 2.0 License](https://github.com/remkop/picocli/blob/main/LICENSE))
* [minimal-json](https://github.com/ralfstx/minimal-json) conversion library ([MIT License](https://github.com/ralfstx/minimal-json/blob/master/LICENSE))



## Feedback & contribution

Your feedback is very appreciated in any suitable way:
* [create a pull request](https://github.com/Toparvion/jar-sign-scanner/compare) for missing/misbehaving features;
* [file an issue](https://github.com/Toparvion/jar-sign-scanner/issues/new/choose) to discuss changes or suggest improvements;
* just **star**⭐ the project if it helps.



## Other tools

Refer to my other [GitHub projects](https://github.com/Toparvion) or [this web page](https://toparvion.pro/en/) to find more tools for JVM-based development & testing. 
