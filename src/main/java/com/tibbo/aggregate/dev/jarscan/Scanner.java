package com.tibbo.aggregate.dev.jarscan;

import static java.util.Arrays.asList;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toMap;

import com.eclipsesource.json.Json;
import com.eclipsesource.json.JsonArray;
import com.eclipsesource.json.JsonObject;
import com.eclipsesource.json.WriterConfig;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.CodeSigner;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Function;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.zip.ZipFile;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(name = "scanner", version = "JAR Sign Scanner 1.0", mixinStandardHelpOptions = true)
public class Scanner implements Runnable {

    private static final int STANDARD_TERMINAL_WIDTH = 80;
    
    @Parameters(paramLabel = "paths", description = "JAR files and folders to scan.", defaultValue = ".")
    private String[] args = {"."};
    
    @Option(names = {"-n", "--no-recurse"}, description = "Deny recursive directory traversing.")
    private boolean noRecursion = false;

    @Option(names = {"-v", "--verbose"}, description = "Print error details (stack traces).")
    private boolean verbose = false;

    @Option(names = {"-s", "--show"}, split = ",", description = "Output filter: signed/unsigned/unknown (default: all).", paramLabel = "option")
    private List<ShowOption> showOptions = Arrays.asList(ShowOption.values());
    
    @Option(names = {"-o", "--output"}, description = "Output format: text/json. Defaults to text.")
    private OutputOption output = OutputOption.text;
    
    @Option(names = {"-p", "--pretty"}, description = "Pretty print JSON output.")
    private boolean pretty = false;

    public static void main(String[] args) {
        int exitCode = new CommandLine(new Scanner()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public void run() {
        List<Path> filesToCheck = collectFilesToCheck(args);
        if (filesToCheck.isEmpty()) {
            System.err.println("No JAR files found within specified path(s).");
            return;
        }

        System.out.println();
        Map<Path, CheckResult> path2Result = filesToCheck.stream()
                .peek(this::printCurrentPath)
                .map(this::checkForSignature)
                .collect(Collectors.collectingAndThen(toMap(CheckResult::getPath, Function.identity()), TreeMap::new));
        System.out.println("\r\n");

        if (output == OutputOption.json) {
            composeResultsJson(path2Result);
        } else {
            printCheckResults(path2Result);
            printStats(path2Result);
        }

    }
    private List<Path> collectFilesToCheck(String[] args) {
        if (args.length < 1) {
            System.out.println("Specify directories and/or files to scan (separated by spaces). " +
                    "Example: scanner.jar /opt/app/jar/ /opt/app2/lib/ /tmp/my.jar another.jar");
            return Collections.emptyList();
        }
        
        List<Path> filesToCheck = new ArrayList<>();
        for (String arg : args) {
            try {
                Path givenPath = Paths.get(arg);
                boolean isDirectory = Files.isDirectory(givenPath);
                if (isDirectory) {
                    int walkDepth = noRecursion ? 0 : Integer.MAX_VALUE;
                    try (Stream<Path> stream = Files.walk(givenPath, walkDepth)) {
                        List<Path> jarPaths = stream.filter(Files::isRegularFile)
                                .filter(file -> file.getFileName().toString().toLowerCase().endsWith(".jar"))
                                .collect(toList());
                        filesToCheck.addAll(jarPaths);
                    }
                } else {
                    if (Files.isRegularFile(givenPath)) {
                        filesToCheck.add(givenPath);
                    } else {
                        System.err.println("Cannot read specified path: " + givenPath);
                    }
                }
            } catch (Exception e) {
                System.err.printf("Failed to parse path '%s': %s\n", arg, e.getMessage());
                if (verbose) {
                    e.printStackTrace(System.err);
                }
            }
        }
        return filesToCheck;
    }

    private CheckResult checkForSignature(Path jarPath) {
        try {
            try (JarFile jarFile = new JarFile(jarPath.toFile(), true, ZipFile.OPEN_READ)) {
                Set<Certificate> certificates = new HashSet<>();
                jarFile.stream()
                        .filter(jarEntry -> !jarEntry.isDirectory())
                        .forEach(entry -> {
                            readEntry(jarFile, entry);
                            CodeSigner[] codeSigners = entry.getCodeSigners();
                            if (codeSigners != null) {
                                for (CodeSigner cs : entry.getCodeSigners()) {
                                    certificates.addAll(cs.getSignerCertPath().getCertificates());
                                }
                            }

                            Certificate[] entryCerts = entry.getCertificates();
                            if (entryCerts != null) {
                                certificates.addAll(asList(entryCerts));
                            }
                        });

                return CheckResult.ok(jarPath, certificates);
            }
        } catch (IOException e) {
            System.err.printf("Failed to read JAR file %s: %s\n", jarPath, e.getMessage());
            if (verbose) {
                e.printStackTrace(System.err);
            }
            return CheckResult.fail(jarPath, e.getMessage());
        }
    }

    private void readEntry(JarFile jf, JarEntry je) {
        try (InputStream is = jf.getInputStream(je)) {
            byte[] buffer = new byte[8192];
            //noinspection StatementWithEmptyBody
            while ((is.read(buffer, 0, buffer.length)) != -1) { /* ignore */ }
        } catch (IOException e) {
            System.err.printf("Failed to read entry '%s' from file '%s': %s\n", jf, je, e.getMessage());
            if (verbose) {
                e.printStackTrace(System.err);
            }
        }
    }
    
    private void printCurrentPath(Path path) {
        if (output != OutputOption.text) {
            return;
        }
        StringBuilder sb = new StringBuilder("\rScanning ")
                .append(path).append("...");
        int curLength = sb.length() - 1;
        sb.append(fillSpaces((STANDARD_TERMINAL_WIDTH - curLength)));
        System.out.print(sb);
    }
    
    private void printCheckResults(Map<Path, CheckResult> results) {
        int maxLength = results.keySet().stream()
                .mapToInt(path -> path.toString().length())
                .max()
                .orElseThrow(IllegalArgumentException::new);

        StringBuilder sb = new StringBuilder("Certificate scan results:\n");
        for (Map.Entry<Path, CheckResult> resultEntry : results.entrySet()) {
            Path jarPath = resultEntry.getKey();
            CheckResult checkResult = resultEntry.getValue();

            String jarPathString = jarPath.toString();
            char[] pathFiller = fillSpaces((maxLength - jarPathString.length()));

            if (checkResult.isOk()) {
                Set<Certificate> certs = checkResult.getCerts();
                if (certs.isEmpty()) {
                    if (showOptions.contains(ShowOption.unsigned)) {
                        sb.append(jarPathString).append(pathFiller).append(" | ").append("[UNSIGNED]").append('\n');
                    }
                } else {
                    if (showOptions.contains(ShowOption.signed)) {
                        sb.append(jarPathString).append(pathFiller).append(" | ");
                        int count = 0;
                        for (Certificate cert : certs) {
                            if (!(cert instanceof X509Certificate)) {
                                sb.append("Unknown certificate type: ").append(cert.toString());
                            } else {
                                X509Certificate x509cert = (X509Certificate) cert;
                                String subject = x509cert.getSubjectDN().toString();
                                String issuer = x509cert.getIssuerDN().toString();
                                boolean isSelfSigned = subject.equals(issuer);
                                sb.append("Signed: ").append(subject);
                                if (isSelfSigned) {
                                    sb.append(" (self-signed)");
                                } else {
                                    sb.append(" (issued by: ").append(issuer).append(")");
                                }
                            }
                            if (++count < certs.size()) {
                                sb.append('\n').append("┕").append(fillSpaces((maxLength-1))).append(" | ");
                            }
                        }
                        sb.append('\n');
                    }
                }
            } else {
                if (showOptions.contains(ShowOption.unknown)) {
                    sb.append(jarPathString).append(pathFiller).append(" | ").append("ERROR: ").append(checkResult.getError()).append('\n');
                }
            }
        }
        System.out.println(sb);
    }

    private void printStats(Map<Path, CheckResult> results) {
        if (output != OutputOption.text) {
            return;
        }
        List<CheckResult> successful = results.values().stream()
                .filter(CheckResult::isOk)
                .collect(toList());
        int successFulCount = successful.size();

        long notSignedCount = successful.stream()
                .map(CheckResult::getCerts)
                .filter(Collection::isEmpty)
                .count();

        long signedCount = successFulCount - notSignedCount;
        long failedCount = results.size() - successFulCount;

        System.out.printf("Total %d JAR files scanned: %d signed, %d not signed, %d unknown.\n",
                results.size(), signedCount, notSignedCount, failedCount);
    }

    private void composeResultsJson(Map<Path, CheckResult> results) {
        JsonArray rootArray = Json.array();
        for (Map.Entry<Path, CheckResult> resultEntry : results.entrySet()) {
            Path jarPath = resultEntry.getKey();
            CheckResult checkResult = resultEntry.getValue();

            if (checkResult.isOk()) {
                if (checkResult.getCerts().isEmpty()) {
                    if (showOptions.contains(ShowOption.unsigned)) {
                        rootArray.add(new JsonObject()
                                .add("path", jarPath.toString())
                                .add("certs", new JsonArray())
                                .add("valid", true));
                    }
                } else {
                    if (showOptions.contains(ShowOption.signed)) {
                        JsonArray certsArray = new JsonArray();
                        for (Certificate cert : checkResult.getCerts()) {
                            if (!(cert instanceof X509Certificate)) {
                                certsArray.add("Unknown certificate type" + cert.toString());
                            } else {
                                X509Certificate x509Cert = (X509Certificate) cert;
                                String subject = x509Cert.getSubjectDN().toString();
                                JsonObject certObject = new JsonObject().add("subject", subject);
                                String issuer = x509Cert.getIssuerDN().toString();
                                if (!issuer.equals(subject)) {
                                    certObject.add("issuer", issuer);
                                }
                                certsArray.add(certObject);
                            }
                        }
                        rootArray.add(new JsonObject()
                                .add("path", jarPath.toString())
                                .add("certs", certsArray)
                                .add("valid", true));                    
                    }
                }
            } else {
                if (showOptions.contains(ShowOption.unknown)) {
                    rootArray.add(new JsonObject()
                            .add("path", jarPath.toString())
                            .add("valid", false)
                            .add("error", checkResult.getError()));
                }
            } 
        }
        WriterConfig config = pretty ? WriterConfig.PRETTY_PRINT : WriterConfig.MINIMAL;
        System.out.println(rootArray.toString(config));
    }
    
    private static char[] fillSpaces(int count)
    {
        char[] fillBuff = new char[count];
        Arrays.fill(fillBuff, ' ');
        return fillBuff;
    }
    
    private static class CheckResult implements Comparable<CheckResult> {
        private final boolean isOk;
        private final Path path;
        private final Set<Certificate> certs;
        private final String error;

        private CheckResult(boolean isOk, Path path, Set<Certificate> certs, String error) {
            this.isOk = isOk;
            this.path = path;
            this.certs = certs;
            this.error = error;
        }

        public static CheckResult ok(Path path,  Set<Certificate> certs) {
            return new CheckResult(true, path, certs, null);
        }

        public Path getPath() {
            return path;
        }

        public static CheckResult fail(Path path, String error) {
            return new CheckResult(false, path, Collections.emptySet(), error);
        }

        public boolean isOk() {
            return isOk;
        }

        public Set<Certificate> getCerts() {
            return certs;
        }

        public String getError() {
            return error;
        }

        @Override
        @SuppressWarnings("NullableProblems")
        public int compareTo(CheckResult other) {
            if (other == null) {
                return -1;
            }
            return path.compareTo(other.getPath());
        }
    }
    
    private enum ShowOption {
        signed,
        unsigned,
        unknown
    }
    
    private enum OutputOption {
        text,
        json
    }

}