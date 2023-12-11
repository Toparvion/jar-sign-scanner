package pro.toparvion.util.jarscan;

import static java.util.Arrays.asList;
import static java.util.stream.Collectors.collectingAndThen;
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
import java.util.Timer;
import java.util.TimerTask;
import java.util.TreeMap;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Stream;
import java.util.zip.ZipFile;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(name = "scanner", version = "JAR Sign Scanner 1.1", mixinStandardHelpOptions = true)
public class Scanner implements Callable<Integer> {

    @Parameters(paramLabel = "paths", description = "JAR files and folders to scan.", defaultValue = ".")
    private String[] args = {"."};
    
    @Option(names = {"-n", "--no-recurse"}, description = "Deny recursive directory traversing.")
    private boolean noRecursion = false;

    @Option(names = {"-v", "--verbose"}, description = "Print process details (including stack traces).")
    private boolean verbose = false;

    @Option(names = {"-s", "--show"}, split = ",", description = "Output filter: signed/unsigned/unknown (default: all).", paramLabel = "option")
    private List<ShowOption> showOptions = Arrays.asList(ShowOption.values());
    
    @Option(names = {"-o", "--output"}, description = "Output format: text/json. Defaults to text.")
    private OutputOption output = OutputOption.text;
    
    @Option(names = {"-p", "--pretty"}, description = "Pretty print JSON output.")
    private boolean pretty = false;

    private final AtomicLong progressCounter = new AtomicLong(1);

    public static void main(String[] args) {
        int exitCode = new CommandLine(new Scanner()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() {
        var startTime = System.currentTimeMillis();
        List<Path> filesToCheck = collectFilesToCheck(args);
        if (filesToCheck.isEmpty()) {
            System.err.println("No JAR files found within specified path(s).");
            return 1;
        }

        setupProgressMonitor(filesToCheck.size(), startTime);
        Map<Path, CheckResult> path2Result = filesToCheck.stream()
                .parallel()
                .map(this::checkForSignature)
                .collect(collectingAndThen(
                        toMap(CheckResult::path, Function.identity()),
                        TreeMap::new));

        if (output == OutputOption.json) {
            composeResultsJson(path2Result);
        } else {
            System.out.println("\n");       
            printCheckResults(path2Result);
            printStats(path2Result, startTime);
        }
        
        return 0;
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
                                .toList();
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
        if (verbose && output == OutputOption.text) {
            System.out.printf("Found %d JAR eligible files to scan\n", filesToCheck.size());
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
        } finally {
            progressCounter.incrementAndGet();
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

    private void setupProgressMonitor(int total, long startTime) {
        if (total > 100 && output == OutputOption.text) {
            Timer timer = new Timer("ProgressTimer", true);
            timer.scheduleAtFixedRate(new TimerTask() {
                @Override
                public void run() {
                    printProgress(startTime, total);
                }
            }, 0, 200);
        }
        System.out.println();
    }

    /**
     * @see <a href="https://stackoverflow.com/a/39257969/3507435">Source</a>
     */
    private void printProgress(long startTime, long total) {
        long current = progressCounter.get();
        long eta = current == 0 ? 0 :
                (total - current) * (System.currentTimeMillis() - startTime) / current;

        String etaHms = current == 0 ? "N/A" :
                String.format("%02d:%02d:%02d", TimeUnit.MILLISECONDS.toHours(eta),
                        TimeUnit.MILLISECONDS.toMinutes(eta) % TimeUnit.HOURS.toMinutes(1),
                        TimeUnit.MILLISECONDS.toSeconds(eta) % TimeUnit.MINUTES.toSeconds(1));

        int percent = (int) (current * 100 / total);
        String string = '\r' +
                String.join("", Collections.nCopies(percent == 0 ? 2 : 2 - (int) (Math.log10(percent)), " ")) +
                String.format(" %d%% [", percent) +
                String.join("", Collections.nCopies(percent, "=")) +
                '>' +
                String.join("", Collections.nCopies(100 - percent, " ")) +
                ']' +
                String.join("", Collections.nCopies((int) (Math.log10(total)) - (int) (Math.log10(current)), " ")) +
                String.format(" %d/%d, ETA: %s", current, total, etaHms);

        System.out.print(string);
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
                Set<Certificate> certs = checkResult.certs();
                if (certs.isEmpty()) {
                    if (showOptions.contains(ShowOption.unsigned)) {
                        sb.append(jarPathString).append(pathFiller).append(" | ").append("[UNSIGNED]").append('\n');
                    }
                } else {
                    if (showOptions.contains(ShowOption.signed)) {
                        sb.append(jarPathString).append(pathFiller).append(" | ");
                        int count = 0;
                        for (Certificate cert : certs) {
                            if (!(cert instanceof X509Certificate x509cert)) {
                                sb.append("Unknown certificate type: ").append(cert.toString());
                            } else {
                                String subject = x509cert.getSubjectX500Principal().toString();
                                String issuer = x509cert.getIssuerX500Principal().toString();
                                boolean isSelfSigned = subject.equals(issuer);
                                sb.append("Signed: ").append(subject);
                                if (isSelfSigned) {
                                    sb.append(" (self-signed)");
                                } else {
                                    sb.append(" (issued by: ").append(issuer).append(")");
                                }
                            }
                            if (++count < certs.size()) {
                                String indent = "  \\-->";
                                sb.append('\n').append(indent).append(fillSpaces((maxLength-indent.length()))).append(" | ");
                            }
                        }
                        sb.append('\n');
                    }
                }
            } else {
                if (showOptions.contains(ShowOption.unknown)) {
                    sb.append(jarPathString).append(pathFiller).append(" | ").append("ERROR: ").append(checkResult.error()).append('\n');
                }
            }
        }
        System.out.println(sb);
    }

    private void printStats(Map<Path, CheckResult> results, long startTime) {
        if (output != OutputOption.text) {
            return;
        }
        List<CheckResult> successful = results.values().stream()
                .filter(CheckResult::isOk)
                .toList();
        int successFulCount = successful.size();

        long notSignedCount = successful.stream()
                .map(CheckResult::certs)
                .filter(Collection::isEmpty)
                .count();

        long signedCount = successFulCount - notSignedCount;
        long failedCount = results.size() - successFulCount;

        var tookTime = System.currentTimeMillis() - startTime;
        System.out.printf("Total %d JAR files scanned: %d signed, %d not signed, %d unknown (took %d ms).\n",
                results.size(), signedCount, notSignedCount, failedCount, tookTime);
    }

    private void composeResultsJson(Map<Path, CheckResult> results) {
        JsonArray rootArray = Json.array();
        for (Map.Entry<Path, CheckResult> resultEntry : results.entrySet()) {
            Path jarPath = resultEntry.getKey();
            CheckResult checkResult = resultEntry.getValue();

            if (checkResult.isOk()) {
                if (checkResult.certs().isEmpty()) {
                    if (showOptions.contains(ShowOption.unsigned)) {
                        rootArray.add(new JsonObject()
                                .add("path", jarPath.toString())
                                .add("certs", new JsonArray())
                                .add("valid", true));
                    }
                } else {
                    if (showOptions.contains(ShowOption.signed)) {
                        JsonArray certsArray = new JsonArray();
                        for (Certificate cert : checkResult.certs()) {
                            if (!(cert instanceof X509Certificate x509Cert)) {
                                certsArray.add("Unknown certificate type" + cert.toString());
                            } else {
                                String subject = x509Cert.getSubjectX500Principal().toString();
                                JsonObject certObject = new JsonObject().add("subject", subject);
                                String issuer = x509Cert.getIssuerX500Principal().toString();
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
                            .add("error", checkResult.error()));
                }
            } 
        }
        WriterConfig config = pretty ? WriterConfig.PRETTY_PRINT : WriterConfig.MINIMAL;
        System.out.println(rootArray.toString(config));
    }
    
    private static char[] fillSpaces(int count)
    {
        if (count < 0) {
            count = 0;
        }
        char[] fillBuff = new char[count];
        Arrays.fill(fillBuff, ' ');
        return fillBuff;
    }

    private record CheckResult(boolean isOk, 
                               Path path, 
                               Set<Certificate> certs,
                               String error) implements Comparable<CheckResult> {

        public static CheckResult ok(Path path, Set<Certificate> certs) {
                return new CheckResult(true, path, certs, null);
            }
    
            public static CheckResult fail(Path path, String error) {
                return new CheckResult(false, path, Collections.emptySet(), error);
            }
    
            @Override
            @SuppressWarnings("NullableProblems")
            public int compareTo(CheckResult other) {
                if (other == null) {
                    return -1;
                }
                return path.compareTo(other.path());
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