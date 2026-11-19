// Test: negative for rule JAVA-INJ-002
// Expected: should_not_trigger
// Category: injection
// Language: java

package com.acme.secure.service;

import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Service
public class FileConversionService {

    private static final Logger logger = LoggerFactory.getLogger(FileConversionService.class);

    private static final String UPLOAD_DIR = "/var/app/uploads/";
    private static final long TIMEOUT_SECONDS = 120;

    /**
     * Converts an uploaded document to PDF using an external tool.
     * This method is safe because it uses ProcessBuilder with an explicit
     * argument list, preventing shell metacharacter interpretation.
     *
     * @param userFilename the filename provided by the user at upload time
     * @return the standard output from the conversion tool
     * @throws IOException if the process fails to execute
     */
    public String convertDocumentToPdf(String userFilename) throws IOException {
        logger.info("Starting PDF conversion for file: {}", userFilename);

        Path sanitizedFilename = Paths.get(userFilename).getFileName();
        String inputPath = UPLOAD_DIR + sanitizedFilename;
        String outputDir = UPLOAD_DIR + "converted/";

        // SAFE: ProcessBuilder with explicit argument list avoids shell injection
        List<String> command = Arrays.asList(
                "libreoffice",
                "--headless",
                "--convert-to", "pdf",
                "--outdir", outputDir,
                inputPath
        );

        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.redirectErrorStream(true);
        Process process = processBuilder.start();

        String stdout;
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            stdout = reader.lines().collect(Collectors.joining("\n"));
        }

        boolean finished;
        try {
            finished = process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
            throw new IOException("Conversion interrupted", e);
        }

        if (!finished) {
            process.destroyForcibly();
            throw new IOException("Conversion timed out after " + TIMEOUT_SECONDS + " seconds");
        }

        int exitCode = process.exitValue();
        if (exitCode != 0) {
            logger.error("Conversion failed with exit code {} for file: {}", exitCode, sanitizedFilename);
            throw new IOException("PDF conversion failed with exit code: " + exitCode);
        }

        logger.info("Successfully converted file: {}", sanitizedFilename);
        return stdout;
    }
}
