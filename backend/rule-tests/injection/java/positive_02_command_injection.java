// Test: positive for rule JAVA-INJ-002
// Expected: should_trigger
// Category: injection
// Language: java

package com.acme.vulnerable.service;

import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.stream.Collectors;

@Service
public class FileConversionServiceVuln {

    private static final Logger logger = LoggerFactory.getLogger(FileConversionServiceVuln.class);

    private static final String UPLOAD_DIR = "/var/app/uploads/";

    /**
     * Converts an uploaded document to PDF using an external tool.
     * This method is vulnerable to OS command injection because it passes
     * user-controlled filename directly into a shell command via Runtime.exec().
     *
     * @param userFilename the filename provided by the user at upload time
     * @return the standard output from the conversion tool
     * @throws IOException if the process fails to execute
     */
    public String convertDocumentToPdf(String userFilename) throws IOException {
        logger.info("Starting PDF conversion for file: {}", userFilename);

        String inputPath = UPLOAD_DIR + userFilename;
        String outputPath = UPLOAD_DIR + "converted/" + userFilename + ".pdf";

        // VULNERABLE: User-supplied filename concatenated into shell command
        String command = "cmd /c libreoffice --headless --convert-to pdf --outdir "
                       + outputPath + " " + inputPath;

        Runtime runtime = Runtime.getRuntime();
        Process process = runtime.exec(command);

        String stdout;
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            stdout = reader.lines().collect(Collectors.joining("\n"));
        }

        int exitCode;
        try {
            exitCode = process.waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Conversion interrupted", e);
        }

        if (exitCode != 0) {
            logger.error("Conversion failed with exit code {} for file: {}", exitCode, userFilename);
            throw new IOException("PDF conversion failed with exit code: " + exitCode);
        }

        logger.info("Successfully converted file: {}", userFilename);
        return stdout;
    }
}
