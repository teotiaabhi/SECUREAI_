// Test: negative for rule PT-JAVA-001
// Expected: should_not_trigger
// Category: path_traversal
// Language: java

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class SafeZipExtractor {

    private static final int BUFFER_SIZE = 4096;

    /**
     * Validates that a zip entry's resolved path stays within the destination directory.
     * Prevents Zip Slip by comparing canonical paths.
     *
     * @throws IOException if the entry would escape the destination directory
     */
    private File validateEntryPath(ZipEntry entry, File destinationDir) throws IOException {
        File outputFile = new File(destinationDir, entry.getName());

        String canonicalDest = destinationDir.getCanonicalPath();
        String canonicalOutput = outputFile.getCanonicalPath();

        if (!canonicalOutput.startsWith(canonicalDest + File.separator)) {
            throw new IOException(
                    "Zip Slip detected: entry '" + entry.getName()
                    + "' resolves outside destination directory");
        }

        return outputFile;
    }

    /**
     * Safely extracts all entries from a ZIP file to the specified destination directory.
     * SAFE: Each entry's canonical path is validated against the destination directory
     * before extraction, preventing Zip Slip attacks.
     */
    public void extractZip(File zipFile, File destinationDir) throws IOException {
        if (!destinationDir.exists()) {
            destinationDir.mkdirs();
        }

        try (ZipFile zip = new ZipFile(zipFile)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();

            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();

                // SAFE: Canonical path check ensures entry stays within destination
                File outputFile = validateEntryPath(entry, destinationDir);

                if (entry.isDirectory()) {
                    outputFile.mkdirs();
                    continue;
                }

                outputFile.getParentFile().mkdirs();

                try (InputStream in = zip.getInputStream(entry);
                     BufferedOutputStream out = new BufferedOutputStream(
                             new FileOutputStream(outputFile), BUFFER_SIZE)) {

                    byte[] buffer = new byte[BUFFER_SIZE];
                    int bytesRead;
                    while ((bytesRead = in.read(buffer)) != -1) {
                        out.write(buffer, 0, bytesRead);
                    }
                }
            }
        }
    }
}
