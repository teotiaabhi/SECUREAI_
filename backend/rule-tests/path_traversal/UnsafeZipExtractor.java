// Test: positive for rule PT-JAVA-001
// Expected: should_trigger
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

public class UnsafeZipExtractor {

    private static final int BUFFER_SIZE = 4096;

    /**
     * Extracts all entries from a ZIP file to the specified destination directory.
     * VULNERABLE: ZipEntry names are not validated, allowing Zip Slip attacks.
     * A crafted archive with entries like "../../etc/cron.d/malicious" can write
     * files outside the intended destination directory.
     */
    public void extractZip(File zipFile, File destinationDir) throws IOException {
        if (!destinationDir.exists()) {
            destinationDir.mkdirs();
        }

        try (ZipFile zip = new ZipFile(zipFile)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();

            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();

                // VULNERABLE: entry.getName() could contain "../" sequences
                // No canonical path validation is performed
                File outputFile = new File(destinationDir, entry.getName());

                if (entry.isDirectory()) {
                    outputFile.mkdirs();
                    continue;
                }

                // Ensure parent directories exist
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
