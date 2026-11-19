// Test: negative for rule RCE-JAVA-001
// Expected: should_not_trigger
// Category: rce
// Language: java

/**
 * Image conversion servlet that uses ProcessBuilder with an explicit
 * argument list.  Because each argument is a separate list element
 * (never concatenated into a single shell string), command injection
 * via the filename is not possible.
 */

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/api/convert-image")
public class SafeImageConvertServlet extends HttpServlet {

    private static final String UPLOAD_DIR = "/var/uploads";
    private static final String OUTPUT_DIR = "/var/converted";
    private static final Set<String> ALLOWED_EXTENSIONS =
            Set.of(".png", ".jpg", ".jpeg", ".tiff", ".bmp");

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String inputFile = request.getParameter("inputFile");
        String outputFormat = request.getParameter("format");

        if (inputFile == null || inputFile.isBlank() || outputFormat == null) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write("{\"error\": \"Missing parameters\"}");
            return;
        }

        // Reject path traversal attempts
        if (inputFile.contains("..") || inputFile.contains("/") || inputFile.contains("\\")) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write("{\"error\": \"Invalid filename\"}");
            return;
        }

        Path sourcePath = Paths.get(UPLOAD_DIR, inputFile);
        String baseName = inputFile.replaceAll("\\.[^.]+$", "");
        String outputFile = baseName + "." + outputFormat.replaceAll("[^a-zA-Z]", "");
        Path destPath = Paths.get(OUTPUT_DIR, outputFile);

        if (!Files.exists(sourcePath)) {
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            response.getWriter().write("{\"error\": \"Source file not found\"}");
            return;
        }

        // SAFE: ProcessBuilder with an argument list -- no shell interpolation.
        ProcessBuilder pb = new ProcessBuilder(
                Arrays.asList("convert", sourcePath.toString(), destPath.toString()));
        pb.redirectErrorStream(true);

        try {
            Process process = pb.start();
            boolean finished = process.waitFor(60, TimeUnit.SECONDS);

            response.setContentType("application/json");
            PrintWriter out = response.getWriter();

            if (!finished) {
                process.destroyForcibly();
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                out.write("{\"error\": \"Conversion timed out\"}");
            } else if (process.exitValue() != 0) {
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                out.write("{\"error\": \"Conversion failed\"}");
            } else {
                out.write("{\"message\": \"Conversion complete\", \"output\": \""
                        + destPath.toString() + "\"}");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("{\"error\": \"Conversion interrupted\"}");
        }
    }
}
