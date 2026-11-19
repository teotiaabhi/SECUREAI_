// Test: positive for rule RCE-JAVA-001
// Expected: should_trigger
// Category: rce
// Language: java

/**
 * Diagnostic servlet that executes a system command supplied via the
 * "command" request parameter.  VULNERABLE: user input is passed
 * directly to Runtime.exec(), enabling arbitrary command execution.
 */

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.stream.Collectors;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/api/diagnostic")
public class DiagnosticServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String cmd = request.getParameter("command");

        if (cmd == null || cmd.isBlank()) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"Missing 'command' parameter\"}");
            return;
        }

        response.setContentType("text/plain");
        PrintWriter out = response.getWriter();

        try {
            // VULNERABLE: attacker-supplied command string is executed directly.
            // Sending ?command=cat%20/etc/passwd will leak sensitive files.
            Process process = Runtime.getRuntime().exec(cmd);

            try (BufferedReader reader =
                    new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String output = reader.lines().collect(Collectors.joining("\n"));
                out.println(output);
            }

            int exitCode = process.waitFor();
            out.println("\nExit code: " + exitCode);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            out.println("Command interrupted");
        } catch (IOException e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            out.println("Command execution failed: " + e.getMessage());
        }
    }
}
