// Test: positive for rule DESER-JAVA-001
// Expected: should_trigger
// Category: deserialization
// Language: java

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.PrintWriter;

@WebServlet("/api/profile/import")
public class ProfileImportServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("application/json");
        PrintWriter out = response.getWriter();

        String contentType = request.getContentType();
        if (contentType == null || !contentType.equals("application/octet-stream")) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            out.print("{\"error\": \"Invalid content type\"}");
            return;
        }

        try {
            // VULNERABLE: Deserializing untrusted data directly from the request stream
            // An attacker can craft a malicious serialized object to achieve remote code execution
            ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
            Object obj = ois.readObject();
            UserProfile profile = (UserProfile) obj;
            ois.close();

            // Process the imported profile
            String username = profile.getUsername();
            String email = profile.getEmail();

            response.setStatus(HttpServletResponse.SC_OK);
            out.print("{\"status\": \"imported\", \"username\": \"" + username + "\"}");

        } catch (ClassNotFoundException e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            out.print("{\"error\": \"Failed to deserialize profile\"}");
        }
    }
}
