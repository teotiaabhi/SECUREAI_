// Test: negative for rule DESER-JAVA-001
// Expected: should_not_trigger
// Category: deserialization
// Language: java

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.util.Set;

@WebServlet("/api/profile/import-safe")
public class SafeProfileImportServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static final Set<String> ALLOWED_CLASSES = Set.of(
            "com.example.model.UserProfile",
            "java.lang.String",
            "java.lang.Integer",
            "java.util.ArrayList",
            "java.util.HashMap"
    );

    private static final int MAX_DEPTH = 5;
    private static final long MAX_BYTES = 1024 * 512; // 512 KB

    /**
     * Custom ObjectInputFilter that restricts deserialization to an explicit allowlist.
     */
    private ObjectInputFilter createAllowlistFilter() {
        return filterInfo -> {
            Class<?> clazz = filterInfo.serialClass();
            if (clazz != null) {
                if (!ALLOWED_CLASSES.contains(clazz.getName())) {
                    return ObjectInputFilter.Status.REJECTED;
                }
            }
            if (filterInfo.depth() > MAX_DEPTH) {
                return ObjectInputFilter.Status.REJECTED;
            }
            if (filterInfo.streamBytes() > MAX_BYTES) {
                return ObjectInputFilter.Status.REJECTED;
            }
            return ObjectInputFilter.Status.ALLOWED;
        };
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("application/json");
        PrintWriter out = response.getWriter();

        InputStream inputStream = request.getInputStream();

        try (ObjectInputStream ois = new ObjectInputStream(inputStream)) {
            // SAFE: ObjectInputFilter restricts classes to an explicit allowlist
            ois.setObjectInputFilter(createAllowlistFilter());

            Object obj = ois.readObject();
            UserProfile profile = (UserProfile) obj;

            response.setStatus(HttpServletResponse.SC_OK);
            out.print("{\"status\": \"imported\", \"user\": \"" + profile.getUsername() + "\"}");

        } catch (ClassNotFoundException | SecurityException e) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            out.print("{\"error\": \"Deserialization rejected by filter\"}");
        }
    }
}
