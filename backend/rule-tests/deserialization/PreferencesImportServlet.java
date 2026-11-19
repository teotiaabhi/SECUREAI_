// ===========================================================================
// Test:     positive_03_java_objectinput
// Expected: TRIGGER rule DESER-JAVA-001
// Category: Deserialization
// Language: Java
// Description: Java servlet that reads an ObjectInputStream directly from
//              the HTTP request input stream, allowing deserialization of
//              arbitrary objects sent by the client.
// ===========================================================================

package com.example.vulnerable;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

@WebServlet("/api/preferences/import")
public class PreferencesImportServlet extends HttpServlet {

    private static final Logger LOGGER =
            Logger.getLogger(PreferencesImportServlet.class.getName());

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("application/json");
        PrintWriter out = response.getWriter();

        String contentType = request.getContentType();
        if (contentType == null || !contentType.contains("application/octet-stream")) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            out.print("{\"error\": \"Expected application/octet-stream\"}");
            return;
        }

        try {
            // VULNERABLE: Deserializing untrusted data from request stream
            ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
            Object obj = ois.readObject();
            ois.close();

            if (!(obj instanceof Map)) {
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                out.print("{\"error\": \"Expected a Map object\"}");
                return;
            }

            @SuppressWarnings("unchecked")
            Map<String, Object> preferences = (Map<String, Object>) obj;

            LOGGER.info("Imported " + preferences.size() + " preferences");
            response.setStatus(HttpServletResponse.SC_OK);
            out.print("{\"status\": \"imported\", \"count\": " + preferences.size() + "}");

        } catch (ClassNotFoundException e) {
            LOGGER.log(Level.SEVERE, "Deserialization class not found", e);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            out.print("{\"error\": \"Deserialization failed\"}");
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "IO error during deserialization", e);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            out.print("{\"error\": \"IO error\"}");
        }
    }
}
