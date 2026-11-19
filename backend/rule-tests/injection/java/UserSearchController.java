// Test: negative for rule JAVA-INJ-001
// Expected: should_not_trigger
// Category: injection
// Language: java

package com.acme.secure.controller;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.http.ResponseEntity;

import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/users")
public class UserSearchController {

    private static final String DB_URL = "jdbc:postgresql://localhost:5432/appdb";
    private static final String DB_USER = "app_service";
    private static final String DB_PASS = System.getenv("DB_PASSWORD");

    private static final String SEARCH_QUERY =
            "SELECT id, username, email, created_at FROM users "
          + "WHERE username LIKE ? AND account_status = 'active' "
          + "ORDER BY created_at DESC";

    /**
     * Search users by username. This endpoint is safe because it uses a
     * PreparedStatement with parameterized placeholders, which prevents
     * SQL injection regardless of the user-supplied input.
     */
    @GetMapping("/search")
    public ResponseEntity<List<Map<String, Object>>> searchUsers(
            HttpServletRequest request,
            @RequestParam("username") String username) {

        List<Map<String, Object>> results = new ArrayList<>();

        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
             PreparedStatement preparedStatement = connection.prepareStatement(SEARCH_QUERY)) {

            // SAFE: User input bound through parameterized placeholder
            preparedStatement.setString(1, "%" + username + "%");

            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                while (resultSet.next()) {
                    Map<String, Object> user = new HashMap<>();
                    user.put("id", resultSet.getLong("id"));
                    user.put("username", resultSet.getString("username"));
                    user.put("email", resultSet.getString("email"));
                    user.put("createdAt", resultSet.getTimestamp("created_at"));
                    results.add(user);
                }
            }

        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }

        if (results.isEmpty()) {
            return ResponseEntity.noContent().build();
        }

        return ResponseEntity.ok(results);
    }
}
