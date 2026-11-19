// Test: positive for rule JAVA-INJ-001
// Expected: should_trigger
// Category: injection
// Language: java

package com.acme.vulnerable.controller;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.http.ResponseEntity;

import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
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

    /**
     * Search users by username. This endpoint is vulnerable to SQL injection
     * because it concatenates raw user input directly into the SQL query string
     * instead of using parameterized queries.
     */
    @GetMapping("/search")
    public ResponseEntity<List<Map<String, Object>>> searchUsers(
            HttpServletRequest request,
            @RequestParam("username") String username) {

        List<Map<String, Object>> results = new ArrayList<>();

        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS)) {
            Statement statement = connection.createStatement();

            // VULNERABLE: Direct string concatenation of user input into SQL query
            String query = "SELECT id, username, email, created_at FROM users "
                         + "WHERE username LIKE '%" + username + "%' "
                         + "AND account_status = 'active' "
                         + "ORDER BY created_at DESC";

            ResultSet resultSet = statement.executeQuery(query);

            while (resultSet.next()) {
                Map<String, Object> user = new HashMap<>();
                user.put("id", resultSet.getLong("id"));
                user.put("username", resultSet.getString("username"));
                user.put("email", resultSet.getString("email"));
                user.put("createdAt", resultSet.getTimestamp("created_at"));
                results.add(user);
            }

            resultSet.close();
            statement.close();

        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }

        if (results.isEmpty()) {
            return ResponseEntity.noContent().build();
        }

        return ResponseEntity.ok(results);
    }
}
