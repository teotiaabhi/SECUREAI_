// Test: positive for rule JAVA-INJ-005
// Expected: should_trigger
// Category: injection
// Language: java

package com.acme.vulnerable.controller;

import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/rules")
public class DynamicRuleControllerVuln {

    private final ExpressionParser expressionParser = new SpelExpressionParser();

    /**
     * Evaluates a user-defined business rule expression against a data context.
     * This endpoint is vulnerable to Spring Expression Language (SpEL) injection
     * because it parses and evaluates an arbitrary expression string provided
     * directly by the user without any restriction or sandboxing.
     *
     * An attacker can execute arbitrary code, e.g.:
     *   T(java.lang.Runtime).getRuntime().exec('calc')
     */
    @PostMapping("/evaluate")
    public Map<String, Object> evaluateRule(@RequestBody Map<String, Object> payload) {

        String ruleExpression = (String) payload.get("expression");
        Map<String, Object> contextData = (Map<String, Object>) payload.get("context");

        StandardEvaluationContext evalContext = new StandardEvaluationContext();
        if (contextData != null) {
            contextData.forEach(evalContext::setVariable);
        }

        // VULNERABLE: User-controlled expression string parsed and evaluated
        Expression expression = expressionParser.parseExpression(ruleExpression);
        Object result = expression.getValue(evalContext);

        Map<String, Object> response = new HashMap<>();
        response.put("expression", ruleExpression);
        response.put("result", result);
        response.put("resultType", result != null ? result.getClass().getSimpleName() : "null");

        return response;
    }
}
