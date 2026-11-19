// Test: positive for rule RCE-JS-001
// Expected: should_trigger
// Category: rce
// Language: javascript

/**
 * Calculator micro-service that evaluates math expressions submitted
 * by the client.  VULNERABLE: uses eval() on unsanitised user input,
 * allowing arbitrary code execution on the server.
 */

const express = require("express");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;

app.post("/api/calculate", (req, res) => {
  const expr = req.body.expression;

  if (!expr || typeof expr !== "string") {
    return res.status(400).json({ error: "Missing 'expression' in request body" });
  }

  if (expr.length > 500) {
    return res.status(400).json({ error: "Expression too long" });
  }

  try {
    // VULNERABLE: eval() executes arbitrary JavaScript supplied by the user.
    // An attacker can send `require('child_process').execSync('id').toString()`
    // as the expression to achieve full remote code execution.
    const result = eval(expr);

    return res.json({ expression: expr, result: result });
  } catch (err) {
    console.error(`Evaluation error for "${expr}":`, err.message);
    return res.status(422).json({ error: "Failed to evaluate expression" });
  }
});

app.listen(PORT, () => {
  console.log(`Calculator service listening on port ${PORT}`);
});
