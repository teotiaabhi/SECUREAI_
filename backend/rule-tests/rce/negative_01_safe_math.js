// Test: negative for rule RCE-JS-001
// Expected: should_not_trigger
// Category: rce
// Language: javascript

/**
 * Calculator micro-service that safely evaluates math expressions
 * using the mathjs library's sandboxed parser.  mathjs never calls
 * eval() and restricts the expression language to mathematical
 * operations, preventing arbitrary code execution.
 */

const express = require("express");
const { create, all } = require("mathjs");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;

// Create a restricted mathjs instance with no dangerous functions
const math = create(all);
const limitedEval = math.evaluate;

// Disable risky built-ins from the mathjs namespace
math.import(
  {
    import: function () { throw new Error("import is disabled"); },
    createUnit: function () { throw new Error("createUnit is disabled"); },
    parse: function () { throw new Error("parse is disabled"); },
    simplify: function () { throw new Error("simplify is disabled"); },
    derivative: function () { throw new Error("derivative is disabled"); },
  },
  { override: true }
);

app.post("/api/calculate", (req, res) => {
  const expr = req.body.expression;

  if (!expr || typeof expr !== "string") {
    return res.status(400).json({ error: "Missing 'expression' in request body" });
  }

  if (expr.length > 200) {
    return res.status(400).json({ error: "Expression too long" });
  }

  try {
    const result = limitedEval(expr);
    return res.json({ expression: expr, result: result });
  } catch (err) {
    console.warn(`Safe eval rejected "${expr}":`, err.message);
    return res.status(422).json({ error: "Invalid mathematical expression" });
  }
});

app.listen(PORT, () => {
  console.log(`Safe calculator service listening on port ${PORT}`);
});
