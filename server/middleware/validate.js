function formatZodError(error) {
  return error.issues.map((issue) => issue.message).join(". ");
}

function validateBody(schema) {
  return (req, res, next) => {
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: formatZodError(parsed.error) });
    }
    req.body = parsed.data;
    next();
  };
}

function validateQuery(schema) {
  return (req, res, next) => {
    const parsed = schema.safeParse(req.query);
    if (!parsed.success) {
      return res.status(400).json({ error: formatZodError(parsed.error) });
    }
    req.query = parsed.data;
    next();
  };
}

module.exports = { validateBody, validateQuery, formatZodError };
