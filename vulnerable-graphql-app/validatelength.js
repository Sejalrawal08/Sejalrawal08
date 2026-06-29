function validateContentLength(req, res, next) {
  const contentLength = req.headers["content-length"];

  // Reject multiple Content-Length headers
  if (Array.isArray(contentLength)) {
    return res.status(400).json({
      error: "Multiple Content-Length headers are not allowed",
    });
  }

  // Reject invalid Content-Length
  if (contentLength !== undefined) {
    const length = Number(contentLength);

    if (!Number.isInteger(length) || length < 0) {
      return res.status(400).json({
        error: "Invalid Content-Length header",
      });
    }
  }

  next();
}

module.exports = validateContentLength;