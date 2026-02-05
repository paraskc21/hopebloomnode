const jwt = require("jsonwebtoken");

/**
 * Protect routes with JWT.
 * @param {string[]} roles - Allowed roles (e.g. ['admin']). Empty = any authenticated user.
 */
module.exports = (roles = []) => {
  return (req, res, next) => {
    const authHeader = req.header("Authorization");
    const token = authHeader && authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "No token, authorization denied",
      });
    }

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = { id: decoded.id, role: decoded.role };

      if (roles.length > 0 && !roles.includes(decoded.role)) {
        return res.status(403).json({
          success: false,
          message: "Access denied",
        });
      }

      next();
    } catch (err) {
      const message = err.name === "TokenExpiredError" ? "Token expired" : "Token is not valid";
      return res.status(401).json({
        success: false,
        message,
      });
    }
  };
};
