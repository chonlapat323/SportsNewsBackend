const jwt = require("jsonwebtoken");

const verifyToken = (req, res, next) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ message: "Unauthorized: No token provided" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // ข้อมูลที่ถูกถอดรหัสจะถูกเก็บใน req.user
    next(); // อนุญาตให้ request เดินทางต่อไปยัง controller
  } catch (err) {
    // ถ้า token ไม่ถูกต้อง (หมดอายุ, แก้ไข) จะเข้า catch
    return res.status(403).json({ message: "Forbidden: Invalid token" });
  }
};

module.exports = { verifyToken };
