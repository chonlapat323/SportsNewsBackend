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

const authorizeRoles = (allowedRoles) => {
  return (req, res, next) => {
    // เราคาดว่า verifyToken ทำงานไปก่อนแล้ว ดังนั้น req.user ควรจะมีอยู่
    if (!req.user) {
      return res
        .status(403)
        .json({ message: "Forbidden: User data not found" });
    }

    const { role } = req.user; // ดึง role ของผู้ใช้ออกจาก token

    // ตรวจสอบว่า role ของผู้ใช้ อยู่ใน Array ของ roles ที่เราอนุญาตหรือไม่
    if (allowedRoles.includes(role)) {
      next(); // ถ้ามีสิทธิ์ ก็ให้ผ่านไปได้
    } else {
      // ถ้าไม่มีสิทธิ์ ก็ปฏิเสธไป
      return res.status(403).json({
        message: "Forbidden: You do not have the required permissions.",
      });
    }
  };
};

module.exports = { verifyToken, authorizeRoles };
