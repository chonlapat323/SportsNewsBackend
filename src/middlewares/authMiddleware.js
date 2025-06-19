const jwt = require("jsonwebtoken");

const verifyToken = (req, res, next) => {
  // 1. ดึง Token จาก Authorization header
  const authHeader = req.headers["authorization"];

  // 2. ตรวจสอบว่า header และ token มีอยู่จริง และอยู่ในรูปแบบ "Bearer <TOKEN>"
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res
      .status(401)
      .json({ message: "Unauthorized: No token provided or malformed token" });
  }

  const token = authHeader.split(" ")[1];

  // 3. ตรวจสอบความถูกต้องของ Token
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // ที่ decoded ออกมาจะมี userId และ role, เราจะเก็บไว้ใน req.user
    // แต่ใน payload ที่เราสร้าง มันอยู่ใต้ key 'user' อีกทีหรือไม่?
    // จากโค้ด loginUser ของคุณ มันไม่มี key 'user' ซ้อนอยู่ ดังนั้น decoded คือ payload โดยตรง
    req.user = decoded; // decoded คือ { userId: '...', role: '...' }

    next(); // ถ้า Token ถูกต้อง, ไปยัง Middleware หรือ Controller ถัดไป
  } catch (err) {
    // ถ้า Token ไม่ถูกต้อง (หมดอายุ, แก้ไข) จะเข้า catch
    // ที่นี่คือที่ที่จะส่ง 403 Forbidden กลับไป
    // Frontend จะต้องดักจับ Error นี้แล้วไปเรียก /api/auth/refresh
    return res
      .status(403)
      .json({ message: "Forbidden: Invalid or expired token" });
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
