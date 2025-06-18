const db = require("../config/db");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const registerUser = async (userData) => {
  const { username, email, password, role, firstName, lastName, bio } =
    userData;

  // 1. ตรวจสอบข้อมูลเบื้องต้น
  if (!username || !email || !password || !role) {
    throw new Error("Username, email, password, and role are required.");
  }

  // 2. เข้ารหัสรหัสผ่าน
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  // 3. สร้างคำสั่ง SQL สำหรับเพิ่มผู้ใช้ใหม่
  const queryText = `
    INSERT INTO users (username, email, password, role, first_name, last_name, bio)
    VALUES ($1, $2, $3, $4, $5, $6, $7)
    RETURNING id, username, email, role, created_at;
  `;
  const values = [
    username,
    email,
    hashedPassword,
    role,
    firstName,
    lastName,
    bio,
  ];

  try {
    // 4. สั่งรันคำสั่ง SQL
    const { rows } = await db.query(queryText, values);

    // 5. ส่งข้อมูล user ใหม่กลับไป (โดยไม่มีรหัสผ่าน)
    return rows[0];
  } catch (error) {
    console.error("RAW DATABASE ERROR:", error);
    // จัดการกับ Error ที่อาจเกิดจาก Database (เช่น username/email ซ้ำ)
    if (error.code === "23505") {
      // Unique violation
      throw new Error("Username or email already exists.");
    }
    throw new Error("Database error during registration.");
  }
};

const loginUser = async (email, password) => {
  // 1. ตรวจสอบว่ามี email, password ส่งมาหรือไม่
  if (!email || !password) {
    throw new Error("Email and password are required.");
  }

  // 2. ค้นหาผู้ใช้จาก email ในฐานข้อมูล
  const queryText = "SELECT * FROM users WHERE email = $1";
  const { rows } = await db.query(queryText, [email]);
  const user = rows[0];

  // 3. ถ้าไม่เจอผู้ใช้ หรือผู้ใช้ถูกปิดใช้งาน (is_active = false)
  if (!user || !user.is_active) {
    throw new Error("Invalid credentials or user is inactive.");
  }

  // 4. เปรียบเทียบรหัสผ่านที่ส่งมา กับรหัสผ่านใน DB
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    throw new Error("Invalid credentials."); // ใช้ข้อความเดียวกันเพื่อความปลอดภัย
  }

  // 5. ถ้าทุกอย่างถูกต้อง: สร้าง JWT (Token)
  const payload = {
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
    },
  };

  const token = jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });

  // 6. เตรียมข้อมูล user ที่จะส่งกลับไป (ไม่ต้องส่งรหัสผ่าน)
  const userToReturn = {
    id: user.id,
    username: user.username,
    email: user.email,
    role: user.role,
  };

  return { token, user: userToReturn };
};

module.exports = {
  registerUser,
  loginUser,
};
