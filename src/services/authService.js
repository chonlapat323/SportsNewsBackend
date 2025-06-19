const db = require("../config/db");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
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
  // --- ขั้นตอนที่ 1: ค้นหาผู้ใช้จากอีเมล ---
  const userQueryResult = await db.query(
    "SELECT * FROM users WHERE email = $1",
    [email]
  );
  const user = userQueryResult.rows[0];

  // --- ขั้นตอนที่ 2: ตรวจสอบความถูกต้องของผู้ใช้และรหัสผ่าน ---
  // ตรวจสอบรหัสผ่านด้วย bcrypt.compare
  // ถ้าไม่เจอ user หรือรหัสผ่านไม่ตรงกัน, ให้โยน Error ที่มีข้อความเหมือนกัน
  // เพื่อป้องกันการเดาว่าอีเมลไหนมีอยู่ในระบบ (User Enumeration Attack)
  const isMatch = user ? await bcrypt.compare(password, user.password) : false;

  if (!user || !isMatch) {
    throw new Error("อีเมลหรือรหัสผ่านไม่ถูกต้อง กรุณาตรวจสอบอีกครั้ง");
  }

  // --- ขั้นตอนที่ 3: ตรวจสอบสถานะการใช้งานของบัญชี ---
  // เราจะตรวจสอบขั้นตอนนี้ "หลังจาก" ที่ยืนยันรหัสผ่านถูกต้องแล้วเท่านั้น
  // เพื่อให้ข้อมูลกับผู้ใช้ที่ถูกต้องเท่านั้น
  if (!user.is_active) {
    throw new Error("บัญชีของคุณถูกระงับการใช้งาน กรุณาติดต่อผู้ดูแลระบบ");
  }

  // --- ขั้นตอนที่ 4: สร้าง Access Token (อายุสั้น) ---
  // Token นี้ใช้สำหรับยืนยันตัวตนในการเข้าถึงข้อมูลที่ต้องป้องกัน
  const accessTokenPayload = {
    userId: user.id,
    role: user.role,
  };
  const accessToken = jwt.sign(
    accessTokenPayload,
    process.env.JWT_SECRET,
    { expiresIn: "15m" } // ตั้งค่าอายุให้สั้น (เช่น 15 นาที) คือวิธีปฏิบัติที่ดีที่สุด
  );

  // --- ขั้นตอนที่ 5: สร้างและจัดเก็บ Refresh Token (อายุยาว) ---
  // Token นี้มีหน้าที่เดียว คือการขอ Access Token ใบใหม่
  const refreshToken = crypto.randomBytes(64).toString("hex");
  const refreshTokenExpiry = new Date();
  refreshTokenExpiry.setDate(refreshTokenExpiry.getDate() + 7); // หมดอายุใน 7 วัน

  // ก่อนจะเพิ่ม Token ใหม่, ให้ลบ Token เก่าทั้งหมดของ user นี้ทิ้ง
  // เพื่อเพิ่มความปลอดภัย และบังคับให้ login ได้ทีละ session
  await db.query("DELETE FROM refresh_tokens WHERE user_id = $1", [user.id]);

  // บันทึก Refresh Token ใหม่ลงในฐานข้อมูล
  await db.query(
    "INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)",
    [user.id, refreshToken, refreshTokenExpiry]
  );

  // --- ขั้นตอนที่ 6: เตรียมข้อมูลผู้ใช้เพื่อส่งกลับ ---
  // เราจะไม่ส่งข้อมูลรหัสผ่านกลับไปให้ Client เด็ดขาด
  const userToReturn = {
    id: user.id,
    username: user.username,
    email: user.email,
    role: user.role,
  };

  // --- ขั้นตอนที่ 7: ส่งข้อมูลที่จำเป็นทั้งหมดกลับไป ---
  // Controller จะนำข้อมูลเหล่านี้ไปสร้าง Cookie และ Response Body ต่อไป
  return { accessToken, refreshToken, user: userToReturn };
};

/**
 * ตรวจสอบ Refresh Token และออก Access Token ใบใหม่
 */
const refreshAccessToken = async (tokenFromCookie) => {
  // 1. ตรวจสอบว่ามี token ส่งมาหรือไม่
  if (!tokenFromCookie) {
    throw new Error("ไม่พบ Refresh Token");
  }

  // 2. ค้นหา token ในฐานข้อมูล
  const refreshTokenQueryResult = await db.query(
    "SELECT * FROM refresh_tokens WHERE token = $1",
    [tokenFromCookie]
  );
  const storedToken = refreshTokenQueryResult.rows[0];

  // 3. ถ้าไม่เจอ token หรือ token หมดอายุแล้ว ให้โยน Error
  if (!storedToken) {
    throw new Error("Refresh Token ไม่ถูกต้องหรือไม่ได้รับอนุญาต");
  }
  if (new Date(storedToken.expires_at) < new Date()) {
    await db.query("DELETE FROM refresh_tokens WHERE id = $1", [
      storedToken.id,
    ]);
    throw new Error("Session หมดอายุ กรุณาเข้าสู่ระบบใหม่อีกครั้ง");
  }

  // 4. ค้นหาข้อมูลผู้ใช้จาก user_id ที่ผูกกับ token
  const userQueryResult = await db.query("SELECT * FROM users WHERE id = $1", [
    storedToken.user_id,
  ]);
  const user = userQueryResult.rows[0];
  if (!user || !user.is_active) {
    throw new Error("ไม่พบผู้ใช้หรือบัญชีถูกระงับ");
  }

  // 5. ถ้าทุกอย่างถูกต้อง, สร้าง Access Token ใบใหม่
  const accessTokenPayload = {
    userId: user.id,
    role: user.role,
  };
  const newAccessToken = jwt.sign(accessTokenPayload, process.env.JWT_SECRET, {
    expiresIn: "15m",
  });

  return newAccessToken;
};

module.exports = {
  registerUser,
  loginUser,
  refreshAccessToken,
};
