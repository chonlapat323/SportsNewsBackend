const authService = require("../services/authService"); //  Import Service

const register = async (req, res) => {
  try {
    // ส่ง req.body ทั้งหมดไปให้ Service จัดการ
    const newUser = await authService.registerUser(req.body);

    // ถ้าสำเร็จ ส่งข้อมูลผู้ใช้ใหม่กลับไป
    res.status(201).json({
      message: "User registered successfully!",
      user: newUser,
    });
  } catch (error) {
    // จัดการ Error ที่ถูกโยนมาจาก Service
    // ถ้าเป็น error ที่เราคาดไว้ (เช่น 'Username already exists') ก็ส่ง 400
    if (
      error.message.includes("required") ||
      error.message.includes("exists")
    ) {
      return res.status(400).json({ message: error.message });
    }
    // ถ้าเป็น error อื่นๆ ที่ไม่คาดคิด
    res
      .status(500)
      .json({ message: "An unexpected error occurred", error: error.message });
  }
};

const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // 1. รับค่า accessToken, refreshToken, และ user จาก Service
    const { accessToken, refreshToken, user } = await authService.loginUser(
      email,
      password
    );

    // 2. ตั้งค่า refreshToken ใน HttpOnly Cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 วัน
    });

    // 3. ส่ง accessToken และข้อมูล user กลับไปใน JSON Body
    res.status(200).json({
      message: "Login successful!",
      accessToken: accessToken,
      user: user,
    });
  } catch (error) {
    // 4. จัดการ Error ที่ส่งมาจาก Service
    if (
      error.message.includes("อีเมลหรือรหัสผ่านไม่ถูกต้อง") ||
      error.message.includes("บัญชีของคุณถูกระงับ")
    ) {
      return res.status(401).json({ message: error.message });
    }
    console.error("Login Error:", error);
    res.status(500).json({ message: "เกิดข้อผิดพลาดในระบบระหว่างการล็อกอิน" });
  }
};

const refresh = async (req, res) => {
  try {
    const tokenFromCookie = req.cookies.refreshToken;
    if (!tokenFromCookie) {
      return res
        .status(401)
        .json({ message: "Access Denied. No refresh token provided." });
    }

    const newAccessToken = await authService.refreshAccessToken(
      tokenFromCookie
    );

    res.status(200).json({
      message: "Access token refreshed successfully.",
      accessToken: newAccessToken,
    });
  } catch (error) {
    if (
      error.message.includes("Refresh Token") ||
      error.message.includes("Session หมดอายุ")
    ) {
      return res.status(403).json({ message: error.message });
    }
    console.error("Refresh Token Error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

module.exports = {
  register,
  login,
  refresh,
};
