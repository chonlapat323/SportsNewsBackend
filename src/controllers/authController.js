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
    // authService.loginUser จะยังทำงานเหมือนเดิม คือคืนค่า token และ user
    const { token, user } = await authService.loginUser(email, password);

    // --- ส่วนที่เปลี่ยนแปลง ---
    res.cookie("token", token, {
      httpOnly: true, // ป้องกันการเข้าถึงจาก JavaScript ฝั่ง client
      secure: process.env.NODE_ENV === "production", // ใช้ HTTPS เท่านั้นบน Production
      sameSite: "strict", // ป้องกันการโจมตีแบบ CSRF
      maxAge: 24 * 60 * 60 * 1000, // อายุของ cookie (1 วัน) หน่วยเป็นมิลลิวินาที
    });

    // ส่งแค่ข้อมูล user กลับไป ไม่ต้องส่ง token ใน body แล้ว
    res.status(200).json({
      message: "Login successful!",
      user: user,
    });
    // -------------------------
  } catch (error) {
    res.status(401).json({ message: error.message });
  }
};

module.exports = {
  register,
  login,
};
