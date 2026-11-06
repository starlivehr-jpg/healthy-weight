const ALLOWED_ORIGINS = new Set([
  "https://healthy-weight.starlive-s.com",
  "https://starlivehr-jpg.github.io"
]);
const encoder = new TextEncoder();
const json = (data, status, headers) => new Response(JSON.stringify(data), {
  status, headers: { "Content-Type":"application/json; charset=utf-8", "Cache-Control":"no-store", ...headers }
});
function cors(origin) {
  const allowed = ALLOWED_ORIGINS.has(origin) ? origin : "https://healthy-weight.starlive-s.com";
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin"
  };
}
function bytesToHex(bytes) {
  return [...new Uint8Array(bytes)].map(v => v.toString(16).padStart(2,"0")).join("");
}
function hexToBytes(hex) {
  return new Uint8Array((hex.match(/.{1,2}/g) || []).map(v => parseInt(v,16)));
}
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({name:"PBKDF2",salt,iterations:100000,hash:"SHA-256"},key,256);
  return "pbkdf2$100000$" + bytesToHex(salt) + "$" + bytesToHex(bits);
}
async function verifyPassword(password, stored) {
  if (!stored) return false;
  if (!stored.startsWith("pbkdf2$")) return stored === password;
  const [,iterations,saltHex,hashHex] = stored.split("$");
  const key = await crypto.subtle.importKey("raw",encoder.encode(password),"PBKDF2",false,["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({name:"PBKDF2",salt:hexToBytes(saltHex),iterations:Number(iterations),hash:"SHA-256"},key,256);
  const actual = new Uint8Array(bits), expected = hexToBytes(hashHex);
  if (actual.length !== expected.length) return false;
  let diff = 0;
  for (let i=0;i<actual.length;i++) diff |= actual[i] ^ expected[i];
  return diff === 0;
}
function bangkokDate() {
  const parts = new Intl.DateTimeFormat("en-CA",{timeZone:"Asia/Bangkok",year:"numeric",month:"2-digit",day:"2-digit"}).formatToParts(new Date());
  const values = Object.fromEntries(parts.map(p=>[p.type,p.value]));
  return values.year + "-" + values.month + "-" + values.day;
}
export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const headers = cors(origin);
    if (request.method === "OPTIONS") return new Response(null,{status:204,headers});
    try {
      if (!env.DB) return json({success:false,message:"Database binding DB is not configured" },500,headers);
      if (request.method === "GET") {
        await env.DB.prepare("SELECT 1 AS ok").first();
        return json({success:true,service:"Healthy Weight API",database:"connected"},200,headers);
      }
      if (request.method !== "POST") return json({success:false,message:"Method not allowed"},405,headers);
      const body = await request.json();
      const action = String(body.action || "");
      if (action === "register") {
        const empId = String(body.empId || "").trim().toUpperCase();
        const nickname = String(body.nickname || "").trim();
        const department = String(body.department || "").trim();
        const password = String(body.password || "");
        const heightCm = Number(body.heightCm);
        const startWeight = Number(body.startWeight);
        const targetWeightKg = Number(body.targetWeightKg);
        if (!empId || !nickname || !department || password.length < 4 || password.length > 128 ||
            !Number.isFinite(heightCm) || !Number.isFinite(startWeight) || !Number.isFinite(targetWeightKg))
          return json({success:false,message:"กรุณากรอกข้อมูลให้ครบทุกช่อง และตั้งรหัสผ่านอย่างน้อย 4 ตัวอักษร"},400,headers);
        if (!/^[A-Z0-9-]{3,20}$/.test(empId))
          return json({success:false,message:"รูปแบบรหัสพนักงานไม่ถูกต้อง กรุณาตรวจสอบอีกครั้ง"},400,headers);
        if (heightCm < 100 || heightCm > 250)
          return json({success:false,message:"ส่วนสูงต้องอยู่ระหว่าง 100–250 เซนติเมตร"},400,headers);
        if (startWeight < 30 || startWeight > 200 || targetWeightKg < 30 || targetWeightKg > 200)
          return json({success:false,message:"น้ำหนักเริ่มต้นและน้ำหนักเป้าหมายต้องอยู่ระหว่าง 30–200 กิโลกรัม"},400,headers);
        if (department.length > 80 || nickname.length > 60)
          return json({success:false,message:"ชื่อเล่นหรือแผนกยาวเกินกำหนด"},400,headers);
        const user = await env.DB.prepare("SELECT emp_id,password FROM employees WHERE emp_id = ?").bind(empId).first();
        if (user?.password && user.password.trim() !== "")
          return json({success:false,message:"รหัสพนักงานนี้มีบัญชีใช้งานแล้ว กรุณาเข้าสู่ระบบ"},200,headers);
        const passwordHash = await hashPassword(password);
        if (user) {
          await env.DB.prepare("UPDATE employees SET password = ?, nickname = ?, name_th = ?, department = ?, height_cm = ?, start_weight = ?, target_weight_kg = ? WHERE emp_id = ?")
            .bind(passwordHash,nickname,nickname,department,heightCm,startWeight,targetWeightKg,empId).run();
        } else {
          // Self-service registration creates a complete employee profile immediately.
          await env.DB.prepare("INSERT INTO employees (emp_id,password,nickname,name_th,department,height_cm,start_weight,target_weight_kg) VALUES (?,?,?,?,?,?,?,?)")
            .bind(empId,passwordHash,nickname,nickname,department,heightCm,startWeight,targetWeightKg).run();
        }
        return json({success:true,message:"ลงทะเบียนสำเร็จ! บันทึกข้อมูลส่วนตัวเรียบร้อยแล้ว สามารถเข้าสู่ระบบได้ทันที"},200,headers);
      }
      if (action === "requestPasswordReset") {
        const empId = String(body.empId || "").trim().toUpperCase();
        const nickname = String(body.nickname || "").trim();
        if (!empId || !nickname)
          return json({success:false,message:"กรุณากรอกรหัสพนักงานและชื่อเล่น"},400,headers);
        if (!/^[A-Z0-9-]{3,20}$/.test(empId))
          return json({success:false,message:"รูปแบบรหัสพนักงานไม่ถูกต้อง"},400,headers);
        const user = await env.DB.prepare("SELECT emp_id,nickname,name_th FROM employees WHERE emp_id = ?").bind(empId).first();
        // Use a generic response to avoid revealing whether an employee ID exists.
        if (user && [user.nickname,user.name_th].filter(Boolean).some(v => String(v).trim().toLocaleLowerCase("th") === nickname.toLocaleLowerCase("th"))) {
          const pending = await env.DB.prepare("SELECT request_id FROM password_reset_requests WHERE emp_id = ? AND status = 'pending' LIMIT 1").bind(empId).first();
          if (!pending) {
            const requestId = "RST" + crypto.randomUUID().replace(/-/g,"");
            await env.DB.prepare("INSERT INTO password_reset_requests (request_id,emp_id,nickname,requested_at,status) VALUES (?,?,?,?,?)")
              .bind(requestId,empId,nickname,new Date().toISOString(),"pending").run();
          }
        }
        return json({success:true,message:"รับคำขอแล้ว หากข้อมูลตรงกับทะเบียนพนักงาน HR จะตรวจสอบและดำเนินการรีเซ็ตรหัสผ่านให้ กรุณาติดต่อ HR หากต้องการเร่งด่วน"},200,headers);
      }
      if (action === "login") {
        const empId = String(body.empId || "").trim().toUpperCase();
        const password = String(body.password || "");
        if (!empId || !password) return json({success:false,message:"กรุณากรอกรหัสพนักงานและรหัสผ่าน"},400,headers);
        const user = await env.DB.prepare("SELECT * FROM employees WHERE emp_id = ?").bind(empId).first();
        if (!user || !(await verifyPassword(password,user.password)))
          return json({success:false,message:"รหัสพนักงานหรือรหัสผ่านไม่ถูกต้อง"},200,headers);
        if (user.password && !user.password.startsWith("pbkdf2$")) {
          const upgraded = await hashPassword(password);
          await env.DB.prepare("UPDATE employees SET password = ? WHERE emp_id = ?").bind(upgraded,empId).run();
        }
        // ส่งข้อมูลประวัติโดยไม่แนบ Base64 ของรูปทั้งหมด เพื่อไม่ให้มือถือใช้หน่วยความจำมาก
        const logs = await env.DB.prepare("SELECT log_id,date,weight_kg,note,CASE WHEN photo_url IS NOT NULL AND photo_url <> '' THEN 1 ELSE 0 END AS has_photo FROM weight_logs WHERE emp_id = ? ORDER BY date DESC, rowid DESC").bind(empId).all();
        const latestWeight = logs.results?.length ? logs.results[0].weight_kg : user.start_weight;
        const start = Number(user.start_weight);
        const latest = Number(latestWeight);
        const weightLost = Number.isFinite(start) && Number.isFinite(latest) ? (start-latest).toFixed(1) : "0.0";
        return json({
          success:true,
          user:{empId:user.emp_id,nickname:user.nickname,nameTh:user.name_th,department:user.department,height:user.height_cm,startWeight:user.start_weight ?? "-"},
          latestWeight:latestWeight ?? "-",
          weightLost,
          logs:(logs.results || []).map(l=>({logId:l.log_id,date:l.date,weight:l.weight_kg,photoAvailable:!!l.has_photo,note:l.note}))
        },200,headers);
      }
      if (action === "getWeightPhoto") {
        const empId = String(body.empId || "").trim().toUpperCase();
        const password = String(body.password || "");
        const logId = String(body.logId || "").trim();
        if (!empId || !password || !logId)
          return json({success:false,message:"ข้อมูลคำขอรูปภาพไม่ครบถ้วน"},400,headers);
        const user = await env.DB.prepare("SELECT password FROM employees WHERE emp_id = ?").bind(empId).first();
        if (!user || !(await verifyPassword(password,user.password)))
          return json({success:false,message:"กรุณาเข้าสู่ระบบใหม่ก่อนเปิดรูปหลักฐาน"},401,headers);
        const photo = await env.DB.prepare("SELECT photo_url FROM weight_logs WHERE log_id = ? AND emp_id = ?").bind(logId,empId).first();
        if (!photo?.photo_url) return json({success:false,message:"ไม่พบรูปหลักฐานรายการนี้"},404,headers);
        return json({success:true,photoUrl:photo.photo_url},200,headers);
      }
      if (action === "submitWeight") {
        const empId = String(body.empId || "").trim().toUpperCase();
        const password = String(body.password || "");
        const weight = Number(body.weight);
        const photoUrl = String(body.photoUrl || "");
        const note = String(body.note || "").slice(0,1000);
        if (!empId || !password) return json({success:false,message:"กรุณาเข้าสู่ระบบใหม่ก่อนบันทึกข้อมูล"},401,headers);
        if (!Number.isFinite(weight) || weight < 30 || weight > 200)
          return json({success:false,message:"น้ำหนักต้องอยู่ระหว่าง 30–200 กก."},400,headers);
        if (!/^data:image\/(jpeg|png|webp);base64,/.test(photoUrl) || photoUrl.length > 850000)
          return json({success:false,message:"กรุณาแนบรูปหลักฐานที่ถูกต้อง และมีขนาดไม่เกินกำหนด"},400,headers);
        const user = await env.DB.prepare("SELECT emp_id,password,start_weight FROM employees WHERE emp_id = ?").bind(empId).first();
        if (!user || !(await verifyPassword(password,user.password)))
          return json({success:false,message:"เซสชันหมดอายุหรือรหัสผ่านไม่ถูกต้อง กรุณาเข้าสู่ระบบใหม่"},401,headers);
        const logId = "LOG" + crypto.randomUUID().replace(/-/g,"");
        await env.DB.prepare("INSERT INTO weight_logs (log_id,date,emp_id,weight_kg,photo_url,verified_by,note) VALUES (?,?,?,?,?,?,?)")
          .bind(logId,bangkokDate(),empId,weight,photoUrl,"Self-Service",note).run();
        if (user.start_weight === null || user.start_weight === undefined || user.start_weight === "")
          await env.DB.prepare("UPDATE employees SET start_weight = ? WHERE emp_id = ?").bind(weight,empId).run();
        return json({success:true,message:"บันทึกน้ำหนักและรูปหลักฐานเรียบร้อยแล้ว"},200,headers);
      }
      return json({success:false,message:"ไม่รู้จักคำสั่งที่ร้องขอ"},400,headers);
    } catch (error) {
      return json({success:false,message:"Server Error: " + (error?.message || "Unknown error")},500,headers);
    }
  }
};