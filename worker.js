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
  const bits = await crypto.subtle.deriveBits({name:"PBKDF2",salt,iterations:120000,hash:"SHA-256"},key,256);
  return "pbkdf2$120000$" + bytesToHex(salt) + "$" + bytesToHex(bits);
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
        const password = String(body.password || "");
        if (!empId || !nickname || password.length < 4 || password.length > 128)
          return json({success:false,message:"กรุณากรอกข้อมูลให้ครบ และตั้งรหัสผ่านอย่างน้อย 4 ตัวอักษร"},400,headers);
        const user = await env.DB.prepare("SELECT emp_id,password FROM employees WHERE emp_id = ?").bind(empId).first();
        if (!user) return json({success:false,message:"ไม่พบรหัสพนักงานในระบบ กรุณาติดต่อ HR"},200,headers);
        if (user.password && user.password.trim() !== "")
          return json({success:false,message:"รหัสพนักงานนี้เคยลงทะเบียนเปิดใช้งานแล้ว"},200,headers);
        const passwordHash = await hashPassword(password);
        await env.DB.prepare("UPDATE employees SET password = ?, nickname = ? WHERE emp_id = ?")
          .bind(passwordHash,nickname,empId).run();
        return json({success:true,message:"ลงทะเบียนสำเร็จ! กรุณาเข้าสู่ระบบ"},200,headers);
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
        const logs = await env.DB.prepare("SELECT date,weight_kg,photo_url,note FROM weight_logs WHERE emp_id = ? ORDER BY date DESC, rowid DESC").bind(empId).all();
        const latestWeight = logs.results?.length ? logs.results[0].weight_kg : user.start_weight;
        const start = Number(user.start_weight);
        const latest = Number(latestWeight);
        const weightLost = Number.isFinite(start) && Number.isFinite(latest) ? (start-latest).toFixed(1) : "0.0";
        return json({
          success:true,
          user:{empId:user.emp_id,nickname:user.nickname,nameTh:user.name_th,department:user.department,height:user.height_cm,startWeight:user.start_weight ?? "-"},
          latestWeight:latestWeight ?? "-",
          weightLost,
          logs:(logs.results || []).map(l=>({date:l.date,weight:l.weight_kg,photoUrl:l.photo_url,note:l.note}))
        },200,headers);
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