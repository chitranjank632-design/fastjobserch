const express = require("express");
const path = require("path");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_SECRET_BEFORE_DEPLOYMENT";

const db = new Database("fastjobserch.db");
db.exec(`
CREATE TABLE IF NOT EXISTS admins(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS posts(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 type TEXT NOT NULL,
 title TEXT NOT NULL,
 organization TEXT DEFAULT '',
 category TEXT DEFAULT '',
 last_date TEXT DEFAULT '',
 details TEXT DEFAULT '',
 official_link TEXT DEFAULT '',
 created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`);

if (!db.prepare("SELECT id FROM admins LIMIT 1").get()) {
  const hash = bcrypt.hashSync(process.env.ADMIN_PASSWORD || "CHANGE_ME_NOW", 12);
  db.prepare("INSERT INTO admins(username,password_hash) VALUES(?,?)")
    .run(process.env.ADMIN_USER || "admin", hash);
}

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

function auth(req,res,next){
  try {
    const token=req.cookies.fjs_token;
    if(!token) return res.status(401).json({error:"Login required"});
    req.admin=jwt.verify(token,JWT_SECRET);
    next();
  } catch { return res.status(401).json({error:"Invalid session"}); }
}

app.post("/api/login",(req,res)=>{
  const {username,password}=req.body||{};
  const admin=db.prepare("SELECT * FROM admins WHERE username=?").get(username);
  if(!admin || !bcrypt.compareSync(password||"",admin.password_hash))
    return res.status(401).json({error:"Invalid username or password"});
  const token=jwt.sign({id:admin.id,username:admin.username},JWT_SECRET,{expiresIn:"8h"});
  res.cookie("fjs_token",token,{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:8*60*60*1000});
  res.json({ok:true});
});

app.post("/api/logout",(req,res)=>{res.clearCookie("fjs_token");res.json({ok:true})});

app.get("/api/posts",(req,res)=>{
  const type=req.query.type;
  const rows=type?db.prepare("SELECT * FROM posts WHERE type=? ORDER BY id DESC").all(type)
                  :db.prepare("SELECT * FROM posts ORDER BY id DESC").all();
  res.json(rows);
});

app.post("/api/posts",auth,(req,res)=>{
  const {type,title,organization="",category="",last_date="",details="",official_link=""}=req.body||{};
  if(!["job","result","admit","notice"].includes(type)||!title)
    return res.status(400).json({error:"Type and title are required"});
  const info=db.prepare(`INSERT INTO posts(type,title,organization,category,last_date,details,official_link)
    VALUES(?,?,?,?,?,?,?)`).run(type,title,organization,category,last_date,details,official_link);
  res.json({id:info.lastInsertRowid});
});

app.delete("/api/posts/:id",auth,(req,res)=>{
  db.prepare("DELETE FROM posts WHERE id=?").run(req.params.id);
  res.json({ok:true});
});

app.get("/api/me",auth,(req,res)=>res.json({username:req.admin.username}));

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`FastJobSerch running on http://localhost:${PORT}`));
