const express=require('express'),path=require('path'),fs=require('fs'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),cookieParser=require('cookie-parser');

const app=express();
const PORT=process.env.PORT||3000;
const SECRET=process.env.JWT_SECRET||'CHANGE_SECRET';
const DB=path.join(__dirname,'data.json');

const SUPABASE_URL=process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY=process.env.SUPABASE_SERVICE_ROLE_KEY;
const STORAGE_BUCKET='student-documents';

const read=()=>{try{return JSON.parse(fs.readFileSync(DB,'utf8'))}catch{return {admins:[],posts:[]}}};
const write=d=>fs.writeFileSync(DB,JSON.stringify(d,null,2));
let db=read();

if(!db.admins.length){
  db.admins.push({
    id:1,
    username:process.env.ADMIN_USER||'admin',
    passwordHash:bcrypt.hashSync(process.env.ADMIN_PASSWORD||'CHANGE_ME_NOW',12)
  });
  write(db);
}

app.use(express.json({limit:'15mb'}));
app.use(cookieParser());
app.use(express.static(__dirname));

function auth(req,res,next){
  try{
    const t=req.cookies.fjs_token;
    if(!t)return res.status(401).json({error:'Login required'});
    req.admin=jwt.verify(t,SECRET);
    next();
  }catch{
    return res.status(401).json({error:'Invalid session'});
  }
}

function safeText(v,max=200){
  return String(v||'').trim().slice(0,max);
}

function safeFileName(name){
  return String(name||'file')
    .replace(/[^a-zA-Z0-9._-]/g,'_')
    .slice(0,100);
}

function checkSupabase(res){
  if(!SUPABASE_URL||!SUPABASE_SERVICE_ROLE_KEY){
    res.status(500).json({
      error:'Supabase is not configured. Add SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in Render Environment Variables.'
    });
    return false;
  }
  return true;
}

async function supabaseUpload(filePath,buffer,contentType){
  const url=
    SUPABASE_URL.replace(/\/$/,'')+
    '/storage/v1/object/'+
    STORAGE_BUCKET+'/'+
    filePath.split('/').map(encodeURIComponent).join('/');

  const r=await fetch(url,{
    method:'POST',
    headers:{
      'Authorization':'Bearer '+SUPABASE_SERVICE_ROLE_KEY,
      'apikey':SUPABASE_SERVICE_ROLE_KEY,
      'Content-Type':contentType||'application/octet-stream',
      'x-upsert':'false'
    },
    body:buffer
  });

  const text=await r.text();

  if(!r.ok)throw new Error(text||'Supabase upload failed');

  return JSON.parse(text||'{}');
}

async function supabaseList(prefix=''){
  const url=
    SUPABASE_URL.replace(/\/$/,'')+
    '/storage/v1/object/list/'+
    STORAGE_BUCKET;

  const r=await fetch(url,{
    method:'POST',
    headers:{
      'Authorization':'Bearer '+SUPABASE_SERVICE_ROLE_KEY,
      'apikey':SUPABASE_SERVICE_ROLE_KEY,
      'Content-Type':'application/json'
    },
    body:JSON.stringify({
      prefix,
      limit:100,
      offset:0,
      sortBy:{column:'created_at',order:'desc'}
    })
  });

  const text=await r.text();

  if(!r.ok)throw new Error(text||'Supabase list failed');

  return JSON.parse(text||'[]');
}

async function supabaseSignedUrl(filePath){
  const url=
    SUPABASE_URL.replace(/\/$/,'')+
    '/storage/v1/object/sign/'+
    STORAGE_BUCKET+'/'+
    filePath.split('/').map(encodeURIComponent).join('/');

  const r=await fetch(url,{
    method:'POST',
    headers:{
      'Authorization':'Bearer '+SUPABASE_SERVICE_ROLE_KEY,
      'apikey':SUPABASE_SERVICE_ROLE_KEY,
      'Content-Type':'application/json'
    },
    body:JSON.stringify({expiresIn:3600})
  });

  const text=await r.text();

  if(!r.ok)throw new Error(text||'Could not create signed URL');

  const data=JSON.parse(text||'{}');

  return SUPABASE_URL.replace(/\/$/,'')+
    '/storage/v1'+
    (data.signedURL||data.signedUrl||'');
}

/* LOGIN */

app.post('/api/login',(req,res)=>{
  const {username,password}=req.body||{};
  const a=db.admins.find(x=>x.username===username);

  if(!a||!bcrypt.compareSync(password||'',a.passwordHash)){
    return res.status(401).json({error:'Invalid username or password'});
  }

  const t=jwt.sign(
    {id:a.id,username:a.username},
    SECRET,
    {expiresIn:'8h'}
  );

  res.cookie('fjs_token',t,{
    httpOnly:true,
    sameSite:'lax',
    secure:process.env.NODE_ENV==='production',
    maxAge:28800000
  });

  res.json({ok:true});
});

app.post('/api/logout',(req,res)=>{
  res.clearCookie('fjs_token');
  res.json({ok:true});
});

app.get('/api/me',auth,(req,res)=>{
  res.json({username:req.admin.username});
});

/* POSTS */

app.get('/api/posts',(req,res)=>{
  let p=db.posts.slice().reverse();

  if(req.query.type){
    p=p.filter(x=>x.type===req.query.type);
  }

  res.json(p);
});

app.post('/api/posts',auth,(req,res)=>{
  const {
    type,
    title,
    organization='',
    category='',
    last_date='',
    details='',
    official_link=''
  }=req.body||{};

  if(!['job','result','admit','notice'].includes(type)||!title){
    return res.status(400).json({
      error:'Type and title are required'
    });
  }

  const id=(db.posts.at(-1)?.id||0)+1;

  db.posts.push({
    id,
    type,
    title,
    organization,
    category,
    last_date,
    details,
    official_link,
    created_at:new Date().toISOString()
  });

  write(db);

  res.json({id});
});

app.delete('/api/posts/:id',auth,(req,res)=>{
  db.posts=db.posts.filter(
    p=>p.id!==Number(req.params.id)
  );

  write(db);

  res.json({ok:true});
});

/* STUDENT DOCUMENT UPLOAD */

app.post('/api/student/upload',async(req,res)=>{
  try{

    if(!checkSupabase(res))return;

    const {
      name,
      mobile,
      service,
      files
    }=req.body||{};

    if(!name||!mobile||!service){
      return res.status(400).json({
        error:'Name, mobile and service are required'
      });
    }

    if(!/^[0-9]{10}$/.test(String(mobile))){
      return res.status(400).json({
        error:'Enter a valid 10 digit mobile number'
      });
    }

    if(!Array.isArray(files)||!files.length){
      return res.status(400).json({
        error:'Please upload at least one document'
      });
    }

    if(files.length>8){
      return res.status(400).json({
        error:'Maximum 8 documents allowed'
      });
    }

    const applicationId=
      'APP-'+
      Date.now()+'-'+
      Math.random().toString(36).slice(2,8).toUpperCase();

    const folder=applicationId;

    const uploaded=[];

    for(const file of files){

      const originalName=safeFileName(file.name);

      const mime=String(
        file.type||'application/octet-stream'
      );

      const allowed=[
        'image/jpeg',
        'image/png',
        'application/pdf'
      ];

      if(!allowed.includes(mime)){
        return res.status(400).json({
          error:'Only JPG, PNG and PDF files are allowed'
        });
      }

      if(!file.data||typeof file.data!=='string'){
        return res.status(400).json({
          error:'Invalid file data'
        });
      }

      const base64=file.data.replace(
        /^data:[^;]+;base64,/,
        ''
      );

      const buffer=Buffer.from(base64,'base64');

      if(buffer.length>5*1024*1024){
        return res.status(400).json({
          error:'Each document must be 5MB or smaller'
        });
      }

      const filePath=
        folder+'/'+
        Date.now()+'-'+
        Math.random().toString(36).slice(2,7)+'-'+
        originalName;

      await supabaseUpload(
        filePath,
        buffer,
        mime
      );

      uploaded.push({
        name:originalName,
        path:filePath,
        type:mime,
        size:buffer.length
      });
    }

    const metadata={
      application_id:applicationId,
      name:safeText(name,100),
      mobile:String(mobile),
      service:safeText(service,150),
      status:'Received',
      created_at:new Date().toISOString(),
      files:uploaded
    };

    await supabaseUpload(
      folder+'/application.json',
      Buffer.from(JSON.stringify(metadata,null,2)),
      'application/json'
    );

    res.json({
      ok:true,
      application_id:applicationId,
      message:'Documents uploaded successfully'
    });

  }catch(err){

    console.error('Student upload error:',err);

    res.status(500).json({
      error:'Document upload failed'
    });
  }
});

/* ADMIN: SEE STUDENT APPLICATIONS */

app.get('/api/admin/applications',auth,async(req,res)=>{
  try{

    if(!checkSupabase(res))return;

    const folders=await supabaseList('');

    const applications=[];

    for(const item of folders){

      if(item.name==='application.json'){
        continue;
      }

      const applicationId=item.name;

      try{

        const files=await supabaseList(applicationId+'/');

        const metadataFile=files.find(
          x=>x.name==='application.json'
        );

        if(metadataFile){

          const filePath=
            applicationId+'/application.json';

          const url=await supabaseSignedUrl(filePath);

          const r=await fetch(url);

          if(r.ok){
            const data=await r.json();
            applications.push(data);
          }
        }

      }catch(e){
        console.error(
          'Application read error:',
          applicationId,
          e
        );
      }
    }

    applications.sort(
      (a,b)=>
        new Date(b.created_at)-
        new Date(a.created_at)
    );

    res.json(applications);

  }catch(err){

    console.error('Applications error:',err);

    res.status(500).json({
      error:'Could not load applications'
    });
  }
});

/* ADMIN: GET PRIVATE DOCUMENT URL */

app.get('/api/admin/document',auth,async(req,res)=>{
  try{

    if(!checkSupabase(res))return;

    const filePath=String(
      req.query.path||''
    );

    if(!filePath||
       filePath.includes('..')||
       filePath.startsWith('/')){
      return res.status(400).json({
        error:'Invalid document path'
      });
    }

    const url=await supabaseSignedUrl(filePath);

    res.json({
      url,
      expires_in:3600
    });

  }catch(err){

    console.error('Document URL error:',err);

    res.status(500).json({
      error:'Could not open document'
    });
  }
});

/* HOME */

app.get('/',(req,res)=>{
  res.sendFile(
    path.join(__dirname,'index.html')
  );
});

app.listen(PORT,()=>{
  console.log(
    'FastJobSerch running on '+PORT
  );
});
