const http = require('http');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const crypto = require('crypto');

function loadEnv() {
  const p = path.join(__dirname, '.env');
  if (!fs.existsSync(p)) return;
  for (const line of fs.readFileSync(p, 'utf8').split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith('#') || !t.includes('=')) continue;
    const i = t.indexOf('=');
    const k = t.slice(0, i).trim();
    const v = t.slice(i + 1).trim();
    if (!(k in process.env)) process.env[k] = v;
  }
}
loadEnv();

const PORT = Number(process.env.PORT || 3000);
const ADMIN_LOGIN = process.env.ADMIN_LOGIN || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'change_me';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change_this_secret';
const ROOT = __dirname;
const PUBLIC = path.join(ROOT, 'public');
const SETTINGS = path.join(ROOT, 'data', 'settings.json');

const MIME = {
  '.html':'text/html; charset=utf-8', '.css':'text/css; charset=utf-8', '.js':'application/javascript; charset=utf-8',
  '.json':'application/json; charset=utf-8', '.png':'image/png', '.jpg':'image/jpeg', '.jpeg':'image/jpeg', '.svg':'image/svg+xml'
};

const sessions = new Map();
function json(res, status, data, headers={}) {
  res.writeHead(status, {'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...headers});
  res.end(JSON.stringify(data));
}
function parseCookies(req){
  const out={};
  for(const part of String(req.headers.cookie||'').split(';')){
    const i=part.indexOf('='); if(i<0) continue;
    out[part.slice(0,i).trim()] = decodeURIComponent(part.slice(i+1).trim());
  }
  return out;
}
function isAuthed(req){
  const sid = parseCookies(req).kz_admin;
  const s = sid && sessions.get(sid);
  if (!s) return false;
  if (s.expires < Date.now()) { sessions.delete(sid); return false; }
  return true;
}
function safeEqual(a,b){
  const aa=Buffer.from(String(a)), bb=Buffer.from(String(b));
  return aa.length===bb.length && crypto.timingSafeEqual(aa,bb);
}
function collectBody(req, max=512*1024){
  return new Promise((resolve,reject)=>{
    let size=0, chunks=[];
    req.on('data',c=>{size+=c.length;if(size>max){reject(new Error('too_large'));req.destroy();return;}chunks.push(c)});
    req.on('end',()=>resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error',reject);
  });
}
async function readSettings(){return JSON.parse(await fsp.readFile(SETTINGS,'utf8'));}
async function writeSettings(data){
  const tmp=SETTINGS+'.'+process.pid+'.'+Date.now()+'.tmp';
  await fsp.writeFile(tmp, JSON.stringify(data,null,2)+'\n','utf8');
  await fsp.rename(tmp,SETTINGS);
}
function validateSettings(s){
  if(!s||typeof s!=='object'||!s.site||!s.links||!s.buttons||!s.calculator) return 'invalid settings';
  if(!Array.isArray(s.calculator.categories)) return 'categories must be array';
  const ids=new Set();
  for(const c of s.calculator.categories){
    if(!c||!c.id||!c.name) return 'category id/name required';
    if(ids.has(c.id)) return 'duplicate category id'; ids.add(c.id);
    if(!Number.isFinite(Number(c.price))||Number(c.price)<0) return 'invalid category price';
    if(!Number.isFinite(Number(c.order))) return 'invalid category order';
  }
  if(!Number.isFinite(Number(s.calculator.markupPercent))) return 'invalid markup';
  if(!Number.isFinite(Number(s.calculator.minimumAmount))||Number(s.calculator.minimumAmount)<0) return 'invalid minimum';
  return null;
}
function serveFile(res, file){
  if(!fs.existsSync(file) || !fs.statSync(file).isFile()){res.writeHead(404);res.end('Not found');return;}
  const ext=path.extname(file).toLowerCase();
  res.writeHead(200, {'Content-Type':MIME[ext]||'application/octet-stream','Cache-Control':ext==='.html'?'no-cache':'public, max-age=300'});
  fs.createReadStream(file).pipe(res);
}

const server=http.createServer(async (req,res)=>{
  try{
    const u=new URL(req.url,'http://localhost');
    const p=u.pathname;
    if(req.method==='GET'&&p==='/api/settings') return json(res,200,await readSettings());
    if(req.method==='GET'&&p==='/api/admin/me') return json(res,200,{authenticated:isAuthed(req)});
    if(req.method==='POST'&&p==='/api/admin/login'){
      const body=JSON.parse((await collectBody(req))||'{}');
      if(!safeEqual(body.login||'',ADMIN_LOGIN)||!safeEqual(body.password||'',ADMIN_PASSWORD)) return json(res,401,{error:'invalid_credentials'});
      const sid=crypto.randomBytes(32).toString('hex');
      sessions.set(sid,{expires:Date.now()+12*60*60*1000});
      return json(res,200,{ok:true},{'Set-Cookie':`kz_admin=${sid}; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200`});
    }
    if(req.method==='POST'&&p==='/api/admin/logout'){
      const sid=parseCookies(req).kz_admin; if(sid) sessions.delete(sid);
      return json(res,200,{ok:true},{'Set-Cookie':'kz_admin=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0'});
    }
    if(req.method==='PUT'&&p==='/api/admin/settings'){
      if(!isAuthed(req)) return json(res,401,{error:'unauthorized'});
      const body=JSON.parse((await collectBody(req))||'{}');
      const err=validateSettings(body); if(err) return json(res,400,{error:err});
      await writeSettings(body); return json(res,200,{ok:true});
    }
    if(req.method!=='GET'&&req.method!=='HEAD'){res.writeHead(405);return res.end('Method not allowed');}
    if(p==='/admin') {res.writeHead(302,{Location:'/admin/'});return res.end();}
    let file;
    if(p==='/') file=path.join(PUBLIC,'index.html');
    else if(p==='/admin/') file=path.join(PUBLIC,'admin','index.html');
    else {
      const rel=decodeURIComponent(p).replace(/^\/+/, '');
      file=path.normalize(path.join(PUBLIC,rel));
      if(!file.startsWith(PUBLIC)) {res.writeHead(403);return res.end('Forbidden');}
    }
    serveFile(res,file);
  }catch(e){console.error(e);json(res,500,{error:'server_error'});}
});
server.listen(PORT,'0.0.0.0',()=>console.log(`KAZANTIP running: http://127.0.0.1:${PORT}`));
