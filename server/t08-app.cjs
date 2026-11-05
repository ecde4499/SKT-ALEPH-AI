'use strict';
// T08: public T01 introduction + private passkey-only area. No passwords.
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const helmet = require('helmet');
const { Pool } = require('pg');
const {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const ROOT = path.resolve(__dirname, '..');
const ORIGIN = process.env.ORIGIN || 'http://localhost:3000';
const RP_ID = process.env.RP_ID || new URL(ORIGIN).hostname;
const SESSION_MS = 24 * 60 * 60 * 1000;
const CHALLENGE_MS = 3 * 60 * 1000;
const COOKIE = process.env.NODE_ENV === 'production' ? '__Host-t08_session' : 't08_session';
const random = () => crypto.randomUUID();
const digest = s => crypto.createHash('sha256').update(s).digest('hex');
const cookie = req => String(req.headers.cookie || '').split(';').map(v => v.trim())
  .find(v => v.startsWith(COOKIE + '='))?.slice(COOKIE.length + 1) || '';
const safeName = x => typeof x === 'string' && /^[a-zA-Z0-9_-]{3,32}$/.test(x) ? x.toLowerCase() : null;
const label = x => typeof x === 'string' && x.trim().length > 0 && x.trim().length <= 40 && !/[\r\n<>]/.test(x) ? x.trim() : null;
const fail = (res, status, message) => res.status(status).json({error:message});
const userText = row => ({id:row.id, username:row.username});

function configCheck() {
  const origin = new URL(ORIGIN);
  if (origin.origin !== ORIGIN || origin.hostname !== RP_ID ||
      (origin.protocol !== 'https:' && !(origin.protocol === 'http:' && origin.hostname === 'localhost'))) {
    throw new Error('T08 ORIGIN/RP_ID must be a matching HTTPS site or local localhost');
  }
  if (process.env.T08_DB_ACK !== 'I_VERIFIED_T08_ONLY' || !process.env.DATABASE_URL) {
    throw new Error('Refusing to start without separate T08 database acknowledgement');
  }
  const db = new URL(process.env.DATABASE_URL);
  if (!/^postgres(ql)?:$/.test(db.protocol) || !/^\/t08_[a-z0-9_]+$/i.test(db.pathname)) {
    throw new Error('T08 requires a dedicated database named t08_* (not T01/T06/T07)');
  }
}

function createApp(pool) {
  const app = express();
  if (process.env.NODE_ENV === 'production') app.set('trust proxy', 1);
  app.disable('x-powered-by');
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc:["'self'"], scriptSrc:["'self'"], styleSrc:["'self'","https://fonts.googleapis.com"],
        fontSrc:["'self'","https://fonts.gstatic.com"], imgSrc:["'self'","data:"],
        connectSrc:["'self'"], objectSrc:["'none'"], baseUri:["'none'"],
        formAction:["'self'"], frameAncestors:["'none'"],
      },
    },
  }));
  app.use(express.json({limit:'96kb', strict:true}));
  // Only original public resources and T08-specific scripts are served. No database files.
  const assets = {
    '/':'index.html', '/style.css':'style.css', '/script.js':'script.js',
    '/vault.css':'vault.css', '/vault.js':'vault.js'
  };
  for (const [route, file] of Object.entries(assets)) {
    app.get(route, (_req, res) => res.sendFile(path.join(ROOT, file)));
  }
  app.get('/vendor/simplewebauthn.js', (_req,res) =>
    res.sendFile(path.join(ROOT, 'node_modules/@simplewebauthn/browser/dist/bundle/index.umd.min.js')));
  const stats = new Map();
  function rateLimit(req,res,next) {
    const key = String(req.ip) + '|' + req.path;
    const now = Date.now(), previous = stats.get(key);
    const item = !previous || previous.until < now
      ? {n:0,until:now + 10*60*1000} : previous;
    if (++item.n > 80) return fail(res,429,'요청이 너무 많습니다. 잠시 후 다시 시도하세요.');
    if (stats.size > 2000) stats.clear();
    stats.set(key,item);
    next();
  }
  app.use('/api/t08', rateLimit);
  app.use('/api/t08', (req,res,next) => {
    if (['POST','PUT','PATCH','DELETE'].includes(req.method) &&
        req.get('origin') !== ORIGIN) return fail(res,403,'허용되지 않은 요청 출처입니다.');
    next();
  });
  async function auth(req,res,next) {
    const token = cookie(req);
    if (!/^[a-f0-9]{64}$/.test(token)) return fail(res,401,'패스키 로그인이 필요합니다.');
    try {
      const r = await pool.query(
        'SELECT u.id,u.username FROM t08_sessions s JOIN t08_users u ON u.id=s.user_id ' +
        'WHERE s.token_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>now()', [digest(token)]);
      if (!r.rowCount) return fail(res,401,'패스키 로그인이 필요합니다.');
      req.user = r.rows[0];
      next();
    } catch(err) { next(err); }
  }
  const wrap = fn => async (req,res,next) => { try { await fn(req,res); } catch(e) { next(e); } };
  async function session(res, userId) {
    const token = crypto.randomBytes(32).toString('hex');
    await pool.query('INSERT INTO t08_sessions(token_hash,user_id,expires_at) VALUES($1,$2,$3)',
      [digest(token),userId,new Date(Date.now()+SESSION_MS)]);
    res.cookie(COOKIE,token,{path:'/',httpOnly:true,secure:process.env.NODE_ENV==='production',
      sameSite:'strict',maxAge:SESSION_MS});
  }
  async function consume(id,types) {
    if (typeof id!=='string'|| !/^[0-9a-f-]{36}$/i.test(id)) return null;
    const {rows} = await pool.query(
      'DELETE FROM t08_challenges WHERE id=$1 AND type=ANY($2::text[]) AND expires_at>now() RETURNING *',
      [id,types]);
    return rows[0] || null;
  }
  async function challenge(type, options, fields) {
    await pool.query('DELETE FROM t08_challenges WHERE expires_at < now()');
    const id=random();
    await pool.query('INSERT INTO t08_challenges(id,type,challenge,user_id,username,display_name,user_handle,expires_at) '+
      'VALUES($1,$2,$3,$4,$5,$6,$7,$8)',
      [id,type,options.challenge,fields.user_id||null,fields.username||null,
        fields.name||null,fields.handle||null,new Date(Date.now()+CHALLENGE_MS)]);
    return {transaction_id:id, options};
  }
  app.get('/api/t08/health', wrap(async (_req,res) => {
    await pool.query('SELECT 1');
    res.json({ok:true,service:'t08',database:'connected'});
  }));
  app.get('/api/t08/me', auth, (req,res)=>res.json({user:userText(req.user)}));
  app.post('/api/t08/register/options', wrap(async (req,res) => {
    const currentToken = cookie(req);
    let current=null;
    if (/^[a-f0-9]{64}$/.test(currentToken)) {
      const a=await pool.query(
        'SELECT u.* FROM t08_sessions s JOIN t08_users u ON u.id=s.user_id '+
        'WHERE s.token_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>now()',
        [digest(currentToken)]);
      current=a.rows[0]||null;
    }
    const name=label(req.body?.name);
    if (!name) return fail(res,400,'패스키 이름은 1~40자로 입력하세요.');
    let username,handle,userId,existing=[];
    if (current) {
      username=current.username;handle=current.user_handle;userId=current.id;
      existing=(await pool.query('SELECT id,transports FROM t08_passkeys WHERE user_id=$1',
        [userId])).rows;
      if (existing.length>=5) return fail(res,409,'패스키는 최대 5개까지 등록할 수 있습니다.');
    } else {
      username=safeName(req.body?.username);
      if (!username) return fail(res,400,'계정 별명은 영문·숫자·_·-의 3~32자만 사용하세요.');
      if ((await pool.query('SELECT 1 FROM t08_users WHERE username=$1',[username])).rowCount)
        return fail(res,409,'이미 사용 중인 계정 별명입니다.');
      handle=crypto.randomBytes(32).toString('base64url');
      userId=random();
    }
    const options=await generateRegistrationOptions({
      rpName:'나의 소개 페이지 · 패스키',rpID:RP_ID,
      userName:username,userDisplayName:username,
      userID:new Uint8Array(Buffer.from(handle,'base64url')),
      attestationType:'none',
      excludeCredentials:existing.map(x=>({id:x.id,transports:x.transports||[]})),
      authenticatorSelection:{residentKey:'required',userVerification:'required'},
    });
    res.json(await challenge(current?'register-add':'register-new',options,
      {user_id:userId,username,name,handle}));
  }));
  app.post('/api/t08/register/verify', wrap(async (req,res) => {
    const pending=await consume(req.body?.transaction_id,['register-new','register-add']);
    if (!pending) return fail(res,400,'등록 질문이 만료됐거나 이미 사용됐습니다.');
    if (pending.type==='register-add') {
      const token=cookie(req);
      const result=/^[a-f0-9]{64}$/.test(token) ? await pool.query(
        'SELECT 1 FROM t08_sessions WHERE token_hash=$1 AND user_id=$2 '+
        'AND revoked_at IS NULL AND expires_at>now()', [digest(token),pending.user_id]) : {rowCount:0};
      if (!result.rowCount) return fail(res,401,'다른 계정의 패스키를 추가할 수 없습니다.');
    }
    let verified;
    try {
      verified=await verifyRegistrationResponse({
        response:req.body?.credential,expectedChallenge:pending.challenge,
        expectedOrigin:ORIGIN,expectedRPID:RP_ID,requireUserVerification:true,
      });
    } catch { return fail(res,400,'패스키 등록 서명을 검증하지 못했습니다.'); }
    if (!verified.verified) return fail(res,400,'패스키 등록 검증에 실패했습니다.');
    const info=verified.registrationInfo;
    const key=info.credential;
    const client=await pool.connect();
    try {
      await client.query('BEGIN');
      if (pending.type==='register-new') {
        await client.query('INSERT INTO t08_users(id,username,user_handle) VALUES($1,$2,$3)',
          [pending.user_id,pending.username,pending.user_handle]);
      } else {
        const count=await client.query('SELECT count(*)::int AS n FROM t08_passkeys WHERE user_id=$1',
          [pending.user_id]);
        if (count.rows[0].n>=5) throw new Error('TOO_MANY_KEYS');
      }
      await client.query(
        'INSERT INTO t08_passkeys(id,user_id,name,public_key,counter,transports,device_type,backed_up) '+
        'VALUES($1,$2,$3,$4,$5,$6,$7,$8)',
        [key.id,pending.user_id,pending.display_name,Buffer.from(key.publicKey),
         key.counter,key.transports||[],info.credentialDeviceType,info.credentialBackedUp]);
      if (pending.type==='register-new') {
        const samples=[
          ['프로젝트 준비 메모','[가상 데이터] 공개 소개 사이트에 접근 제어를 추가하는 작업 아이디어'],
          ['지원 목록 예시','[가상 데이터] A회사, B회사, C회사 — 실제 지원 기록 아님'],
          ['개인 회고 예시','[가상 데이터] 오늘 잘한 점: 테스트 코드를 먼저 작성하기'],
        ];
        for(const [title,body] of samples)await client.query(
          'INSERT INTO t08_notes(id,user_id,title,body) VALUES($1,$2,$3,$4)',
          [random(),pending.user_id,title,body+' (시연 계정: '+pending.username+')']);
      }
      await client.query('COMMIT');
    } catch(e) {
      await client.query('ROLLBACK');
      if(e.code==='23505') return fail(res,409,'이미 등록된 계정 또는 패스키입니다.');
      if(e.message==='TOO_MANY_KEYS') return fail(res,409,'패스키 등록 개수 제한을 넘었습니다.');
      throw e;
    } finally { client.release(); }
    if(pending.type==='register-new') await session(res,pending.user_id);
    res.status(201).json({ok:true,type:pending.type,public_key_stored:true});
  }));
  app.post('/api/t08/login/options', wrap(async (req,res) => {
    const username=safeName(req.body?.username);
    if (!username) return fail(res,400,'계정 별명을 확인하세요.');
    const user=(await pool.query('SELECT id FROM t08_users WHERE username=$1',[username])).rows[0];
    if(!user) return fail(res,404,'등록된 패스키 계정을 찾지 못했습니다.');
    const keys=(await pool.query('SELECT id,transports FROM t08_passkeys WHERE user_id=$1',[user.id])).rows;
    if(!keys.length) return fail(res,409,'등록된 패스키가 없습니다. 복구가 필요합니다.');
    const options=await generateAuthenticationOptions({
      rpID:RP_ID,userVerification:'required',
      allowCredentials:keys.map(x=>({id:x.id,transports:x.transports||[]}))
    });
    res.json(await challenge('login',options,{user_id:user.id}));
  }));
  app.post('/api/t08/login/verify', wrap(async(req,res)=>{
    const pending=await consume(req.body?.transaction_id,['login']);
    if(!pending)return fail(res,401,'로그인 질문이 만료됐거나 이미 사용됐습니다.');
    const key=(await pool.query('SELECT * FROM t08_passkeys WHERE id=$1 AND user_id=$2',
      [req.body?.credential?.id||'',pending.user_id])).rows[0];
    if(!key)return fail(res,403,'이 계정에 등록되지 않은 패스키입니다.');
    let verification;
    try {
      verification=await verifyAuthenticationResponse({
        response:req.body.credential,expectedChallenge:pending.challenge,
        expectedOrigin:ORIGIN,expectedRPID:RP_ID,requireUserVerification:true,
        credential:{id:key.id,publicKey:new Uint8Array(key.public_key),
          counter:Number(key.counter),transports:key.transports||[]},
      });
    } catch {return fail(res,403,'패스키 서명이 일치하지 않습니다.');}
    if(!verification.verified)return fail(res,403,'패스키 인증에 실패했습니다.');
    await pool.query('UPDATE t08_passkeys SET counter=$2,last_used_at=now() WHERE id=$1',
      [key.id,verification.authenticationInfo.newCounter]);
    await session(res,pending.user_id);
    res.json({ok:true});
  }));
  app.post('/api/t08/logout', wrap(async(req,res)=>{
    const token=cookie(req);
    if(/^[a-f0-9]{64}$/.test(token))await pool.query(
      'UPDATE t08_sessions SET revoked_at=now() WHERE token_hash=$1',[digest(token)]);
    res.clearCookie(COOKIE,{path:'/',httpOnly:true,sameSite:'strict',
      secure:process.env.NODE_ENV==='production'});
    res.json({ok:true});
  }));
  app.get('/api/t08/notes',auth,wrap(async(req,res)=>{
    const rows=(await pool.query(
      'SELECT id,title,body,created_at FROM t08_notes WHERE user_id=$1 ORDER BY created_at,id',
      [req.user.id])).rows;
    res.json({notes:rows});
  }));
  app.get('/api/t08/notes/:id',auth,wrap(async(req,res)=>{
    const rows=(await pool.query(
      'SELECT id,title,body FROM t08_notes WHERE id=$1 AND user_id=$2',
      [req.params.id,req.user.id])).rows;
    if(!rows[0])return fail(res,404,'다른 계정의 비공개 항목을 볼 수 없습니다.');
    res.json({note:rows[0]});
  }));
  app.get('/api/t08/passkeys',auth,wrap(async(req,res)=>{
    const rows=(await pool.query(
      'SELECT id,name,created_at,last_used_at FROM t08_passkeys WHERE user_id=$1 ORDER BY created_at,id',
      [req.user.id])).rows;
    res.json({passkeys:rows});
  }));
  app.get('/api/t08/passkeys/public-key',auth,wrap(async(req,res)=>{
    const rows=(await pool.query(
      'SELECT id,name,encode(public_key,$2) AS public_key_hex FROM t08_passkeys WHERE user_id=$1 ORDER BY created_at',
      [req.user.id,'hex'])).rows;
    res.json({description:'공개키(COSE 바이트의 hex 인코딩)만 저장합니다. 개인키/비밀번호는 서버에 없습니다.',keys:rows});
  }));
  app.post('/api/t08/passkeys/:id/delete',auth,wrap(async(req,res)=>{
    const client=await pool.connect();
    try{
      await client.query('BEGIN');
      await client.query('SELECT id FROM t08_users WHERE id=$1 FOR UPDATE',[req.user.id]);
      const keys=await client.query('SELECT id FROM t08_passkeys WHERE user_id=$1 FOR UPDATE',
        [req.user.id]);
      if(keys.rowCount<=1) {
        await client.query('ROLLBACK');
        return fail(res,409,'마지막 패스키는 삭제할 수 없습니다. 분실 전 두 개를 등록하세요.');
      }
      const deleted=await client.query('DELETE FROM t08_passkeys WHERE id=$1 AND user_id=$2 RETURNING id',
        [req.params.id,req.user.id]);
      if(!deleted.rowCount) {
        await client.query('ROLLBACK');
        return fail(res,404,'해당 패스키를 찾을 수 없습니다.');
      }
      await client.query('COMMIT');
      res.json({ok:true});
    } catch(e){await client.query('ROLLBACK');throw e;}finally{client.release();}
  }));
  app.get('/private',auth,(_req,res)=>res.sendFile(path.join(ROOT,'index.html')));
  app.use((err,req,res,_next)=>{
    if(!res.headersSent){console.error('T08 request error',err.code||err.name||'unknown');
      fail(res,500,'요청을 처리할 수 없습니다.');}
  });
  return app;
}

async function main(){
  configCheck();
  const pool=new Pool({
    connectionString:process.env.DATABASE_URL,
    ssl:process.env.DATABASE_SSL==='true'?{rejectUnauthorized:false}:false,
    max:5,
  });
  try {
    await pool.query(fs.readFileSync(path.join(__dirname,'schema.sql'),'utf8'));
    const app=createApp(pool);
    const server=app.listen(Number(process.env.PORT)||3000,'0.0.0.0',()=>{
      console.log('T08 public introduction + passkey-protected service listening');
    });
    for(const sig of ['SIGTERM','SIGINT'])process.once(sig,()=>{
      server.close(async()=>{await pool.end();process.exit(0);});
    });
  }catch(e){console.error('T08 startup failed',e.code||e.name);await pool.end();process.exit(1);}
}
if(require.main===module)main();
module.exports={createApp,configCheck};
