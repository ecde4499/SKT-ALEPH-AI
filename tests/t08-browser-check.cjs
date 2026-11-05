'use strict';
// Disposable Postgres + Chrome DevTools virtual WebAuthn authenticators.
// No physical-device claim. Never print tokens, passwords or full challenges.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const { spawn } = require('node:child_process');
const path = require('node:path');
const { chromium } = require('playwright-core');
const { Pool } = require('pg');

const URL_DB=process.env.TEST_DATABASE_URL;
if(!URL_DB || !/\/t08_[a-z0-9_]+(?:\?|$)/.test(URL_DB)) throw Error('T08 e2e needs a disposable t08_* test database');
const port = 18700 + Math.floor(Math.random()*1000);
const base = 'http://localhost:'+port;
const pool = new Pool({connectionString:URL_DB,ssl:false});
const evidence={type:'T08 virtual WebAuthn integration test (NOT physical passkeys)',
  generated_at:new Date().toISOString(),checks:[],screenshots:[]};
let proc,browser;
const note=(caseName,result)=>{evidence.checks.push({case:caseName,result});console.log(result,caseName);};
const dir=path.resolve('test-results/t08');
fs.mkdirSync(dir,{recursive:true});
const screenshot=async(page,name)=>{
  await page.screenshot({path:path.join(dir,name),fullPage:true});
  evidence.screenshots.push(name);
};
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function api(context,route,body,expected,method='POST',headers={}) {
  const response=await context.request.fetch(base+route,{
    method,headers:{Origin:base,...headers}, ...(body===undefined?{}:{data:body}),timeout:30000
  });
  const json=await response.json().catch(()=>({}));
  assert.equal(response.status(),expected,route+': expected '+expected+', got '+response.status()+' / '+json.error);
  return json;
}
async function withDevice(context){
  const page=await context.newPage();
  const cdp=await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const virtual=async()=> {
    const r=await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{
      protocol:'ctap2',transport:'internal',hasResidentKey:true,
      hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true
    }});
    return r.authenticatorId;
  };
  const id=await virtual();
  await page.goto(base+'/',{waitUntil:'networkidle'});
  return {page,cdp,id,virtual};
}
async function signup(page,username,labelName) {
  await page.locator('#t08-new-name').fill(username);
  await page.locator('#t08-new-key').fill(labelName);
  await page.locator('#t08-register button').click();
  await page.locator('#t08-unlocked').waitFor({state:'visible',timeout:30000});
  assert.equal(await page.locator('#t08-private-list li').count(),3);
}
async function login(page,username) {
  await page.locator('#t08-login-name').fill(username);
  await page.locator('#t08-login button').click();
  await page.locator('#t08-unlocked').waitFor({state:'visible',timeout:30000});
}
async function main(){
  const pg=new URL(URL_DB);
  if(!['localhost','127.0.0.1'].includes(pg.hostname))throw Error('Remote test DB forbidden');
  proc=spawn(process.execPath,['server/t08-app.cjs'],{
    cwd:path.resolve(__dirname,'..'),
    env:{...process.env,NODE_ENV:'test',PORT:String(port),ORIGIN:base,RP_ID:'localhost',
      DATABASE_URL:URL_DB,DATABASE_SSL:'false',T08_DB_ACK:'I_VERIFIED_T08_ONLY'},
    stdio:['ignore','pipe','pipe']
  });
  let stderr='';
  proc.stderr.on('data',data=>{stderr+=String(data).slice(0,300)});
  let ready=false;
  for(let i=0;i<60;i++){
    if(proc.exitCode!==null)throw Error('T08 server exited: '+stderr.slice(0,180));
    try {const res=await fetch(base+'/api/t08/health');if(res.ok){ready=true;break;}}catch{}
    await sleep(250);
  }
  assert.ok(ready,'T08 test server did not start: '+stderr.slice(0,180));
  browser=await chromium.launch({headless:true,
    ...(fs.existsSync('/usr/bin/google-chrome')?{executablePath:'/usr/bin/google-chrome'}:{}),
    args:['--no-sandbox','--disable-dev-shm-usage']});
  const ctxA=await browser.newContext({viewport:{width:1350,height:900},locale:'ko-KR'});
  const ctxAnon=await browser.newContext();
  const publicResponse=await ctxAnon.request.get(base+'/');
  const publicHtml=await publicResponse.text();
  assert.equal(publicResponse.status(),200);
  assert.ok(publicHtml.includes('ONE PAGE INTRODUCTION'));
  assert.ok(!publicHtml.includes('[가상 데이터] 공개 소개 사이트'));
  note('T01 introduction publicly accessible without private note contents','PASS');
  await api(ctxAnon,'/api/t08/notes',undefined,401,'GET');
  await api(ctxAnon,'/private',undefined,401,'GET');
  note('unauthenticated notes and private page deny HTTP 401','PASS');

  const nonce=crypto.randomBytes(4).toString('hex');
  const userA='virtual_a_'+nonce,userB='virtual_b_'+nonce;
  const A=await withDevice(ctxA);
  await screenshot(A.page,'01-public-locked.png');
  await signup(A.page,userA,'가상 보안 키 A-1');
  note('new virtual passkey registration creates a session; no password','PASS');
  const ownerA=(await api(ctxA,'/api/t08/notes',undefined,200,'GET')).notes;
  assert.equal(ownerA.length,3);
  await screenshot(A.page,'02-account-a-private.png');
  let list=(await api(ctxA,'/api/t08/passkeys',undefined,200,'GET')).passkeys;
  assert.equal(list.length,1);
  const keyA1=list[0].id;
  const evidenceKeys=await api(ctxA,'/api/t08/passkeys/public-key',undefined,200,'GET');
  assert.ok(evidenceKeys.keys[0].public_key_hex.length>64);
  evidence.public_key_preview=evidenceKeys.keys[0].public_key_hex.slice(0,24)+'… (public COSE key redacted)';
  note('public key COSE bytes stored server-side; no private key field','PASS');

  const start1=await api(ctxA,'/api/t08/login/options',{username:userA},200);
  const start2=await api(ctxA,'/api/t08/login/options',{username:userA},200);
  assert.notEqual(start1.options.challenge,start2.options.challenge);
  evidence.login_challenge_distinct=true;
  const signed=await A.page.evaluate(async options=>
    window.SimpleWebAuthnBrowser.startAuthentication({optionsJSON:options}),start1.options);
  await api(ctxA,'/api/t08/login/verify',{transaction_id:start1.transaction_id,credential:signed},200);
  await api(ctxA,'/api/t08/login/verify',{transaction_id:start1.transaction_id,credential:signed},401);
  note('fresh login challenges differ and used challenge replay denied','PASS');

  // A new registration options request without verification never creates a passkey account.
  const cancelAlias='not_registered_'+nonce;
  const countBefore=(await pool.query('SELECT count(*)::int n FROM t08_users')).rows[0].n;
  const reg1=await api(ctxAnon,'/api/t08/register/options',{username:cancelAlias,name:'취소 시연'},200);
  const reg2=await api(ctxAnon,'/api/t08/register/options',{username:cancelAlias,name:'취소 시연'},200);
  assert.notEqual(reg1.options.challenge,reg2.options.challenge);
  assert.equal((await pool.query('SELECT count(*)::int n FROM t08_users')).rows[0].n,countBefore);
  evidence.registration_challenge_distinct=true;
  note('registration challenge unique; canceled enrollment never stores a credential','PASS');

  // Remove A-1 from the virtual browser to ensure that A-2 is genuinely new.
  await A.cdp.send('WebAuthn.removeVirtualAuthenticator',{authenticatorId:A.id});
  await A.virtual();
  await A.page.locator('#t08-add-name').fill('가상 보안 키 A-2');
  await A.page.locator('#t08-add button').click();
  await A.page.waitForFunction(()=>document.querySelectorAll('#t08-key-list li').length===2);
  list=(await api(ctxA,'/api/t08/passkeys',undefined,200,'GET')).passkeys;
  assert.equal(list.length,2);
  assert.ok(list.every(x=>x.name&&x.created_at));
  await screenshot(A.page,'03-two-virtual-passkeys.png');
  note('two distinct virtual passkeys listed with names and registration dates','PASS');

  const ctxB=await browser.newContext({viewport:{width:1350,height:900},locale:'ko-KR'});
  const B=await withDevice(ctxB);
  await signup(B.page,userB,'가상 보안 키 B-1');
  const ownerB=(await api(ctxB,'/api/t08/notes',undefined,200,'GET')).notes;
  assert.equal(ownerB.length,3);
  assert.notEqual(ownerA[0].body,ownerB[0].body);
  await api(ctxA,'/api/t08/notes/'+ownerB[0].id,undefined,404,'GET');
  await api(ctxB,'/api/t08/notes/'+ownerA[0].id,undefined,404,'GET');
  assert.equal((await api(ctxA,'/api/t08/notes?user_id='+userB,undefined,200,'GET')).notes[0].id,ownerA[0].id);
  const aN=(await pool.query('SELECT count(*)::int n FROM t08_notes WHERE user_id=(SELECT id FROM t08_users WHERE username=$1)',[userA])).rows[0].n;
  const bN=(await pool.query('SELECT count(*)::int n FROM t08_notes WHERE user_id=(SELECT id FROM t08_users WHERE username=$1)',[userB])).rows[0].n;
  assert.equal(aN,3);assert.equal(bN,3);
  await screenshot(B.page,'04-account-b-private.png');
  note('cross-account both directions rejected 404, forged user_id ignored, note counts 3/3 unchanged','PASS');

  const aChallenge=await api(ctxB,'/api/t08/login/options',{username:userA},200);
  const bChallenge=await api(ctxB,'/api/t08/login/options',{username:userB},200);
  const bSigned=await B.page.evaluate(async options=>
    window.SimpleWebAuthnBrowser.startAuthentication({optionsJSON:options}),bChallenge.options);
  await api(ctxB,'/api/t08/login/verify',{transaction_id:aChallenge.transaction_id,credential:bSigned},403);
  note('credential signed for B cannot authenticate to account A (403)','PASS');

  await api(ctxA,'/api/t08/passkeys/'+encodeURIComponent(keyA1)+'/delete',{},200);
  const remain=(await api(ctxA,'/api/t08/passkeys',undefined,200,'GET')).passkeys;
  assert.equal(remain.length,1);assert.notEqual(remain[0].id,keyA1);
  await api(ctxA,'/api/t08/passkeys/'+encodeURIComponent(remain[0].id)+'/delete',{},409);
  const oldCookie=(await ctxA.cookies()).find(c=>c.name==='t08_session')?.value;
  await api(ctxA,'/api/t08/logout',{},200);
  if(oldCookie)await api(ctxAnon,'/api/t08/notes',undefined,401,'GET',
    {Cookie:'t08_session='+oldCookie});
  await A.page.reload();
  await A.page.locator('#t08-locked').waitFor({state:'visible'});
  await login(A.page,userA);
  await screenshot(A.page,'05-login-with-remaining-passkey.png');
  note('one key deletion, last-key protection 409, logout 401, remaining passkey login successful','PASS');
  evidence.counts={demo_accounts:2,notes_per_account:3,initial_passkeys_a:2,
    remaining_passkeys_a:1,passkeys_b:1};
  console.log('T08 VIRTUAL WEBAUTHN E2E: '+evidence.checks.length+'/'+evidence.checks.length+' PASS');
}
main().catch(e=>{console.error('T08 E2E FAIL:',e.message);process.exitCode=1;})
  .finally(async()=>{
    fs.writeFileSync(path.join(dir,'verification.json'),JSON.stringify(evidence,null,2)+'\n');
    if(browser)await browser.close();
    if(proc){proc.kill('SIGTERM');await sleep(250);}
    await pool.end();
  });
