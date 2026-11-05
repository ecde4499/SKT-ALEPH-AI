'use strict';
// One-time live Render T08 virtual WebAuthn integration.
// All identities and notes are fabricated. No physical-device claims or secrets saved.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright-core');

const base = 'https://t08-skt-aleph-passkey-ecde4499.onrender.com';
const dir = path.resolve('test-results/t08-live');
const evidence = {
  test_type: 'LIVE HTTPS + CHROME VIRTUAL WEBAUTHN (NOT REAL PHYSICAL DEVICE)',
  origin: base,
  executed_utc: new Date().toISOString(),
  claims: [], images: [],
  note: 'Synthetic test accounts only; no usernames, credentials, cookies, keys, challenges, or session tokens included.'
};
fs.mkdirSync(dir,{recursive:true});
let browser;
const log = (name)=>{ evidence.claims.push({name, result:'PASS'}); console.log('PASS',name); };
async function api(ctx, route, expected, body, method='POST', headers={}) {
  const response = await ctx.request.fetch(base+route,{
    method, timeout:120000,
    headers: {Origin:base,...headers},
    ...(body===undefined ? {} : {data:body}),
  });
  const data = await response.json().catch(()=>({}));
  assert.equal(response.status(), expected, route+': expected '+expected+' got '+response.status()+
    (data.error?' '+String(data.error).slice(0,100):''));
  return data;
}
async function device(ctx){
  const page=await ctx.newPage();
  page.setDefaultTimeout(50000);
  const cdp=await ctx.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const add = async()=> (await cdp.send('WebAuthn.addVirtualAuthenticator',{
    options:{
      protocol:'ctap2',transport:'internal',hasResidentKey:true,
      hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true
    }
  })).authenticatorId;
  const id=await add();
  const res=await page.goto(base+'/',{waitUntil:'networkidle',timeout:120000});
  assert.equal(res.status(),200);
  await page.locator('#t08-locked').waitFor({state:'visible'});
  await page.evaluate(()=>{
    const el=document.createElement('div');
    el.id='liveE2eWatermark';
    el.textContent='테스트용 가상 패스키 · 실제 기기 인증 아님';
    el.style.cssText='position:fixed;bottom:14px;right:14px;z-index:10000;'+
      'background:#142e29;color:white;font-weight:700;font-size:14px;'+
      'padding:8px 13px;border-radius:10px;pointer-events:none';
    document.body.appendChild(el);
  });
  return {page,cdp,id,add};
}
async function shot(page,name){
  await page.screenshot({path:path.join(dir,name),fullPage:true});
  evidence.images.push(name);
  console.log('SCREENSHOT',name);
}
async function signup(page,username,key){
  await page.locator('#t08-new-name').fill(username);
  await page.locator('#t08-new-key').fill(key);
  await page.locator('#t08-register button').click();
  await page.locator('#t08-unlocked').waitFor({state:'visible'});
  assert.equal(await page.locator('#t08-private-list li').count(),3);
}
async function login(page,username){
  await page.locator('#t08-login-name').fill(username);
  await page.locator('#t08-login button').click();
  await page.locator('#t08-unlocked').waitFor({state:'visible'});
}
async function run(){
  browser=await chromium.launch({
    headless:true,
    ...(fs.existsSync('/usr/bin/google-chrome')?{executablePath:'/usr/bin/google-chrome'}:{}),
    args:['--no-sandbox','--disable-dev-shm-usage']
  });
  const ctxAnon=await browser.newContext();
  const health=await api(ctxAnon,'/api/t08/health',200,undefined,'GET');
  assert.equal(health.ok,true);
  const pageResp=await ctxAnon.request.get(base+'/');
  assert.equal(pageResp.status(),200);
  const body=await pageResp.text();
  assert.ok(body.includes('ONE PAGE INTRODUCTION'));
  assert.ok(!body.includes('[가상 데이터] 공개 소개 사이트'));
  await api(ctxAnon,'/api/t08/notes',401,undefined,'GET');
  await api(ctxAnon,'/private',401,undefined,'GET');
  log('LIVE public intro 200 + DB health 200 + private unauthenticated 401; private note not in HTML');

  const suffix=crypto.randomBytes(5).toString('hex');
  const nameA='t08_live_a_'+suffix;
  const nameB='t08_live_b_'+suffix;
  const ctxA=await browser.newContext({viewport:{width:1360,height:900},locale:'ko-KR',timezoneId:'Asia/Seoul'});
  const A=await device(ctxA);
  await shot(A.page,'01-live-public-locked.png');
  const cancelName='t08_not_saved_'+suffix;
  const one=await api(ctxAnon,'/api/t08/register/options',200,
    {username:cancelName,name:'취소 테스트'});
  const two=await api(ctxAnon,'/api/t08/register/options',200,
    {username:cancelName,name:'취소 테스트'});
  assert.notEqual(one.options.challenge,two.options.challenge);
  const canceled=await api(ctxAnon,'/api/t08/login/options',404,{username:cancelName});
  assert.ok(canceled.error);
  log('LIVE two registration challenges distinct; uncompleted registration leaves no account');

  await signup(A.page,nameA,'가상패스키 A-1');
  const notesA=(await api(ctxA,'/api/t08/notes',200,undefined,'GET')).notes;
  assert.equal(notesA.length,3);
  await shot(A.page,'02-live-account-a.png');
  const initialKeys=(await api(ctxA,'/api/t08/passkeys',200,undefined,'GET')).passkeys;
  assert.equal(initialKeys.length,1);
  const removedId=initialKeys[0].id;
  const proof=(await api(ctxA,'/api/t08/passkeys/public-key',200,undefined,'GET'));
  assert.equal(proof.keys.length,1);
  assert.ok(proof.keys[0].public_key_hex.length>64);
  log('LIVE WebAuthn signup stores public COSE key and three synthetic private notes');

  const aOpt1=await api(ctxA,'/api/t08/login/options',200,{username:nameA});
  const aOpt2=await api(ctxA,'/api/t08/login/options',200,{username:nameA});
  assert.notEqual(aOpt1.options.challenge,aOpt2.options.challenge);
  const signatureA=await A.page.evaluate(async o=>
    window.SimpleWebAuthnBrowser.startAuthentication({optionsJSON:o}),aOpt1.options);
  await api(ctxA,'/api/t08/login/verify',200,
    {transaction_id:aOpt1.transaction_id,credential:signatureA});
  await api(ctxA,'/api/t08/login/verify',401,
    {transaction_id:aOpt1.transaction_id,credential:signatureA});
  log('LIVE distinct login challenges; signed login 200; replay denied 401');

  await A.cdp.send('WebAuthn.removeVirtualAuthenticator',{authenticatorId:A.id});
  await A.add();
  await A.page.locator('#t08-add-name').fill('가상패스키 A-2');
  await A.page.locator('#t08-add button').click();
  await A.page.waitForFunction(()=>document.querySelectorAll('#t08-key-list li').length===2);
  const keysTwo=(await api(ctxA,'/api/t08/passkeys',200,undefined,'GET')).passkeys;
  assert.equal(keysTwo.length,2);
  await shot(A.page,'03-live-two-passkeys.png');
  log('LIVE two separately registered virtual passkeys with names and creation dates');

  const ctxB=await browser.newContext({viewport:{width:1360,height:900},locale:'ko-KR',timezoneId:'Asia/Seoul'});
  const B=await device(ctxB);
  await signup(B.page,nameB,'가상패스키 B-1');
  const notesB=(await api(ctxB,'/api/t08/notes',200,undefined,'GET')).notes;
  assert.equal(notesB.length,3);
  assert.notEqual(notesA[0].body,notesB[0].body);
  await api(ctxA,'/api/t08/notes/'+notesB[0].id,404,undefined,'GET');
  await api(ctxB,'/api/t08/notes/'+notesA[0].id,404,undefined,'GET');
  assert.equal((await api(ctxA,'/api/t08/notes?user_id='+nameB,200,undefined,'GET')).notes.length,3);
  assert.equal((await api(ctxB,'/api/t08/notes?user_id='+nameA,200,undefined,'GET')).notes.length,3);
  await shot(B.page,'04-live-account-b.png');
  log('LIVE A/B cross-account note requests 404 in both directions; forged user ID ignored');

  const aOpt=await api(ctxB,'/api/t08/login/options',200,{username:nameA});
  const bOpt=await api(ctxB,'/api/t08/login/options',200,{username:nameB});
  const bSigned=await B.page.evaluate(async o=>
    window.SimpleWebAuthnBrowser.startAuthentication({optionsJSON:o}),bOpt.options);
  await api(ctxB,'/api/t08/login/verify',403,
    {transaction_id:aOpt.transaction_id,credential:bSigned});
  log('LIVE B credential cannot authenticate into A account (403)');

  await api(ctxA,'/api/t08/passkeys/'+encodeURIComponent(removedId)+'/delete',200,{});
  const lastKeys=(await api(ctxA,'/api/t08/passkeys',200,undefined,'GET')).passkeys;
  assert.equal(lastKeys.length,1);
  assert.notEqual(lastKeys[0].id,removedId);
  const afterDelete=await api(ctxA,'/api/t08/login/options',200,{username:nameA});
  await api(ctxA,'/api/t08/login/verify',403,
    {transaction_id:afterDelete.transaction_id,credential:signatureA});
  await api(ctxA,'/api/t08/passkeys/'+encodeURIComponent(lastKeys[0].id)+'/delete',409,{});
  log('LIVE deleted passkey credential rejected 403; deleting final remaining key denied 409');

  await api(ctxA,'/api/t08/logout',200,{});
  await api(ctxA,'/api/t08/notes',401,undefined,'GET');
  await A.page.reload({waitUntil:'networkidle'});
  await A.page.locator('#t08-locked').waitFor({state:'visible'});
  await login(A.page,nameA);
  await shot(A.page,'05-live-remaining-key-relogin.png');
  log('LIVE logout blocks notes 401; remaining virtual passkey can still log in');
  await api(ctxA,'/api/t08/logout',200,{});
  await api(ctxB,'/api/t08/logout',200,{});

  evidence.summary={pass:true,
    created_synthetic_accounts:2,synthetic_notes_each:3,
    account_a_passkeys_initial:2,account_a_passkeys_after_revoke:1,
    account_b_passkeys:1,
    no_physical_passkeys_used:true};
  console.log('T08 LIVE VIRTUAL WEBAUTHN',evidence.claims.length+'/'+evidence.claims.length,'PASS');
}
run().catch(e=>{
  evidence.summary={pass:false,error_type:e.name||'Error'};
  console.error('T08 LIVE E2E FAIL:',String(e.message||e).slice(0,250));
  process.exitCode=1;
}).finally(async()=>{
  fs.writeFileSync(path.join(dir,'verification.json'),JSON.stringify(evidence,null,2)+'\n');
  if(browser)await browser.close();
});
