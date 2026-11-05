'use strict';
(() => {
  const byId=id=>document.getElementById(id);
  const locked=byId('t08-locked'), unlocked=byId('t08-unlocked');
  if(!locked || !unlocked) return;
  const status=byId('t08-message');
  const api=async (url,body) => {
    const response=await fetch(url,{
      method:body===undefined?'GET':'POST',
      credentials:'same-origin',cache:'no-store',
      ...(body===undefined?{}:{headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
    });
    const data=await response.json().catch(()=>({}));
    if(!response.ok)throw new Error(data.error||'요청 실패 ('+response.status+')');
    return data;
  };
  const message=(text,bad=false)=>{
    status.textContent=text;status.classList.toggle('t08-error',bad);
  };
  const textElement=(tag,content)=>{const el=document.createElement(tag);el.textContent=content;return el;};
  const unsupported=()=>!(window.PublicKeyCredential&&window.SimpleWebAuthnBrowser);
  async function listKeys() {
    const response=await api('/api/t08/passkeys');
    const box=byId('t08-key-list');box.replaceChildren();
    for(const item of response.passkeys){
      const wrapper=document.createElement('li');
      const info=document.createElement('span');
      info.textContent=item.name+' · 등록일 '+new Date(item.created_at).toLocaleDateString('ko-KR');
      const remove=textElement('button','삭제');remove.type='button';
      remove.className='button secondary';remove.dataset.id=item.id;
      remove.addEventListener('click',async()=>{
        if(!confirm('이 패스키 등록을 서버에서 삭제할까요? 다른 기기는 사용하지 못합니다.'))return;
        try{await api('/api/t08/passkeys/'+encodeURIComponent(item.id)+'/delete',{});
          message('패스키 삭제가 적용됐습니다.');await listKeys();
        }catch(e){message(e.message,true);}
      });
      wrapper.append(info,remove);box.append(wrapper);
    }
    byId('t08-key-count').textContent='등록된 패스키 '+response.passkeys.length+'개';
  }
  async function showUnlocked(user) {
    locked.hidden=true;unlocked.hidden=false;
    byId('t08-current-user').textContent=user.username;
    const data=await api('/api/t08/notes');
    const list=byId('t08-private-list');list.replaceChildren();
    for(const note of data.notes){
      const li=document.createElement('li'),title=textElement('strong',note.title),
        body=textElement('p',note.body);
      li.append(title,body);list.append(li);
    }
    await listKeys();
  }
  const submit=async(button,action)=>{
    button.disabled=true;message('');
    try{await action();}catch(error){
      if(error.name==='NotAllowedError')message('패스키 창을 취소했거나 시간이 초과됐어요. 아무 패스키도 새로 등록되지 않았습니다.',true);
      else message(error.message||'패스키 작업이 실패했습니다.',true);
    }finally{button.disabled=false;}
  };
  async function refresh() {
    try{const {user}=await api('/api/t08/me');await showUnlocked(user);}
    catch{locked.hidden=false;unlocked.hidden=true;}
  }
  byId('t08-register').addEventListener('submit',event=>{
    event.preventDefault();
    const button=event.currentTarget.querySelector('button[type=submit]');
    submit(button,async()=>{
      if(unsupported())throw Error('이 브라우저는 WebAuthn 패스키를 지원하지 않습니다.');
      const username=byId('t08-new-name').value;
      const name=byId('t08-new-key').value;
      const {transaction_id,options}=await api('/api/t08/register/options',{username,name});
      const credential=await window.SimpleWebAuthnBrowser.startRegistration({optionsJSON:options});
      await api('/api/t08/register/verify',{transaction_id,credential});
      message('패스키 계정이 등록됐습니다. 비밀번호는 만들지 않았어요.');
      await refresh();
    });
  });
  byId('t08-login').addEventListener('submit',event=>{
    event.preventDefault();
    const button=event.currentTarget.querySelector('button[type=submit]');
    submit(button,async()=>{
      if(unsupported())throw Error('이 브라우저는 WebAuthn 패스키를 지원하지 않습니다.');
      const username=byId('t08-login-name').value;
      const {transaction_id,options}=await api('/api/t08/login/options',{username});
      const credential=await window.SimpleWebAuthnBrowser.startAuthentication({optionsJSON:options});
      await api('/api/t08/login/verify',{transaction_id,credential});
      message('패스키 서명 검증 성공');
      await refresh();
    });
  });
  byId('t08-add').addEventListener('submit',event=>{
    event.preventDefault();
    const button=event.currentTarget.querySelector('button[type=submit]');
    submit(button,async()=>{
      if(unsupported())throw Error('이 브라우저는 WebAuthn 패스키를 지원하지 않습니다.');
      const name=byId('t08-add-name').value;
      const {transaction_id,options}=await api('/api/t08/register/options',{name});
      const credential=await window.SimpleWebAuthnBrowser.startRegistration({optionsJSON:options});
      await api('/api/t08/register/verify',{transaction_id,credential});
      message('두 번째 패스키가 등록됐습니다.');
      byId('t08-add-name').value='';
      await listKeys();
    });
  });
  byId('t08-logout').addEventListener('click',async()=>{
    try{await api('/api/t08/logout',{});message('로그아웃했습니다.');await refresh();}
    catch(e){message(e.message,true);}
  });
  byId('t08-show-public-key').addEventListener('click',async()=>{
    try{
      const data=await api('/api/t08/passkeys/public-key');
      const box=byId('t08-key-proof');box.replaceChildren();
      box.append(textElement('p',data.description));
      for(const key of data.keys)box.append(textElement('p',key.name+': 공개키(COSE) '+key.public_key_hex.slice(0,48)+'… (생략)'));
    }catch(e){message(e.message,true);}
  });
  if(unsupported())message('이 브라우저 또는 보안 컨텍스트에서는 패스키를 사용할 수 없습니다.',true);
  refresh();
})();
