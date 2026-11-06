'use strict';
fetch('data/portfolio.json',{cache:'no-store'}).then(r=>{if(!r.ok)throw Error('data');return r.json()}).then(v=>{
 const m=v.ritual, update=(id,text)=>{const x=document.getElementById(id);if(x)x.textContent=text};
 update('m-days',String(m.days));update('m-open',m.open+' / '+m.close);
 update('m-done',String(m.status_counts['실천했다']||0));
 update('m-other',(m.status_counts['일부 실천했다']||0)+' / '+(m.status_counts['못 했다']||0));
 update('asof','측정 기준일 '+m.last_date+' · 출처: 리추얼 JSON · 원문 비공개');
}).catch(()=>{});
