'use strict';(async()=>{try{const r=await fetch('./data/summary.json',{cache:'no-cache'});if(!r.ok)return;const d=await r.json();document.querySelectorAll('[data-field]').forEach(n=>{const v=d.stats[n.dataset.field];if(Number.isInteger(v))n.textContent=String(v)});if(Array.isArray(d.approved_paragraphs)&&d.approved_paragraphs.length){const box=document.querySelector('#approved'),list=document.querySelector('#approved-list');box.hidden=false;for(const p of d.approved_paragraphs){const para=document.createElement('p');para.textContent=p.candidate+' — 근거: '+p.source;list.append(para)}}}catch(_){}})();
/* Highlight the current portfolio chapter as the page scrolls. */
(()=>{
  const navLinks=[...document.querySelectorAll('.nav nav a[href^="#"]')];
  const pairs=navLinks.map(link=>({link,section:document.querySelector(link.getAttribute('href'))})).filter(p=>p.section);
  if(!pairs.length)return;
  const update=()=>{
    const top=window.innerWidth<=800?115:89;
    let active=null;
    if(window.scrollY>100){
      for(const pair of pairs){
        if(pair.section.getBoundingClientRect().top<=top+30)active=pair;
      }
    }
    for(const pair of pairs){
      if(pair===active)pair.link.setAttribute('aria-current','location');
      else pair.link.removeAttribute('aria-current');
    }
  };
  for(const pair of pairs)pair.link.addEventListener('click',()=>{
    for(const p of pairs)p.link.removeAttribute('aria-current');
    pair.link.setAttribute('aria-current','location');
  });
  window.addEventListener('scroll',update,{passive:true});
  window.addEventListener('resize',update,{passive:true});
  update();
})();
