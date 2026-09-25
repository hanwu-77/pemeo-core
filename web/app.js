'use strict';
let csrf='',candidate=null,requestKey=null;
const $=id=>document.getElementById(id);
const status=(message,error=false)=>{$('status').textContent=message;$('status').classList.toggle('error',error);};
const decode=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
const encode=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
async function api(path,data){
 const response=await fetch('/api/'+path,{method:data===undefined?'GET':'POST',credentials:'same-origin',cache:'no-store',
  headers:data===undefined?{}:{'Content-Type':'application/json','X-PeMeO-CSRF':csrf},body:data===undefined?undefined:JSON.stringify(data)});
 const body=await response.json();if(!response.ok)throw new Error(body.error||'请求失败');return body;
}
async function credential(options,register=false){
 const p=structuredClone(options);p.challenge=decode(p.challenge);
 if(register){p.user.id=decode(p.user.id);p.excludeCredentials=(p.excludeCredentials||[]).map(x=>({...x,id:decode(x.id)}));}
 else p.allowCredentials=(p.allowCredentials||[]).map(x=>({...x,id:decode(x.id)}));
 const c=await navigator.credentials[register?'create':'get']({publicKey:p});if(!c)throw new Error('认证已取消');
 const r={clientDataJSON:encode(c.response.clientDataJSON)};
 if(register)r.attestationObject=encode(c.response.attestationObject);
 else Object.assign(r,{authenticatorData:encode(c.response.authenticatorData),signature:encode(c.response.signature),userHandle:c.response.userHandle?encode(c.response.userHandle):null});
 return {id:c.id,rawId:encode(c.rawId),type:c.type,response:r};
}
async function refresh(){
 const a=await api('session');csrf=a.csrf;
 $('welcome').hidden=a.authenticated;for(const id of ['workspace','credentials'])$(id).hidden=!a.authenticated;
 $('credential-list').replaceChildren();
 for(const [i,c] of (a.credentials||[]).entries()){
  const row=document.createElement('div');row.className='credential';const p=document.createElement('p');
  p.textContent=`凭据 ${i+1}${c.current?' · 当前登录':''}${c.backup_eligible?' · 可备份/同步':' · 不可备份标志'}`;
  const b=document.createElement('button');b.className='quiet';b.textContent='撤销';
  b.addEventListener('click',()=>run(async()=>{
   if(!confirm('撤销这个凭据？撤销最后一个凭据后，本版无法恢复写入。'))return;
   const start=await api('manage/begin',{action:'revoke',target:c.id});
   await api('manage/finish',{action:'revoke',ceremony_id:start.ceremony_id,credential:await credential(start.options)});
   clearCandidate();await refresh();status('已撤销，请使用仍有效的凭据重新登录');
  }));row.append(p,b);$('credential-list').append(row);
 }
}
function clearCandidate(){candidate=null;requestKey=null;$('candidate').hidden=true;}
async function run(fn){
 document.querySelectorAll('button').forEach(b=>b.disabled=true);
 try{status('处理中…');await fn();}
 catch(e){status(e.name==='NotAllowedError'?'认证已取消或超时；没有保存确认':e.message,true);}
 finally{document.querySelectorAll('button').forEach(b=>b.disabled=false);}
}
$('register').onclick=()=>run(async()=>{
 const token=$('bootstrap').value.trim();const start=await api('register/begin',{bootstrap:token});
 await api('register/finish',{bootstrap:token,ceremony_id:start.ceremony_id,credential:await credential(start.options,true)});
 $('bootstrap').value='';status('凭据已登记，请登录');
});
$('login').onclick=()=>run(async()=>{const start=await api('login/begin',{});await api('login/finish',{ceremony_id:start.ceremony_id,credential:await credential(start.options)});await refresh();status('已登录；确认内容时仍需单独验证');});
$('prepare').onclick=()=>run(async()=>{
 const result=await api('candidate',{statement:$('statement').value,confirmation:$('confirmation').value,request_key:crypto.randomUUID()});
 candidate=result;requestKey=crypto.randomUUID();$('candidate').hidden=false;
 $('target-text').textContent=candidate.target_record.payload.content;
 $('candidate-text').textContent=candidate.records[0].payload.confirmationText;
 $('candidate-json').textContent=JSON.stringify({target:candidate.target_record,confirmation:candidate.records},null,2);$('candidate-digest').textContent='摘要：'+candidate.candidate_digest;
 $('receipt').hidden=true;status('候选已准备，请核对完整内容后再批准');
});
$('approve').onclick=()=>run(async()=>{
 if(!candidate)return;const c=candidate;const request={request_key:requestKey,candidate_id:c.candidate_id,candidate_digest:c.candidate_digest};
 // First query successful same-key replay. This is authorized receipt access,
 // not bypassing a new confirmation; otherwise obtain a fresh assertion below.
 let result=await api('approve/replay',request);
 if(!result.committed){const options=await api('approve/options',{candidate_id:c.candidate_id});result=await api('approve',{...request,credential:await credential(options)});}
 $('receipt').hidden=false;$('receipt-status').textContent='确认动作：已通过已登记凭据的验证。内容：未作独立真实性核验。';
 $('receipt-json').textContent=JSON.stringify(result,null,2);clearCandidate();status('确认已保存，正文保持原样');
});
$('reject').onclick=()=>run(async()=>{await api('reject',{candidate_id:candidate.candidate_id});clearCandidate();status('已放弃，没有新增确认记录');});
$('add').onclick=()=>run(async()=>{
 const one=await api('manage/begin',{action:'add_authorize'});
 const two=await api('manage/finish',{action:'add_authorize',ceremony_id:one.ceremony_id,credential:await credential(one.options)});
 await api('manage/add',{ceremony_id:two.ceremony_id,credential:await credential(two.options,true)});
 clearCandidate();await refresh();status('新凭据已登记，请重新登录');
});
$('logout').onclick=()=>run(async()=>{await api('logout',{});clearCandidate();await refresh();status('已退出');});
refresh().then(()=>status('仅连接本机 PeMeO 服务')).catch(e=>status(e.message,true));
