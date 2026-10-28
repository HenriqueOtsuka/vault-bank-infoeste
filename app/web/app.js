const api = (p, o) => fetch(p, Object.assign({headers:{'Content-Type':'application/json'}}, o)).then(r=>r.json().then(j=>({s:r.status,j})));
let STATE = {user:null, mode:'?'};

const NAV = [['/extrato','Extrato'],['/search','Beneficiarios'],['/mensagens','Mensagens'],['/admin','Admin'],['/ctf','CTF']];
function paintNav(){
  document.getElementById('nav').innerHTML = NAV.map(([h,t])=>`<a href="${h}" class="${location.pathname===h?'active':''}">${t}</a>`).join('');
  document.querySelectorAll('nav a').forEach(a=>a.onclick=e=>{e.preventDefault();go(a.getAttribute('href'));});
  document.getElementById('who').textContent = STATE.user ? `${STATE.user.name} - conta ${STATE.user.account} - mode:${STATE.mode}` : `mode:${STATE.mode}`;
}
function go(path){ history.pushState({},'',path); route(); }
window.onpopstate = route;
const esc = s => s.replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

async function boot(){
  const h = await api('/api/health'); STATE.mode = h.j.mode;
  const me = await api('/api/me'); if(me.s===200){ STATE.user = me.j.user; sessionStorage.vault_token = me.j.token; }
  route();
}

function route(){
  paintNav();
  const el = document.getElementById('app'); const p = location.pathname;
  if(!STATE.user && p!=='/login') return go('/login');
  if(p==='/login') return viewLogin(el);
  if(p==='/extrato'||p==='/') return viewExtrato(el);
  if(p==='/search') return viewSearch(el);
  if(p==='/mensagens') return viewNotes(el);
  if(p==='/admin') return viewAdmin(el);
  if(p==='/ctf') return viewCtf(el);
  el.innerHTML = '<div class="card">404</div>';
}

function viewLogin(el){
  el.innerHTML = `<h1>Entrar na VAULT</h1><p class="sub">Use uma conta de teste do laboratorio.</p>
  <div class="card">
    <label>E-mail</label><input id="email" value="cliente@vault.local">
    <label>Senha</label><input id="pw" type="password" value="exemplo123">
    <button id="go">AUTENTICAR</button>
    <p class="muted" id="msg"></p>
    <p class="muted">Contas: cliente@vault.local / beatriz@vault.local / admin@vault.local - senha exemplo123</p>
  </div>`;
  document.getElementById('go').onclick = async ()=>{
    const r = await api('/api/login',{method:'POST',body:JSON.stringify({email:email.value,password:pw.value})});
    if(r.s===200){ STATE.user=r.j.user; sessionStorage.vault_token=r.j.token; go('/extrato'); }
    else document.getElementById('msg').textContent = 'Falha no login (401).';
  };
}

async function viewExtrato(el){
  const r = await api('/api/transactions');
  el.innerHTML = `<h1>Extrato</h1><p class="sub">Suas transacoes. Cada uma tem um ID na URL da API.</p>
  <div class="card">${(r.j.transactions||[]).map(t=>`<div class="note"><b>#${t.id}</b> ${esc(t.descricao)} <span class="muted">- ${esc(t.valor)}</span></div>`).join('')||'<span class="muted">sem transacoes</span>'}</div>
  <div class="card"><label>Consultar transacao por ID (GET /api/transactions/&lt;id&gt;)</label>
    <div class="row"><input id="tid" value="2001"><button id="q">CONSULTAR</button></div>
    <pre id="out">// resultado</pre></div>`;
  document.getElementById('q').onclick = async ()=>{
    const r = await api('/api/transactions/'+encodeURIComponent(tid.value));
    document.getElementById('out').textContent = JSON.stringify(r.j,null,2);
  };
}

async function viewSearch(el){
  el.innerHTML = `<h1>Beneficiarios</h1><p class="sub">Busque pelo nome do beneficiario.</p>
  <div class="card"><div class="row"><input id="q" placeholder="ex: padaria"><button id="b">BUSCAR</button></div>
    <div id="res"></div></div>`;
  async function run(){
    const r = await api('/api/search?q='+encodeURIComponent('%'+q.value+'%'));
    document.getElementById('res').innerHTML = (r.j.beneficiaries||[]).map(b=>
      `<div class="note"><b>#${b.id}</b> ${esc(b.nome)} <span class="muted">${esc(b.banco)}</span>${b.descricao?` <span class="flag">${esc(b.descricao)}</span>`:''}</div>`
    ).join('') || '<span class="muted">nada encontrado</span>';
  }
  document.getElementById('b').onclick = run; run();
}

async function viewNotes(el){
  el.innerHTML = `<h1>Mensagens de suporte</h1><p class="sub">Mural de mensagens entre clientes e o banco.</p>
  <div class="card"><label>Nova mensagem</label><textarea id="t" rows="2">Ola, VAULT!</textarea>
    <button id="s">PUBLICAR</button></div>
  <div class="card" id="mural"></div>
  <div class="card"><span class="muted">Prova benigna de XSS:</span> <span id="xsssink" class="muted">aguardando...</span></div>`;
  window.vaultProofXSS = async ()=>{
    const r = await api('/api/ctf/xss-proof',{method:'POST'});
    document.getElementById('xsssink').innerHTML = r.j.evidence ? `<span class="flag">${r.j.evidence}</span>` : 'bloqueado (modo seguro)';
  };
  document.getElementById('s').onclick = async ()=>{
    await api('/api/notes',{method:'POST',body:JSON.stringify({texto:t.value})}); load();
  };
  async function load(){
    const r = await api('/api/notes'); const m = document.getElementById('mural');
    m.innerHTML='';
    (r.j.notes||[]).forEach(n=>{
      const d=document.createElement('div'); d.className='note';
      const who=document.createElement('b'); who.textContent=n.autor+': '; d.appendChild(who);
      const span=document.createElement('span');
      if(STATE.mode==='secure'){ span.textContent = n.texto; }   // defesa: texto puro
      else { span.innerHTML = n.texto; }                          // VULNERAVEL: renderiza HTML
      d.appendChild(span); m.appendChild(d);
    });
  }
  load();
}

function b64urlDecode(s){ try{return JSON.parse(atob(s.replace(/-/g,'+').replace(/_/g,'/')));}catch(e){return {error:'payload invalido'};} }
async function viewAdmin(el){
  const tok = sessionStorage.vault_token || '';
  el.innerHTML = `<h1>Painel administrativo</h1><p class="sub">Relatorios financeiros - apenas administradores.</p>
  <div class="card"><label>Token JWT (editavel)</label><textarea id="jwt" rows="3">${esc(tok)}</textarea>
    <div class="row"><button id="read" class="alt">LER PAYLOAD</button><button id="rep">SOLICITAR RELATORIO</button></div>
    <pre id="payload">// payload</pre>
    <pre id="report">// relatorio</pre></div>`;
  document.getElementById('read').onclick = ()=>{
    const parts = (jwt.value||'').split('.');
    document.getElementById('payload').textContent = parts[1]?JSON.stringify(b64urlDecode(parts[1]),null,2):'token invalido';
  };
  document.getElementById('rep').onclick = async ()=>{
    const r = await fetch('/api/admin/reports',{headers:{'Authorization':'Bearer '+jwt.value}}).then(x=>x.json().then(j=>({s:x.status,j})));
    document.getElementById('report').textContent = `HTTP ${r.s}\n`+JSON.stringify(r.j,null,2);
  };
}

async function viewCtf(el){
  el.innerHTML = `<h1>Mini CTF - VAULT</h1><p class="sub">Cole as flags no formato VAULT{...}.</p>
  <div class="card"><label>Flag encontrada</label><div class="row"><input id="f" placeholder="VAULT{...}"><button id="v">VALIDAR</button></div>
    <p class="muted" id="msg"></p><div class="sb" id="sb"></div></div>`;
  async function board(){
    const r = await api('/api/ctf/scoreboard');
    document.getElementById('sb').innerHTML = `<div class="pill">Pontos: ${r.j.score}/${r.j.max}</div>`+
      r.j.challenges.map(c=>`<div class="pill ${r.j.solved.includes(c)?'ok':''}">${c} ${r.j.solved.includes(c)?'OK':''}</div>`).join('');
  }
  document.getElementById('v').onclick = async ()=>{
    const r = await api('/api/ctf/submit',{method:'POST',body:JSON.stringify({flag:f.value})});
    document.getElementById('msg').textContent = r.j.correct?`Correta! ${r.j.challenge} +${r.j.points}`:'Flag invalida.';
    board();
  };
  board();
}

boot();
