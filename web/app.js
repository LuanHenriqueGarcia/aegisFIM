const $ = (s)=>document.querySelector(s);
const enc = encodeURIComponent;
const text = async (u)=> (await fetch(u)).text();

document.querySelectorAll('.tabs a').forEach(a=>{
  a.addEventListener('click',e=>{
    const id = a.getAttribute('href');
    if(id.startsWith('#')){
      e.preventDefault();
      document.querySelector(id)?.scrollIntoView({behavior:'smooth',block:'start'});
      history.replaceState(null,'',id);
    }
  });
});

const pwlen = $('#pwlen');
const pwlenRange = $('#pwlen-range');
pwlen.addEventListener('input', ()=> pwlenRange.value = pwlen.value);
pwlenRange.addEventListener('input', ()=> pwlen.value = pwlenRange.value);

$('#btn-gen').addEventListener('click', async () => {
  const len = +pwlen.value || 16;
  const sets = ['a','A','0','s'].filter((k,i)=>{
    const ids = ['#set-a','#set-A','#set-0','#set-s']; return $(ids[i]).checked;
  }).join('');
  const allow = $('#allow-ambig').checked ? '&allow=1' : '';
  const out = await text(`/api/pwgen?len=${enc(len)}&sets=${enc(sets)}${allow}`);
  $('#pwout').value = out.trim() || '—';
});
$('#btn-copy').addEventListener('click', async ()=>{
  const s = $('#pwout').value; if(!s || s==='—') return;
  await navigator.clipboard.writeText(s);
  $('#btn-copy').textContent = 'Copiado!'; setTimeout(()=>$('#btn-copy').textContent='Copiar',900);
});

async function vaultCall(path, params) {
  const q = Object.entries(params).map(([k,v])=>`${k}=${enc(v??'')}`).join('&');
  return await text(`/api/${path}?${q}`);
}
$('#btn-vault-init').addEventListener('click', async ()=>{
  const out = $('#vaultout');
  out.textContent = 'Inicializando...';
  out.textContent = await vaultCall('vault/init', {
    file: $('#vaultfile').value.trim(),
    mpw:  $('#mpw').value.trim(),
    iter: 200000
  });
});
$('#btn-vault-list').addEventListener('click', async ()=>{
  const out = $('#vaultout');
  out.textContent = 'Listando...';
  out.textContent = await vaultCall('vault/list', {
    file: $('#vaultfile').value.trim(),
    mpw:  $('#mpw').value.trim()
  });
});
$('#btn-vault-add').addEventListener('click', async ()=>{
  const out = $('#vaultout');
  const site = $('#site').value.trim();
  const user = $('#user').value.trim();
  const pass = $('#pass').value.trim();
  const genlen = +$('#genlen').value || 20;
  const vsets = ['a','A','0','s'].filter((k,i)=>{
    const ids = ['#vset-a','#vset-A','#vset-0','#vset-s']; return $(ids[i]).checked;
  }).join('');
  out.textContent = 'Gravando...';
  out.textContent = await vaultCall('vault/add', {
    file: $('#vaultfile').value.trim(),
    mpw:  $('#mpw').value.trim(),
    site, user,
    pass,
    gen: pass ? '' : genlen,
    sets: vsets
  });
});
$('#btn-vault-get').addEventListener('click', async ()=>{
  const out = $('#vaultout');
  const site = $('#site-get').value.trim();
  out.textContent = 'Obtendo...';
  out.textContent = await vaultCall('vault/get', {
    file: $('#vaultfile').value.trim(),
    mpw:  $('#mpw').value.trim(),
    site
  });
});
$('#btn-vault-rm').addEventListener('click', async ()=>{
  const out = $('#vaultout');
  const site = $('#site-get').value.trim();
  if(!site) return;
  out.textContent = 'Removendo...';
  out.textContent = await vaultCall('vault/rm', {
    file: $('#vaultfile').value.trim(),
    mpw:  $('#mpw').value.trim(),
    site
  });
});

$('#btn-fim').addEventListener('click', async ()=>{
  $('#fimout').textContent = 'Executando...';
  $('#fimout').textContent = await text(`/api/fim?dir=${enc($('#fimdir').value.trim())}`);
});
$('#btn-scan').addEventListener('click', async ()=>{
  $('#scanout').textContent = 'Executando...';
  $('#scanout').textContent = await text(`/api/scan?host=${enc($('#scanhost').value.trim())}&ports=${enc($('#scanports').value.trim())}`);
});
