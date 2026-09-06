const $=id=>document.getElementById(id);
const groupKey=value=>value.match(/.{1,4}/g).join(' ');
const json=async(url,body)=>{
  const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const d=await r.json();
  if(!r.ok)throw Error(d.error||'Request failed');
  return d;
};
const showError=(id,error)=>{
  const el=$(id);
  if(!el)return;
  el.textContent=`Error: ${error.message}`;
  el.classList.remove('hidden');
};
const hideError=id=>{
  const el=$(id);
  if(!el)return;
  el.textContent='';
  el.classList.add('hidden');
};
const renderList=(id,items)=>{
  const el=$(id);
  if(el)el.innerHTML=items.map(item=>`<div>${item}</div>`).join('');
};

function switchTab(id){
  ['classical','symmetric','publickey'].forEach(name=>{
    $(`tab-${name}`).classList.toggle('hidden',name!==id);
    $(`tab-btn-${name}`).classList.toggle('active-tab',name===id);
  });
}

function setAlphabetKey(){
  $('sub-key').value='QWERTYUIOPASDFGHJKLZXCVBNM';
  hideError('sub-error');
}

function setDefaultDtKeys(){
  $('dt-rowkey').value='2 4 0 3 1';
  $('dt-colkey').value='0 2 1';
  hideError('dt-error');
}

function frequency(id,data,color='var(--primary)'){
  renderList(id,data.sorted.filter(x=>x.count>0).map(x=>`<div><b>${x.letter}</b> ${x.percentage}% (${x.count})<div style="height:4px;background:${color};width:${x.percentage}%"></div></div>`));
}

async function runSubstitution(){
  hideError('sub-error');
  try{
    const d=await json('/api/classical/substitution',{plaintext:$('sub-plaintext').value,key:$('sub-key').value,action:'encrypt'});
    $('sub-results').classList.remove('hidden');
    $('sub-ciphertext').textContent=d.ciphertext;
    $('sub-decrypted').textContent=d.decrypted;
    frequency('sub-freq-bars',d.frequency);
    renderList('sub-caesar-shifts',d.caesar_brute_force.map(x=>`Shift ${String(x.shift).padStart(2,'0')}: ${x.text}`));
  }catch(e){showError('sub-error',e)}
}

async function runDoubleTransposition(){
  hideError('dt-error');
  try{
    const d=await json('/api/classical/double_transposition',{plaintext:$('dt-plaintext').value,row_key:$('dt-rowkey').value,col_key:$('dt-colkey').value,action:'encrypt'});
    $('dt-results').classList.remove('hidden');
    $('dt-ciphertext').textContent=d.ciphertext;
    $('dt-decrypted').textContent=d.decrypted;
    frequency('dt-freq-bars',d.frequency,'var(--secondary)');
  }catch(e){showError('dt-error',e)}
}

async function generateDesKey(){
  hideError('des-error');
  try{
    $('des-key').value=groupKey((await fetch('/api/symmetric/des/generate_key').then(r=>r.json())).key_hex);
  }catch(e){showError('des-error',e)}
}

async function runDes(){
  hideError('des-error');
  try{
    const d=await json('/api/symmetric/des/execute',{plaintext:$('des-plaintext').value,key_hex:$('des-key').value,action:'encrypt'});
    $('des-results').classList.remove('hidden');
    $('des-ciphertext').textContent=d.ciphertext_hex;
    $('des-decrypted').textContent=d.decrypted;
    renderList('des-keys-table',d.round_keys.map(x=>`Round ${x.round}: ${x.hex}`));
  }catch(e){showError('des-error',e)}
}

async function generateAesKey(){
  hideError('aes-error');
  try{
    $('aes-key').value=groupKey((await json('/api/symmetric/aes/generate_key',{bits:+$('aes-bits').value})).key_hex);
  }catch(e){showError('aes-error',e)}
}

async function runAes(){
  hideError('aes-error');
  try{
    const d=await json('/api/symmetric/aes/execute',{plaintext:$('aes-plaintext').value,key_hex:$('aes-key').value,bits:+$('aes-bits').value,action:'encrypt'});
    $('aes-results').classList.remove('hidden');
    $('aes-ciphertext').textContent=d.ciphertext_hex;
    $('aes-decrypted').textContent=d.decrypted;
    renderList('aes-keys-table',d.round_keys.map(x=>`Round ${x.round}: ${x.hex}`));
  }catch(e){showError('aes-error',e)}
}

async function generateRsaKeys(){
  hideError('rsa-error');
  try{
    const d=await json('/api/public/rsa/generate_keys',{bits:+$('rsa-bits').value});
    ['p','q','n','e','d'].forEach(k=>$(`rsa-${k}`).value=d[k]);
    $('fermat-output').textContent='Keys generated. Ready for attack.';
  }catch(e){showError('rsa-error',e)}
}

async function runRsaEncrypt(){
  hideError('rsa-error');
  try{
    const d=await json('/api/public/rsa/encrypt',{plaintext:$('rsa-plaintext').value,e:$('rsa-e').value,n:$('rsa-n').value,bits:+$('rsa-bits').value});
    $('rsa-output-card').classList.remove('hidden');
    $('rsa-hex-output').textContent=d.continuous_hex;
    $('rsa-int-output').textContent=d.single_int;
    $('rsa-array-output').textContent=JSON.stringify(d.cipher_ints);
    $('rsa-ciphertext-bin').value=d.continuous_hex;
  }catch(e){showError('rsa-error',e)}
}

async function runRsaDecrypt(){
  hideError('rsa-error');
  try{
    const d=await json('/api/public/rsa/decrypt',{ciphertext:$('rsa-ciphertext-bin').value,d:$('rsa-d').value,n:$('rsa-n').value,bits:+$('rsa-bits').value});
    $('rsa-output-card').classList.remove('hidden');
    $('rsa-decrypted-card').classList.remove('hidden');
    $('rsa-decrypted-output').textContent=d.decrypted;
  }catch(e){showError('rsa-error',e)}
}

async function simulateFermatAttack(){
  hideError('rsa-error');
  try{
    $('fermat-loading').classList.remove('hidden');
    const d=await json('/api/public/rsa/factor',{n:$('rsa-n').value});
    $('fermat-output').textContent=d.success?`Succeeded: p=${d.p}, q=${d.q}, steps=${d.steps}`:'Search failed.';
  }catch(e){$('fermat-output').textContent=e.message}
  finally{$('fermat-loading').classList.add('hidden')}
}

async function validateEccParams(){
  hideError('ecc-error');
  try{
    const b={p:$('ecc-p').value,a:$('ecc-a').value,b:$('ecc-b').value,Gx:$('ecc-gx').value,Gy:$('ecc-gy').value};
    const d=await json('/api/public/ecc/validate_parameters',b);
    $('ecc-log-summary').textContent=`${d.curve_str}; subgroup order n=${d.n}`;
    renderList('ecc-multiples',d.subgroup.map(x=>`${x.step}G = ${x.coord}`));
    $('ecc-px').value=b.Gx;
    $('ecc-py').value=b.Gy;
  }catch(e){showError('ecc-error',e)}
}

async function runEccExchange(){
  hideError('ecc-error');
  try{
    const d=await json('/api/public/ecc/exchange',{p:$('ecc-p').value,a:$('ecc-a').value,b:$('ecc-b').value,Px:$('ecc-px').value,Py:$('ecc-py').value,alice_priv:$('ecc-alice-priv').value,bob_priv:$('ecc-bob-priv').value});
    $('ecc-log-summary').textContent=`Alice: ${d.alice_pub}; Bob: ${d.bob_pub}; Shared key: ${d.shared_key}; Match: ${d.match}`;
    renderList('ecc-multiples',d.subgroup_p.map(x=>`${x.step}P = ${x.coord}`));
  }catch(e){showError('ecc-error',e)}
}

window.addEventListener('DOMContentLoaded',()=>{
  setAlphabetKey();
  setDefaultDtKeys();
  generateDesKey();
  generateAesKey();

  const bindClear=(inputs,errId)=>{
    inputs.forEach(id=>{
      const el=$(id);
      if(el)el.addEventListener('input',()=>hideError(errId));
    });
  };
  bindClear(['sub-plaintext','sub-key'],'sub-error');
  bindClear(['dt-plaintext','dt-rowkey','dt-colkey'],'dt-error');
  bindClear(['des-plaintext','des-key'],'des-error');
  bindClear(['aes-plaintext','aes-key'],'aes-error');
  bindClear(['rsa-plaintext','rsa-ciphertext-bin'],'rsa-error');
  bindClear(['ecc-p','ecc-a','ecc-b','ecc-gx','ecc-gy','ecc-px','ecc-py','ecc-alice-priv','ecc-bob-priv'],'ecc-error');
});