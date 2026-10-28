"""Apply session isolation to the recovered shop bridge and regenerate its embed."""
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1] / 'exports/game.tabby.meme-20261021-141852/godot-project/scripts/web'
path = root / 'shop_bridge.js'
s = path.read_text(encoding='utf-8')
def replace(old, new):
    global s
    assert old in s, old
    s = s.replace(old, new)

replace('version===6', 'version===7')
replace(" let api='',token='',generation=0,timer=null,polls=0;", """ window.VyloShop?.close();
 let api='',token='',generation=0,timer=null,polls=0;
 let session=null;
 const current=ticket=>session!==null&&ticket===generation;
 function check(ticket){if(!current(ticket))throw {code:'session_changed'};}
 function close(){generation++;clearTimeout(timer);const old=session;session=null;token='';if(old)for(const controller of old.controllers)controller.abort();}
 async function walletRequest(ticket,provider,method){check(ticket);const value=await provider.request({method});check(ticket);return value;}
""")
start = s.index(' async function request(')
end = s.index('\n function accept(', start)
s = s[:start] + """ async function request(path,body,ticket){
  check(ticket);const context=session;const controller=new AbortController();context.controllers.add(controller);
  const timeout=setTimeout(()=>controller.abort(),12000);
  try{const r=await fetch(context.api+'/shop'+path,{method:body?'POST':'GET',headers:{Authorization:'Bearer '+context.token,'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined,signal:controller.signal});
   check(ticket);const data=await r.json();check(ticket);if(!r.ok)throw {code:data.code||'shop_unavailable'};return data;
  }finally{clearTimeout(timeout);context.controllers.delete(controller);}
 }
""" + s[end:]
# Every state-changing response is checked at the mutation boundary as well as
# inside request(), so a close between promise continuations cannot leak state.
replace('function accept(data){', 'function accept(data,ticket){check(ticket);')
start = s.index(' async function refresh(')
end = s.index('\n async function buy(', start)
s = s[:start] + """ function refresh(ticket=generation){
  if(!current(ticket))return Promise.resolve();const context=session;if(context.refreshing)return context.refreshing;clearTimeout(timer);
  context.refreshing=(async()=>{try{
   const data=await request('',undefined,ticket);accept(data,ticket);const saved=read();
   if(saved?.hash&&!state.orders.some(o=>o.id===saved.orderId&&o.txHash))accept(await request('/submit',{orderId:saved.orderId,txHash:saved.hash},ticket),ticket);
   check(ticket);if(state.status!=='wallet_confirm')state.status=state.orders.some(o=>o.status==='PENDING')?'confirming':state.orders.some(o=>o.status==='REVIEW')?'review':saved&&!saved.hash?'payment_uncertain':'ready';
  }catch(e){if(current(ticket))state.status=e.code||'shop_unavailable';}
  finally{context.refreshing=null;if(current(ticket))timer=setTimeout(()=>refresh(ticket),2000);}})();return context.refreshing;
 }
""" + s[end:]
replace('async function buy(productId){if(state.busy)return;', 'async function buy(productId){if(!session||state.busy)return;')
replace("const ticket=generation;try{", "const ticket=generation;const address=state.address;try{")
replace('paymentProvider(state.address)', 'paymentProvider(address)')
replace('providerForAddress(state.address);if(!provider)', 'providerForAddress(address);check(ticket);if(!provider)')
replace("await provider.request({method:'eth_requestAccounts'})", "await walletRequest(ticket,provider,'eth_requestAccounts')")
replace("await provider.request({method:'eth_chainId'})", "await walletRequest(ticket,provider,'eth_chainId')")
replace("await provider.request({method:'eth_accounts'})", "await walletRequest(ticket,provider,'eth_accounts')")
replace('state.address.toLowerCase()', 'address.toLowerCase()')
# storageKey is intentionally based on current state; buy captures it before
# broadcasting, and always saves the resulting hash to that original key.
replace("'vylo_shop_'+address.toLowerCase()", "'vylo_shop_'+state.address.toLowerCase()")
replace("await request('/order',{productId});if(ticket!==generation)return;", "await request('/order',{productId},ticket);check(ticket);")
replace("let hash;try{hash=await provider.request", "let hash;try{check(ticket);hash=await provider.request")
replace("if(e.code===4001){await request('/cancel-quote',{orderId:o.id});persist(null);}", "if(e.code===4001){persist(null);if(current(ticket))await request('/cancel-quote',{orderId:o.id},ticket);}")
replace('persist({orderId:o.id,hash});if(ticket!==generation)return;', 'persist({orderId:o.id,hash});check(ticket);')
replace("accept(await request('/submit',{orderId:o.id,txHash:hash}));await refresh();", "accept(await request('/submit',{orderId:o.id,txHash:hash},ticket),ticket);await refresh(ticket);")
replace('if(ticket===generation)', 'if(current(ticket))')
start = s.index(' window.VyloShop={')
s = s[:start] + """ window.VyloShop={version:7,
  open(base,credential){close();api=base;token=credential;session={api,token,controllers:new Set(),refreshing:null};polls=0;Object.assign(state,{resetGeneration:'initial',busy:false,status:'loading',products:[],orders:[],settlements:[],address:'',expiresAt:null});void refresh(generation);},buy,
  async unlist(productId){if(!session||state.busy)return;const ticket=generation;state.busy=true;try{await request('/unlist',{productId},ticket);check(ticket);await refresh(ticket);}catch(e){if(current(ticket))state.status=e.code||'shop_unavailable';}finally{if(current(ticket))state.busy=false;}},
  snapshot(){return JSON.stringify({...state,waiting:state.expiresAt?Math.max(0,Math.ceil((Date.parse(state.expiresAt)-Date.now())/1000)):0});},close};
})();
"""
path.write_text(s, encoding='utf-8')
(root / 'shop_bridge_source.gd').write_text('extends RefCounted\nconst SOURCE: = ' + json.dumps(s, ensure_ascii=False) + '\n', encoding='utf-8')
print('Updated shop bridge and embedded GDScript source')
