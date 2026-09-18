export const enc = new TextEncoder();
export function base32Decode(input){
  const s=input.toUpperCase().replace(/[^A-Z2-7]/g,''); let bits=0,val=0,out=[];
  for(const c of s){ val=(val<<5)|('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c)); bits+=5; if(bits>=8){ out.push((val>>(bits-8))&255); bits-=8; } }
  if(!out.length) throw new Error('Invalid Base32 secret'); return new Uint8Array(out);
}
export function base32Encode(bytes){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let bits=0,val=0,out='';for(const b of bytes){val=(val<<8)|b;bits+=8;while(bits>=5){out+=a[(val>>(bits-5))&31];bits-=5;}}if(bits)out+=a[(val<<(5-bits))&31];return out;}
export function parseOtpAuth(raw){
  const u=new URL(raw); if(u.protocol!=='otpauth:'||u.hostname!=='totp') throw new Error('Only otpauth://totp URIs are supported');
  const label=decodeURIComponent(u.pathname.slice(1)); const secret=u.searchParams.get('secret'); if(!secret) throw new Error('Missing secret');
  const algorithm=(u.searchParams.get('algorithm')||'SHA1').toUpperCase(); if(!['SHA1','SHA256','SHA512'].includes(algorithm)) throw new Error('Unsupported algorithm');
  const digits=Number(u.searchParams.get('digits')||6), period=Number(u.searchParams.get('period')||30); if(![6,8].includes(digits))throw new Error('Digits must be 6 or 8'); if(!Number.isInteger(period)||period<1||period>300)throw new Error('Period must be 1-300 seconds');
  const split=label.indexOf(':'); return {id:crypto.randomUUID(),issuer:u.searchParams.get('issuer')||(split>=0?label.slice(0,split):''),account:split>=0?label.slice(split+1):label,secret:base32Encode(base32Decode(secret)),algorithm,digits,period};
}
export async function totp(secret,algorithm='SHA1',digits=6,period=30,time=Date.now()){
  const counter=Math.floor(time/1000/period), msg=new ArrayBuffer(8), dv=new DataView(msg); dv.setUint32(4,counter,false);
  const key=await crypto.subtle.importKey('raw',base32Decode(secret),{name:'HMAC',hash:{name:algorithm.replace('SHA','SHA-')}},false,['sign']);
  const h=new Uint8Array(await crypto.subtle.sign('HMAC',key,msg)),o=h[h.length-1]&15;
  const n=(((h[o]&127)<<24)|(h[o+1]<<16)|(h[o+2]<<8)|h[o+3])>>>0; return String(n%10**digits).padStart(digits,'0');
}
