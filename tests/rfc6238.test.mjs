import {totp,base32Encode} from '../crypto.js';
const vectors=[
[59,'94287082','46119246','90693936'],[1111111109,'07081804','68084774','25091201'],[1111111111,'14050471','67062674','99943326'],[1234567890,'89005924','91819424','93441116'],[2000000000,'69279037','90698825','38618901'],[20000000000,'65353130','77737706','47863826']];
const secrets=[new TextEncoder().encode('12345678901234567890'),new TextEncoder().encode('12345678901234567890123456789012'),new TextEncoder().encode('1234567890123456789012345678901234567890123456789012345678901234')];
let n=0;for(const [t,...expect] of vectors)for(let i=0;i<3;i++){const got=await totp(base32Encode(secrets[i]),['SHA1','SHA256','SHA512'][i],8,30,t*1000);if(got!==expect[i])throw new Error(`${t} alg${i}: ${got} != ${expect[i]}`);n++;}console.log(`PASS: ${n}/18 RFC 6238 vectors`);
