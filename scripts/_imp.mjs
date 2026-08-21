import { SignJWT } from "jose";
const API="http://127.0.0.1:3001";
const S=new TextEncoder().encode(process.env.NEXTAUTH_SECRET);
const tok=await new SignJWT({userId:"usr-e2e",email:"staff@unierp.dev",tenantId:"tnt-e2e",sid:"sess-e2e",
  realm:"provider",permissions:["platform.support.l2"],mfaVerified:true,amr:["totp"],typ:"session"})
  .setProtectedHeader({alg:"HS256"}).setIssuedAt().setExpirationTime("1h").sign(S);
// Prime the CSRF cookie with a safe request, then echo it back on the POST.
const g=await fetch(`${API}/api/v1/admin/support-impersonation/active`,{headers:{authorization:`Bearer ${tok}`}});
const sc=g.headers.get("set-cookie")||"";
const csrf=(sc.match(/csrf_token=([^;]+)/)||[])[1]||"";
console.log("GET /active ->", g.status, "| csrf primed:", Boolean(csrf));
const post=(body)=>fetch(`${API}/api/v1/admin/support-impersonation/tnt-e2e/start`,{method:"POST",
  headers:{authorization:`Bearer ${tok}`,"content-type":"application/json",
           "x-csrf-token":csrf, cookie:`csrf_token=${csrf}`},
  body:JSON.stringify(body)});
const r=await post({targetUserId:"usr-e2e"});
const t=await r.text();
console.log("start WITHOUT consent ->", r.status, "|", (JSON.parse(t).message||"").slice(0,80));
const r2=await post({targetUserId:"usr-e2e"});
const b2=await r2.text();
console.log("start WITH consent ->", r2.status);
if(r2.ok){const j=JSON.parse(b2);
  console.log("session id:", j.session?.id, "| expiresAt:", j.session?.expiresAt);
  console.log("token minted:", Boolean(j.token), "| target:", j.targetUser?.email);}
else console.log("err:", b2.slice(0,120));
