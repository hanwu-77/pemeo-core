// Disposable virtual authenticator only; this never operates a user's passkey.
const fs=require('fs');
const {chromium}=require(process.env.PEMEO_PLAYWRIGHT_MODULE||'playwright');
(async()=>{
 const cfg=JSON.parse(fs.readFileSync(0,'utf8'));
 const browser=await chromium.launch({channel:process.env.PEMEO_BROWSER_CHANNEL||'chrome',headless:true});
 try{
  const context=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1100,height:920}});
  // TLS exception applies only to this disposable automated context, not the
  // user's browser or macOS trust store. Human TLS acceptance remains pending.
  await context.route('**/*',r=>new URL(r.request().url()).origin===cfg.origin?r.continue():r.abort());
  const page=await context.newPage();page.setDefaultTimeout(12000);
  const cdp=await context.newCDPSession(page);await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
  await page.goto(cfg.origin);await page.locator('#status').filter({hasText:'仅连接本机'}).waitFor();
  await page.locator('#bootstrap').fill(cfg.bootstrap);await page.locator('#register').click();
  await page.locator('#status').filter({hasText:'凭据已登记'}).waitFor();
  await page.locator('#login').click();await page.locator('#workspace').waitFor({state:'visible'});
  const cookies=await context.cookies();const session=cookies.find(c=>c.name==='__Host-pemeo-session');
  if(!session?.secure||!session.httpOnly||session.sameSite!=='Strict')throw Error('cookie attributes');
  if(await page.evaluate(()=>document.cookie.includes('__Host-pemeo-session')))throw Error('HttpOnly leak');
  await page.locator('#prepare').click();await page.locator('#candidate').waitFor({state:'visible'});
  const candidate=JSON.parse(await page.locator('#candidate-json').textContent());
  if(candidate.confirmation[0].metadata.verification!=='unverified')throw Error('candidate verification changed');
  if(await page.locator('#target-text').textContent()!==candidate.target.payload.content)throw Error('target not displayed');
  await page.locator('#approve').click();await page.locator('#receipt').waitFor({state:'visible'});
  const receipt=JSON.parse(await page.locator('#receipt-json').textContent());
  if(receipt.evidence_class!=='verified_assertion')throw Error('wrong receipt evidence');
  await page.screenshot({path:cfg.screenshot,fullPage:true});
  // Missing CSRF, foreign Origin and untrusted Host exercised through HTTPS.
  const noCsrf=await context.request.post(cfg.origin+'/api/logout',{headers:{Origin:cfg.origin},data:{}});
  if(noCsrf.status()!==403)throw Error('CSRF accepted');
  const foreign=await context.request.post(cfg.origin+'/api/logout',{headers:{Origin:'https://evil.invalid'},data:{}});
  if(foreign.status()!==403)throw Error('foreign origin accepted');
  const wrongHost=await context.request.get(cfg.origin+'/',{headers:{Host:'evil.invalid'}});
  if(wrongHost.status()!==403)throw Error('foreign host accepted');
  // Losing the approval HTTP response is tested using same-key replay in DB
  // tests. Here UI rejection does not create another confirmation.
  await page.locator('#prepare').click();await page.locator('#candidate').waitFor({state:'visible'});
  await page.locator('#reject').click();await page.locator('#status').filter({hasText:'没有新增确认'}).waitFor();
  await page.locator('#logout').click();await page.locator('#welcome').waitFor({state:'visible'});
  process.stdout.write(JSON.stringify({browser:browser.version(),virtual_authenticator:true,human_acceptance:false,
   registration:true,login:true,confirmation:true,rejection:true,logout:true,csrf_origin_host_rejected:true,cookie_flags:true,receipt_id:receipt.receipt_id}));
  await context.close();
 }finally{await browser.close();}
})().catch(e=>{process.stderr.write(e.message);process.exitCode=1;});
