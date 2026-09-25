"""Small HTTPS-only, loopback-only I2 validation UI. No private media or AI."""
from collections import deque
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import hmac,json,mimetypes,secrets,socket,ssl,threading,time,logging
from datetime import datetime,timezone
from uuid import uuid4
from .ingestion import IngestionError,CommitOutcomeUnknown
from .ingestion_json import InputRejected,parse
from .errors import EcomValidationError
from .webauthn_service import BrowserSession,csrf_for

SESSION_COOKIE='__Host-pemeo-session'
PREAUTH_COOKIE='__Host-pemeo-preauth'
MAX_BODY=65536
ERROR_LOG=logging.getLogger('pemeo.http')
LOG_ROUTES=frozenset(('/', '/app.js', '/style.css', '/api/session',
    '/api/register/begin','/api/register/finish','/api/login/begin','/api/login/finish',
    '/api/candidate','/api/approve/options','/api/approve/replay','/api/approve',
    '/api/reject','/api/manage/begin','/api/manage/finish','/api/manage/add','/api/logout'))


def report_unexpected_error(exc,method,path):
    """Allowlisted metadata only: never stringify exceptions or request values."""
    identifier=uuid4().hex
    # Custom exception class names can also contain untrusted information.
    kind=next((name for cls,name in ((TypeError,'TypeError'),(AttributeError,'AttributeError'),
        (RuntimeError,'RuntimeError')) if type(exc) is cls),'UnexpectedError')
    record={'event':'unexpected_http_error','request_id':identifier,
        'occurred_at':datetime.now(timezone.utc).isoformat(),
        'method':method if method in {'GET','POST'} else 'OTHER',
        'route':path if path in LOG_ROUTES else 'unrecognized', 'error_type':kind}
    ERROR_LOG.error(json.dumps(record,separators=(',',':')),exc_info=False,stack_info=False)
    return identifier


def validate_request(method,path,headers,origin):
    host=origin.removeprefix('https://')
    if headers.get_all('Host') != [host]:raise IngestionError('host_rejected')
    supplied=headers.get_all('Origin')
    if method=='POST' and supplied!=[origin]:raise IngestionError('origin_rejected')
    if supplied and supplied!=[origin]:raise IngestionError('origin_rejected')
    if headers.get('Sec-Fetch-Site') not in (None,'same-origin','none'):raise IngestionError('cross_site_rejected')
    if '?' in path or '#' in path or '%' in path or '..' in path:raise IngestionError('path_rejected')
    if headers.get_all('Transfer-Encoding'):raise IngestionError('transfer_encoding_rejected')
    if method=='POST':
        if headers.get_all('Content-Type')!=['application/json']:raise IngestionError('content_type_rejected')
        lengths=headers.get_all('Content-Length')
        if not lengths or len(lengths)!=1 or not lengths[0].isdigit() or not 0<int(lengths[0])<=MAX_BODY:
            raise IngestionError('body_size_rejected')


def cookie_value(headers,name):
    values=headers.get_all('Cookie') or []
    if len(values)>1:raise IngestionError('cookie_rejected')
    raw=values[0] if values else ''
    # SimpleCookie silently accepts duplicate names; reject them before parsing.
    parts=[part.strip().split('=',1)[0] for part in raw.split(';') if part.strip()]
    if len(parts)!=len(set(parts)):raise IngestionError('cookie_rejected')
    cookie=SimpleCookie();cookie.load(raw)
    return cookie[name].value if name in cookie else None


def make_handler(service,web_root):
    class Handler(BaseHTTPRequestHandler):
        server_version='PeMeO'
        sys_version=''
        def log_message(self,*args):pass
        def setup(self):
            super().setup();self.connection.settimeout(10)
        def reply(self,status,payload,*,mime='application/json',cookies=()):
            body=payload if isinstance(payload,bytes) else json.dumps(payload,ensure_ascii=False).encode()
            self.send_response(status);self.send_header('Content-Type',mime);self.send_header('Content-Length',str(len(body)))
            self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Referrer-Policy','no-referrer');self.send_header('X-Frame-Options','DENY')
            self.send_header('Content-Security-Policy',"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            self.send_header('Permissions-Policy','publickey-credentials-create=(self), publickey-credentials-get=(self)')
            for name,value,age in cookies:self.send_header('Set-Cookie',f'{name}={value}; Path=/; Max-Age={age}; Secure; HttpOnly; SameSite=Strict')
            self.end_headers();self.wfile.write(body)
        def session(self):
            token=cookie_value(self.headers,SESSION_COOKIE)
            return BrowserSession(token, self.headers.get('X-PeMeO-CSRF',''))
        def do_GET(self):self.handle_request('GET')
        def do_POST(self):self.handle_request('POST')
        def handle_request(self,method):
            try:
                validate_request(method,self.path,self.headers,service.verifier.origin)
                if not self.server.admit():raise IngestionError('rate_limited')
                if method=='GET':
                    if self.path=='/api/session':
                        token=cookie_value(self.headers,SESSION_COOKIE)
                        if token:
                            try:return self.reply(200,service.account(BrowserSession(token,csrf_for(token))))
                            except IngestionError:pass
                        pre=secrets.token_hex(32)
                        return self.reply(200,{'authenticated':False,'csrf':csrf_for(pre)},cookies=[(PREAUTH_COOKIE,pre,600),(SESSION_COOKIE,'',0)])
                    files={'/':'index.html','/app.js':'app.js','/style.css':'style.css'}
                    if self.path not in files:return self.reply(404,{'error':'not_found'})
                    p=web_root/files[self.path]
                    return self.reply(200,p.read_bytes(),mime={'/':'text/html; charset=utf-8','/app.js':'text/javascript; charset=utf-8','/style.css':'text/css; charset=utf-8'}[self.path])
                body=parse(self.rfile.read(int(self.headers['Content-Length'])))
                if not isinstance(body,dict):raise IngestionError('invalid_body')
                preauth=self.path in {'/api/register/begin','/api/register/finish','/api/login/begin','/api/login/finish'}
                if preauth:
                    token=cookie_value(self.headers,PREAUTH_COOKIE)
                    if not token or self.headers.get_all('X-PeMeO-CSRF')!=[csrf_for(token)]:raise IngestionError('csrf_rejected')
                else:
                    if len(self.headers.get_all('X-PeMeO-CSRF') or [])!=1:raise IngestionError('csrf_rejected')
                ctx=self.session()
                raw=json.dumps(body.get('credential'),ensure_ascii=False,separators=(',',':')).encode()
                p=self.path
                if p=='/api/register/begin':result=service.begin_registration(body['bootstrap'])
                elif p=='/api/register/finish':result=service.finish_registration(body['bootstrap'],body['ceremony_id'],raw)
                elif p=='/api/login/begin':result=service.begin_login()
                elif p=='/api/login/finish':
                    result=service.finish_login(body['ceremony_id'],raw);token=result.pop('token')
                    return self.reply(200,result,cookies=[(SESSION_COOKIE,token,28800),(PREAUTH_COOKIE,'',0)])
                elif p=='/api/candidate':
                    if not isinstance(body['confirmation'],str) or not 1<=len(body['confirmation'])<=4000:raise IngestionError('invalid_confirmation')
                    key=body['request_key']
                    if not isinstance(key,str) or len(key)>100:raise IngestionError('invalid_request_key')
                    record=service.create_statement(ctx,key,body['statement'])
                    prepared=service.prepare_confirmation(ctx,key+':confirm',record['record_ids'][0],body['confirmation'])
                    result=service.view_confirmation(ctx,prepared['candidate_id'])
                elif p=='/api/approve/options':result=service.confirmation_options(ctx,body['candidate_id'])
                elif p=='/api/approve/replay':result=service.replay_confirmation(ctx,body['request_key'],body['candidate_id'],body['candidate_digest'])
                elif p=='/api/approve':result=service.approve(ctx,body['request_key'],body['candidate_id'],body['candidate_digest'],raw)
                elif p=='/api/reject':result=service.reject(ctx,body['candidate_id'])
                elif p=='/api/manage/begin':result=service.begin_management(ctx,body['action'],body.get('target'))
                elif p=='/api/manage/finish':result=service.finish_management(ctx,body['action'],body['ceremony_id'],raw)
                elif p=='/api/manage/add':result=service.finish_add(ctx,body['ceremony_id'],raw)
                elif p=='/api/logout':
                    result=service.logout(ctx);return self.reply(200,result,cookies=[(SESSION_COOKIE,'',0)])
                else:return self.reply(404,{'error':'not_found'})
                self.reply(200,result)
            except CommitOutcomeUnknown:self.reply(503,{'error':'commit_outcome_unknown_retry_same_key'})
            except IngestionError as exc:self.reply(403,{'error':exc.code})
            except (KeyError,ValueError,InputRejected,EcomValidationError):self.reply(400,{'error':'invalid_request'})
            except (TimeoutError,ConnectionError,BrokenPipeError):self.close_connection=True
            except Exception as exc:
                identifier=report_unexpected_error(exc,method,self.path)
                self.reply(500,{'error':'internal_error','request_id':identifier})
    return Handler


class BoundedServer(ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,address,handler):
        if address[0]!='127.0.0.1':raise ValueError('Loopback only')
        self.slots=threading.BoundedSemaphore(8);self.recent=deque();self.rate_lock=threading.Lock()
        super().__init__(address,handler)
    def admit(self):
        with self.rate_lock:
            now=time.monotonic()
            while self.recent and self.recent[0]<now-60:self.recent.popleft()
            if len(self.recent)>=120:return False
            self.recent.append(now);return True
    def process_request(self,request,client_address):
        if not self.slots.acquire(False):request.close();return
        try:super().process_request(request,client_address)
        except Exception:self.slots.release();raise
    def process_request_thread(self,request,client_address):
        try:super().process_request_thread(request,client_address)
        finally:self.slots.release()


def serve(service,web_root,cert,key,port):
    server=BoundedServer(('127.0.0.1',port),make_handler(service,web_root))
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert,key)
    server.socket=context.wrap_socket(server.socket,server_side=True,do_handshake_on_connect=False)
    server.serve_forever(poll_interval=.5)
