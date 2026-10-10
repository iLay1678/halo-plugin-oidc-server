import { createServer } from 'node:http'
import { readFileSync } from 'node:fs'
import { randomBytes, createHash, createPublicKey, verify } from 'node:crypto'

// 仅用于本地联调；秘密配置和令牌不写入页面、日志或源码。
const configPath = process.argv[2]
if (!configPath) throw new Error('用法：node scripts/oidc-demo.mjs <本地配置JSON路径>')
const config = JSON.parse(readFileSync(configPath, 'utf8'))
const issuer = new URL(config.issuer)
if (!['localhost', '127.0.0.1', '[::1]'].includes(issuer.hostname)) {
  throw new Error('联调工具只允许本机 Halo 地址')
}
const port = Number(config.port ?? 8765)
const callback = `http://127.0.0.1:${port}/callback`
const sessions = new Map()
const hash = (input) => createHash('sha256').update(input).digest()
const random = () => randomBytes(32).toString('base64url')
const escape = (value) => String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c])

async function requestJson(url, options) {
  const response = await fetch(url, { ...options, redirect: 'error', signal: AbortSignal.timeout(10000) })
  const value = await response.json()
  if (!response.ok) throw new Error(`HTTP ${response.status}: ${value.error ?? '请求失败'}`)
  return value
}

const discovery = await requestJson(`${issuer.href.replace(/\/$/, '')}/.well-known/openid-configuration`)
if (discovery.issuer !== config.issuer) throw new Error('Discovery issuer 不一致')
for (const name of ['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri', 'revocation_endpoint']) {
  if (new URL(discovery[name]).origin !== issuer.origin) throw new Error(`端点来源不一致：${name}`)
}

async function validateIdToken(tokens, session, validateNonce) {
  const parts = tokens.id_token?.split('.') ?? []
  if (parts.length !== 3) throw new Error('缺少有效 ID Token')
  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString())
  const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString())
  if (header.alg !== 'RS256') throw new Error('签名算法不匹配')
  const jwks = await requestJson(discovery.jwks_uri)
  const jwk = jwks.keys.find((key) => key.kid === header.kid && key.kty === 'RSA')
  if (!jwk || !verify('RSA-SHA256', Buffer.from(`${parts[0]}.${parts[1]}`), createPublicKey({ key: jwk, format: 'jwk' }), Buffer.from(parts[2], 'base64url'))) {
    throw new Error('ID Token 签名校验失败')
  }
  const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud]
  if (claims.iss !== config.issuer || !audience.includes(config.clientId) || claims.exp <= Date.now() / 1000 || claims.iat > Date.now() / 1000 + 30 || !claims.sub) {
    throw new Error('ID Token 身份/时效校验失败')
  }
  if (validateNonce && claims.nonce !== session.nonce) throw new Error('nonce 不一致')
  if (claims.at_hash !== hash(tokens.access_token).subarray(0, 16).toString('base64url')) throw new Error('at_hash 不一致')
  if (session.sub && session.sub !== claims.sub) throw new Error('刷新后身份变化')
  session.sub = claims.sub
  return claims
}

async function tokenRequest(params) {
  const body = new URLSearchParams({ ...params, client_id: config.clientId })
  if (config.clientSecret) body.set('client_secret', config.clientSecret)
  return requestJson(discovery.token_endpoint, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body })
}

function sendPage(response, session) {
  response.setHeader('Content-Type', 'text/html; charset=utf-8')
  response.setHeader('Cache-Control', 'no-store')
  response.end(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>OIDC 联调应用</title>
<style>body{font:16px system-ui;max-width:720px;margin:48px auto;padding:0 20px}button,a{display:inline-block;padding:10px 14px;margin:4px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f4f4;padding:16px}p{line-height:1.7}</style>
<h1>OIDC 联调应用</h1><p>回调：${escape(callback)}</p><p>Issuer：${escape(config.issuer)}</p><a href="/login">通过 Halo 登录</a>
<form method="post" action="/action"><input type="hidden" name="csrf" value="${session.csrf}"><button name="action" value="userinfo">查询用户身份</button><button name="action" value="refresh">刷新令牌</button><button name="action" value="replay">重放旧刷新令牌</button><button name="action" value="revoke">撤销访问令牌</button></form>
<p role="status">${escape(session.message ?? '尚未登录')}</p><pre>${escape(JSON.stringify(session.identity ?? {}, null, 2))}</pre></html>`)
}

const server = createServer(async (request, response) => {
  const url = new URL(request.url, `http://127.0.0.1:${port}`)
  const cookie = request.headers.cookie?.match(/(?:^|;\s*)oidc_demo=([a-zA-Z0-9_-]+)/)?.[1]
  let session = sessions.get(cookie)
  if (!session) {
    const id = random()
    session = { csrf: random() }
    sessions.set(id, session)
    response.setHeader('Set-Cookie', `oidc_demo=${id}; HttpOnly; SameSite=Lax; Path=/`)
  }
  try {
    if (url.pathname === '/login' && request.method === 'GET') {
      session.state = random()
      session.nonce = random()
      session.verifier = random()
      const target = new URL(discovery.authorization_endpoint)
      target.search = new URLSearchParams({ client_id: config.clientId, redirect_uri: callback, response_type: 'code', scope: 'openid profile email offline_access', state: session.state, nonce: session.nonce, code_challenge: hash(session.verifier).toString('base64url'), code_challenge_method: 'S256', prompt: 'consent' }).toString()
      response.writeHead(302, { Location: target.href })
      response.end()
      return
    }
    if (url.pathname === '/callback' && request.method === 'GET') {
      if (!session.state || url.searchParams.get('state') !== session.state) throw new Error('state 不一致')
      delete session.state
      if (url.searchParams.has('error')) throw new Error(`授权拒绝：${url.searchParams.get('error')}`)
      const code = url.searchParams.get('code')
      if (!code) throw new Error('回调缺少 code')
      const tokens = await tokenRequest({ grant_type: 'authorization_code', code, redirect_uri: callback, code_verifier: session.verifier })
      await validateIdToken(tokens, session, true)
      session.tokens = tokens
      session.identity = await requestJson(discovery.userinfo_endpoint, { headers: { Authorization: `Bearer ${tokens.access_token}` } })
      if (session.identity.sub !== session.sub) throw new Error('UserInfo sub 与 ID Token 不一致')
      session.message = '登录成功：签名、issuer、audience、时效、nonce、at_hash 与 UserInfo 身份校验通过'
      response.writeHead(303, { Location: '/' })
      response.end()
      return
    }
    if (url.pathname === '/action' && request.method === 'POST') {
      let body = ''
      for await (const chunk of request) { body += chunk; if (body.length > 4096) throw new Error('请求过大') }
      const data = new URLSearchParams(body)
      if (data.get('csrf') !== session.csrf) throw new Error('CSRF 校验失败')
      if (!session.tokens) throw new Error('请先登录')
      const action = data.get('action')
      if (action === 'userinfo') {
        session.identity = await requestJson(discovery.userinfo_endpoint, { headers: { Authorization: `Bearer ${session.tokens.access_token}` } })
        if (session.identity.sub !== session.sub) throw new Error('UserInfo sub 不一致')
        session.message = 'UserInfo 查询成功'
      } else if (action === 'refresh' || action === 'replay') {
        const refreshToken = action === 'replay' ? session.oldRefresh : session.tokens.refresh_token
        if (!refreshToken) throw new Error('缺少刷新令牌')
        const tokens = await tokenRequest({ grant_type: 'refresh_token', refresh_token: refreshToken })
        await validateIdToken(tokens, session, false)
        session.oldRefresh = refreshToken
        session.tokens = tokens
        session.message = '刷新成功，已保存轮换后的刷新令牌'
      } else if (action === 'revoke') {
        const data = new URLSearchParams({ client_id: config.clientId, token: session.tokens.access_token, token_type_hint: 'access_token' })
        if (config.clientSecret) data.set('client_secret', config.clientSecret)
        const result = await fetch(discovery.revocation_endpoint, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: data, redirect: 'error', signal: AbortSignal.timeout(10000) })
        if (!result.ok) throw new Error(`撤销失败：HTTP ${result.status}`)
        session.message = '访问令牌已撤销，可再次查询 UserInfo 验证拒绝'
      } else throw new Error('无效操作')
      response.writeHead(303, { Location: '/' })
      response.end()
      return
    }
    if (url.pathname !== '/' || request.method !== 'GET') {
      response.writeHead(404)
      response.end('Not Found')
      return
    }
  } catch (error) {
    session.message = error.message
  }
  sendPage(response, session)
})
server.listen(port, '127.0.0.1', () => console.log(`OIDC 联调应用：http://127.0.0.1:${port}`))
