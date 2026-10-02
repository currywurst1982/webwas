'use strict';

// Dashboard users (not WildFly management users). Passwords are stored as
// scrypt hashes in <dataDir>/users.json. On first start an "admin" account is
// created; its password must be changed at first login.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const ROLES = ['admin', 'viewer'];
const MAX_FAILURES = 5;
const LOCK_MS = 5 * 60 * 1000;

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return { salt, hash };
}

function verifyPassword(password, user) {
  const { hash } = hashPassword(password, user.salt);
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(user.hash, 'hex'));
}

function validatePassword(pw) {
  if (typeof pw !== 'string' || pw.length < 8) return '비밀번호는 8자 이상이어야 합니다';
  if (!/[A-Za-z]/.test(pw) || !/\d/.test(pw)) return '비밀번호는 영문자와 숫자를 모두 포함해야 합니다';
  return null;
}

class UserStore {
  constructor(dataDir) {
    this.file = path.join(dataDir, 'users.json');
    this.users = [];
    this.failures = new Map();
    this.load();
  }

  load() {
    try {
      this.mtime = fs.statSync(this.file).mtimeMs;
      this.users = JSON.parse(fs.readFileSync(this.file, 'utf8')).users || [];
    } catch (e) {
      if (e.code !== 'ENOENT') throw e;
      this.users = [];
    }
  }

  /** Picks up changes made by scripts/add-user.js while the server is running. */
  reloadIfChanged() {
    try {
      if (fs.statSync(this.file).mtimeMs !== this.mtime) this.load();
    } catch (_) { /* file not created yet */ }
  }

  save() {
    const tmp = `${this.file}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify({ users: this.users }, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, this.file);
    this.mtime = fs.statSync(this.file).mtimeMs;
  }

  /** Creates the initial admin account; returns the generated password if one was generated. */
  ensureAdmin() {
    if (this.users.length) return null;
    const provided = process.env.DASHBOARD_ADMIN_PASSWORD;
    const password = provided || crypto.randomBytes(9).toString('base64url');
    this.upsert('admin', password, 'admin', { mustChangePassword: true });
    return provided ? null : password;
  }

  find(username) {
    this.reloadIfChanged();
    return this.users.find((u) => u.username === username);
  }

  upsert(username, password, role = 'viewer', extra = {}) {
    if (!/^[A-Za-z0-9._-]{3,32}$/.test(username)) throw new Error('사용자 이름은 3~32자의 영문/숫자/._- 만 사용할 수 있습니다');
    if (!ROLES.includes(role)) throw new Error(`역할은 ${ROLES.join(', ')} 중 하나여야 합니다`);
    const existing = this.find(username);
    const record = { username, role, ...hashPassword(password), mustChangePassword: false, ...extra, updatedAt: new Date().toISOString() };
    if (existing) Object.assign(existing, record);
    else this.users.push({ ...record, createdAt: record.updatedAt });
    this.save();
  }

  authenticate(username, password, ip) {
    const key = `${ip}|${username}`;
    const f = this.failures.get(key);
    if (f && f.count >= MAX_FAILURES && Date.now() - f.last < LOCK_MS) {
      return { error: '로그인 실패 횟수 초과로 5분간 잠겼습니다', locked: true };
    }
    const user = this.find(username);
    const ok = user ? verifyPassword(password, user) : (hashPassword(password), false); // equalize timing
    if (!ok) {
      const cur = f && Date.now() - f.last < LOCK_MS ? f : { count: 0 };
      this.failures.set(key, { count: cur.count + 1, last: Date.now() });
      return { error: '아이디 또는 비밀번호가 올바르지 않습니다' };
    }
    this.failures.delete(key);
    user.lastLoginAt = new Date().toISOString();
    this.save();
    return { user };
  }

  changePassword(username, current, next) {
    const user = this.find(username);
    if (!user || !verifyPassword(current, user)) throw new Error('현재 비밀번호가 올바르지 않습니다');
    const err = validatePassword(next);
    if (err) throw new Error(err);
    if (current === next) throw new Error('새 비밀번호는 현재 비밀번호와 달라야 합니다');
    Object.assign(user, hashPassword(next), { mustChangePassword: false, updatedAt: new Date().toISOString() });
    this.save();
  }
}

function publicUser(u) {
  return u && { username: u.username, role: u.role, mustChangePassword: Boolean(u.mustChangePassword) };
}

/** Requires a logged-in user; users that must change their password may only reach the password API. */
function requireLogin(store) {
  return (req, res, next) => {
    const user = req.session && req.session.username && store.find(req.session.username);
    if (!user) return res.status(401).json({ error: '로그인이 필요합니다' });
    if (user.mustChangePassword && !req.path.startsWith('/auth/')) {
      return res.status(403).json({ error: '비밀번호를 먼저 변경해야 합니다', mustChangePassword: true });
    }
    req.user = user;
    next();
  };
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') return res.status(403).json({ error: '관리자 권한이 필요합니다' });
  next();
}

module.exports = { UserStore, requireLogin, requireAdmin, publicUser, validatePassword, ROLES };
