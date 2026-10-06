'use strict';

// Finds WildFly standalone server processes running on this host by scanning
// /proc (Linux) and derives each instance's HTTP management URL from its
// command line: -bmanagement / jboss.bind.address.management,
// jboss.management.http.port and jboss.socket.binding.port-offset.
//
// Values that are only set inside standalone.xml are invisible here, so the
// caller verifies every candidate by asking the management API for its PID.

const fs = require('fs');
const path = require('path');

function readCmdline(procDir, pid) {
  try {
    return fs.readFileSync(path.join(procDir, pid, 'cmdline'), 'latin1').split('\0').filter(Boolean);
  } catch (_) {
    return null; // process exited or not readable
  }
}

let passwdCache = null;
function userName(uid) {
  if (!passwdCache) {
    passwdCache = new Map();
    try {
      for (const line of fs.readFileSync('/etc/passwd', 'utf8').split('\n')) {
        const [name, , id] = line.split(':');
        if (name && id) passwdCache.set(Number(id), name);
      }
    } catch (_) { /* no passwd file */ }
  }
  return passwdCache.get(uid) || String(uid);
}

function processUser(procDir, pid) {
  try {
    const m = /^Uid:\s+(\d+)/m.exec(fs.readFileSync(path.join(procDir, pid, 'status'), 'utf8'));
    return m ? userName(Number(m[1])) : null;
  } catch (_) {
    return null;
  }
}

/** Returns the value of `-Dname=value`, `--name=value` or `name value` style options (last one wins). */
function option(args, names) {
  let value;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    for (const n of names) {
      if (a.startsWith(`${n}=`)) value = a.slice(n.length + 1);
      else if (a === n && !n.startsWith('-D') && i + 1 < args.length) value = args[i + 1];
    }
  }
  return value;
}

const intOr = (v, def) => (v !== undefined && /^-?\d+$/.test(String(v)) ? Number(v) : def);

/** System properties given on the command line; -b/-bmanagement are shortcuts for bind addresses. */
function systemProperties(args) {
  const props = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    let m = /^-D([^=]+)=(.*)$/.exec(a);
    if (m) { props[m[1]] = m[2]; continue; }
    m = /^-b(management)?(?:=(.*))?$/.exec(a);
    if (m) {
      const value = m[2] !== undefined ? m[2] : args[i + 1];
      if (value !== undefined) props[m[1] ? 'jboss.bind.address.management' : 'jboss.bind.address'] = value;
    }
  }
  return props;
}

/** Resolves a WildFly expression such as ${jboss.socket.binding.port-offset:0} against the given properties. */
function resolveExpression(value, props) {
  if (value === undefined || value === null) return undefined;
  return String(value).replace(/\$\{([^}]+)\}/g, (_, expr) => {
    const i = expr.indexOf(':');
    const names = (i < 0 ? expr : expr.slice(0, i)).split(',');
    for (const n of names) if (props[n.trim()] !== undefined) return props[n.trim()];
    return i < 0 ? '' : expr.slice(i + 1);
  });
}

/**
 * Reads the management port, port offset and management address from the
 * server's configuration file (standalone*.xml). Instances that share one
 * base dir usually differ only by the -c file, which holds their port offset.
 */
function readServerConfig(file, props) {
  let xml;
  try {
    xml = fs.readFileSync(file, 'utf8');
  } catch (_) {
    return null;
  }
  const attr = (re) => { const m = re.exec(xml); return m ? resolveExpression(m[1], props) : undefined; };
  return {
    offset: attr(/<socket-binding-group\b[^>]*\bport-offset="([^"]*)"/),
    port: attr(/<socket-binding\s+name="management-http"[^>]*\bport="([^"]*)"/),
    address: attr(/<interface\s+name="management"\s*>\s*<inet-address\s+value="([^"]*)"/),
  };
}

/** Parses a WildFly java command line; returns null when it is not a WildFly server process. */
function parseCommandLine(args) {
  if (!args || !args.some((a) => /jboss-modules\.jar$/.test(a))) return null;
  const domainServer = args.find((a) => /^-D\[Server:.+\]$/.test(a));
  const kind = args.includes('-D[Standalone]') ? 'standalone'
    : domainServer ? 'domain-server'
      : args.includes('-D[Host Controller]') ? 'host-controller'
        : args.includes('-D[Process Controller]') ? 'process-controller' : 'standalone';

  const props = systemProperties(args);
  const home = option(args, ['-Djboss.home.dir']) || null;
  const baseDir = option(args, ['-Djboss.server.base.dir']) || (home ? path.join(home, 'standalone') : null);
  const configFile = option(args, ['-c', '--server-config', '-Djboss.server.default.config']) || 'standalone.xml';
  const configDir = props['jboss.server.config.dir'] || (baseDir ? path.join(baseDir, 'configuration') : null);
  const configPath = path.isAbsolute(configFile) ? configFile : (configDir ? path.join(configDir, configFile) : null);
  const xml = (configPath && readServerConfig(configPath, props)) || {};

  // The configuration file wins (its expressions already see the -D values); fall back to the command line.
  const offset = intOr(xml.offset, intOr(props['jboss.socket.binding.port-offset'], 0));
  const port = intOr(xml.port, intOr(props['jboss.management.http.port'], 9990)) + offset;
  let address = xml.address || props['jboss.bind.address.management'] || '127.0.0.1';
  if (/^(0\.0\.0\.0|::|\[::\]|)$/.test(address) || address.includes('${')) address = '127.0.0.1';
  const serverName = option(args, ['-Djboss.server.name', '-Djboss.node.name']) ||
    (domainServer ? domainServer.slice(10, -1) : null);
  const host = address.includes(':') && !address.startsWith('[') ? `[${address}]` : address;

  return { kind, address, port, offset, url: `http://${host}:${port}/management`, home, baseDir, configFile, configPath, serverName };
}

/** Scans /proc for WildFly processes. Only standalone servers have their own management endpoint. */
function scan(procDir = '/proc') {
  let pids;
  try {
    pids = fs.readdirSync(procDir).filter((d) => /^\d+$/.test(d));
  } catch (_) {
    return []; // not Linux / no procfs
  }
  const found = [];
  for (const pid of pids) {
    const args = readCmdline(procDir, pid);
    const info = args && parseCommandLine(args);
    if (!info || info.kind !== 'standalone') continue;
    found.push({ pid: Number(pid), user: processUser(procDir, pid), ...info });
  }
  return found.sort((a, b) => a.port - b.port);
}

module.exports = { scan, parseCommandLine, resolveExpression };
