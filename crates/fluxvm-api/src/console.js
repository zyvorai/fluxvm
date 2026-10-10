// FluxVM dashboard: VMs and container sandboxes grouped by stack, with power actions and logs. Talks only to this
// daemon's REST API. Everything from the API is rendered with textContent, never as HTML.
'use strict';

const TOKEN_KEY = 'fluxvm.token';
const STACK = 'fluxvm.stack';
const SERVICE = 'fluxvm.service';
const $ = (id) => document.getElementById(id);
let logsFor = null;
let timer = null;

function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const c of children) {
    if (c !== null && c !== undefined) e.append(c instanceof Node ? c : String(c));
  }
  return e;
}

class Unauthorized extends Error {}

async function api(method, path, { text = false } = {}) {
  const headers = {};
  const token = sessionStorage.getItem(TOKEN_KEY);
  if (token) headers.Authorization = 'Bearer ' + token;
  const r = await fetch(path, { method, headers, cache: 'no-store' });
  if (r.status === 401) throw new Unauthorized();
  const body = text ? await r.text() : await r.json().catch(() => ({}));
  if (!r.ok) throw new Error((body && body.error) || r.status + ' ' + r.statusText);
  return body;
}

function showError(e) {
  if (e instanceof Unauthorized) {
    $('login').hidden = false;
    $('error').textContent = sessionStorage.getItem(TOKEN_KEY) ? 'token rejected' : '';
    return;
  }
  $('error').textContent = String(e.message || e);
}

const isContainer = (vm) => !!(vm.request && vm.request.apple && vm.request.apple.init_config);

function ports(vm) {
  const net = vm.request && vm.request.network;
  const fwd = (net && net.forwards) || [];
  return fwd.map((f) => (f.guests ? 'guests:' : '') + f.host_port + '→' + f.guest_port).join(' ');
}

function pill(status) {
  return el('span', { class: 'pill ' + status }, status);
}

async function act(vm, op) {
  if (op === 'delete' && !confirm('Delete ' + vm.name + '? Its disk is removed.')) return;
  try {
    if (op === 'delete') await api('DELETE', '/v1/vms/' + vm.id);
    else await api('POST', '/v1/vms/' + vm.id + '/' + op);
    if (logsFor && logsFor.id === vm.id && op === 'delete') closeLogs();
  } catch (e) {
    showError(e);
  }
  refresh();
}

function actions(vm) {
  const b = (label, op, cls) => el('button', { class: cls || '', onclick: () => act(vm, op) }, label);
  const td = el('td', { class: 'actions' });
  td.append(el('button', { onclick: () => openLogs(vm) }, 'Logs'));
  if (vm.status === 'running') td.append(b('Restart', 'restart'), b('Stop', 'stop'));
  else if (vm.status === 'stopped' || vm.status === 'failed') td.append(b('Start', 'start'));
  else if (vm.status === 'paused') td.append(b('Resume', 'resume'));
  td.append(b('Delete', 'delete', 'danger'));
  return td;
}

function vmTable(vms, inStack) {
  const head = el('tr', {}, ...[inStack ? 'Service' : 'Name', 'Kind', 'Status', 'Address', 'Size', 'Ports', '']
    .map((h) => el('th', {}, h)));
  const rows = vms.map((vm) => el('tr', {},
    el('td', {}, inStack ? (vm.labels[SERVICE] || vm.name) : vm.name,
      vm.error ? el('div', { class: 'failed' }, vm.error) : null),
    el('td', { class: 'muted' }, isContainer(vm) ? 'container' : vm.backend),
    el('td', {}, pill(vm.status)),
    el('td', {}, el('code', {}, vm.guest_ip || '')),
    el('td', { class: 'muted' }, vm.request.vcpus + ' vCPU · ' + vm.request.memory_mib + ' MiB'),
    el('td', {}, el('code', {}, ports(vm))),
    actions(vm)));
  return el('table', {}, el('thead', {}, head), el('tbody', {}, ...rows));
}

function stackActions(name, vms) {
  const all = async (op, want) => {
    for (const vm of vms.filter(want)) {
      try { await api('POST', '/v1/vms/' + vm.id + '/' + op); } catch (e) { showError(e); }
    }
    refresh();
  };
  return [
    el('button', { onclick: () => all('start', (v) => v.status === 'stopped' || v.status === 'failed') }, 'Start all'),
    el('button', { onclick: () => all('stop', (v) => v.status === 'running') }, 'Stop all'),
  ];
}

function render(vms, density) {
  const count = (s) => vms.filter((v) => v.status === s).length;
  const stats = [['VMs', vms.length], ['running', count('running')], ['stopped', count('stopped')],
    ['failed', count('failed')], ['containers', vms.filter(isContainer).length]];
  if (density && density.host_pressure_level) stats.push(['memory pressure', density.host_pressure_level]);
  $('stats').replaceChildren(...stats.map(([k, v]) => el('div', { class: 'stat' }, el('b', {}, v), el('span', { class: 'muted' }, k))));

  const stacks = new Map();
  const loose = [];
  for (const vm of vms.sort((a, b) => a.name.localeCompare(b.name))) {
    const s = vm.labels && vm.labels[STACK];
    if (s) (stacks.get(s) || stacks.set(s, []).get(s)).push(vm);
    else loose.push(vm);
  }
  const cards = [...stacks.keys()].sort().map((name) => el('section', { class: 'card' },
    el('h2', {}, 'Stack ', el('code', {}, name), ' ', ...stackActions(name, stacks.get(name))),
    vmTable(stacks.get(name), true)));
  if (loose.length) cards.push(el('section', { class: 'card' }, el('h2', {}, stacks.size ? 'Other VMs' : 'VMs'), vmTable(loose, false)));
  if (!vms.length) cards.push(el('section', { class: 'card muted' }, 'No VMs. Create one with fluxctl run, sandbox run or up.'));
  $('groups').replaceChildren(...cards);
}

async function refresh() {
  try {
    const [list, density] = await Promise.all([
      api('GET', '/v1/vms'),
      api('GET', '/v1/sandboxes/density').catch((e) => { if (e instanceof Unauthorized) throw e; return null; }),
    ]);
    $('login').hidden = true;
    $('logout').hidden = !sessionStorage.getItem(TOKEN_KEY);
    $('error').textContent = '';
    $('host').textContent = location.host;
    render(list.items || [], density);
    if (logsFor && !$('logs').hidden) loadLogs();
  } catch (e) {
    showError(e);
  }
}

function openLogs(vm) {
  logsFor = vm;
  $('logs').hidden = false;
  $('logs-title').textContent = 'Logs: ' + vm.name;
  $('logs-body').textContent = '…';
  loadLogs();
  $('logs').scrollIntoView({ behavior: 'smooth' });
}

function closeLogs() {
  logsFor = null;
  $('logs').hidden = true;
}

async function loadLogs() {
  const vm = logsFor;
  if (!vm) return;
  try {
    if (isContainer(vm)) {
      const l = await api('GET', '/v1/sandboxes/' + vm.id + '/logs?lines=200');
      const meta = [];
      if (l.health) meta.push('health: ' + l.health);
      if (l.restarts) meta.push('restarts: ' + l.restarts);
      if (l.exit_code !== null && l.exit_code !== undefined) meta.push('exit code: ' + l.exit_code);
      if (l.init_error) meta.push('init error: ' + l.init_error);
      $('logs-meta').textContent = meta.join(' · ');
      $('logs-body').textContent = l.log || '';
    } else {
      $('logs-meta').textContent = 'console output';
      $('logs-body').textContent = await api('GET', '/v1/vms/' + vm.id + '/logs?lines=200', { text: true });
    }
  } catch (e) {
    $('logs-body').textContent = String(e.message || e);
  }
}

function schedule() {
  clearInterval(timer);
  if ($('auto').checked) timer = setInterval(() => { if (!document.hidden) refresh(); }, 5000);
}

$('login-form').addEventListener('submit', (ev) => {
  ev.preventDefault();
  sessionStorage.setItem(TOKEN_KEY, $('token').value.trim());
  $('token').value = '';
  refresh();
});
$('logout').addEventListener('click', () => { sessionStorage.removeItem(TOKEN_KEY); location.reload(); });
$('refresh').addEventListener('click', refresh);
$('auto').addEventListener('change', schedule);
$('logs-close').addEventListener('click', closeLogs);
$('logs-reload').addEventListener('click', loadLogs);
schedule();
refresh();
