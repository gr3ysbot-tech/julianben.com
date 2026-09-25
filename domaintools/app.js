/**
 * 100% client-side. No backend at all -- this file runs entirely in the
 * visitor's browser, on GitHub Pages' static hosting.
 *
 * MX/SPF/DMARC/DKIM: real DNS lookups via Cloudflare's DNS-over-HTTPS JSON
 * API (cloudflare-dns.com/dns-query), which sends
 * "Access-Control-Allow-Origin: *" -- confirmed by hand before building
 * this, not assumed. Genuinely the same DNS answers a real resolver gives,
 * just reached over HTTPS instead of raw UDP port 53 (which a browser has
 * no API for at all).
 *
 * WHOIS: real WHOIS (port 43, raw TCP) is categorically impossible from a
 * browser -- there is no browser API for a raw socket, on any platform, full
 * stop. RDAP (RFC 9083) is the modern HTTPS-based replacement most
 * registries have adopted since 2021, and several major ones -- confirmed
 * for Verisign (.com/.net), PIR (.org), Google Registry (.dev) -- send open
 * CORS headers. Coverage is real but incomplete: some TLDs (.io and .co
 * among them, confirmed against IANA's own bootstrap list) have no RDAP
 * service published at all, and a registry that supports RDAP without CORS
 * headers would still fail here even though `curl` could reach it fine --
 * the failure is specific to being called from a browser. Both cases are
 * reported plainly rather than silently, which is the whole reason this
 * exists as a static-hosting trade-off instead of just being called a bug.
 */

const DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query";
const RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json";

let rdapBootstrapCache = null;

async function dohQuery(name, type) {
  const url = `${DOH_ENDPOINT}?name=${encodeURIComponent(name)}&type=${type}`;
  const res = await fetch(url, { headers: { accept: "application/dns-json" } });
  if (!res.ok) throw new Error(`DNS query failed (${res.status})`);
  const json = await res.json();
  return json.Answer || [];
}

/**
 * A TXT record's "data" field is one or more double-quoted character-strings
 * separated by a space, e.g. `"\"part one\" \"part two\""` -- DNS splits any
 * string over 255 bytes into multiple such segments, and reassembling the
 * real value means concatenating them with NO separator, not a space.
 * Verified on a real record: github.com's SPF answer arrives as two segments
 * ending "...ip4:62.253.2" and starting "27.114 ip4:...", which is the
 * address 62.253.227.114 -- inserting a space between them would silently
 * corrupt that IP into two different, wrong ones.
 */
function parseTxtData(data) {
  const segments = [...data.matchAll(/"((?:[^"\\]|\\.)*)"/g)];
  if (!segments.length) return data;
  return segments.map((m) => m[1].replace(/\\"/g, '"')).join("");
}

async function lookupMx(domain) {
  try {
    const answers = await dohQuery(domain, "MX");
    return answers
      .map((a) => {
        const m = /^(\d+)\s+(\S+)$/.exec(a.data.trim());
        if (!m) return null;
        const exchange = m[2].replace(/\.$/, "");
        return { priority: Number(m[1]), exchange, isNullMx: exchange === "" || exchange === "." };
      })
      .filter(Boolean)
      .sort((a, b) => a.priority - b.priority);
  } catch {
    return [];
  }
}

async function lookupTxt(name) {
  try {
    const answers = await dohQuery(name, "TXT");
    return answers.map((a) => parseTxtData(a.data));
  } catch {
    return [];
  }
}

async function lookupSpf(domain) {
  const txts = await lookupTxt(domain);
  return txts.find((t) => t.toLowerCase().startsWith("v=spf1")) ?? null;
}

/**
 * RFC 7208 caps SPF at 10 DNS-lookup-costing mechanisms (include, a, mx,
 * ptr, exists, redirect -- ip4/ip6/all cost nothing) across the WHOLE
 * resolved tree, includes recursively counted. Exceeding it isn't a warning
 * in real mail servers, it's a PermError -- the entire SPF record stops
 * being evaluated. A flat "here's the raw record" view can't show this at
 * all, since the cost is hidden inside each include's own record.
 */
const SPF_LOOKUP_TYPES = new Set(["include", "a", "mx", "ptr", "exists", "redirect"]);
const SPF_MAX_DEPTH = 10; // matches the RFC's own lookup cap, used as a recursion backstop against loops

function classifySpfTerm(term) {
  const qm = /^([+\-~?])?(.+)$/.exec(term);
  const qualifier = qm[1] || "+";
  const rest = qm[2];
  if (rest === "all") return { type: "all", qualifier, raw: term };
  if (rest.startsWith("include:")) return { type: "include", value: rest.slice(8), qualifier, raw: term };
  if (rest.startsWith("redirect=")) return { type: "redirect", value: rest.slice(9), qualifier, raw: term };
  if (rest.startsWith("ip4:")) return { type: "ip4", value: rest.slice(4), qualifier, raw: term };
  if (rest.startsWith("ip6:")) return { type: "ip6", value: rest.slice(4), qualifier, raw: term };
  if (rest === "a" || rest.startsWith("a:") || rest.startsWith("a/")) return { type: "a", value: rest.includes(":") ? rest.split(":")[1] : null, qualifier, raw: term };
  if (rest === "mx" || rest.startsWith("mx:") || rest.startsWith("mx/")) return { type: "mx", value: rest.includes(":") ? rest.split(":")[1] : null, qualifier, raw: term };
  if (rest === "ptr" || rest.startsWith("ptr:")) return { type: "ptr", value: rest.startsWith("ptr:") ? rest.slice(4) : null, qualifier, raw: term };
  if (rest.startsWith("exists:")) return { type: "exists", value: rest.slice(7), qualifier, raw: term };
  if (rest.startsWith("exp=")) return { type: "exp", value: rest.slice(4), qualifier, raw: term };
  return { type: "unknown", value: rest, qualifier, raw: term };
}

/**
 * Resolves one domain's SPF record plus every include/redirect it names,
 * recursively, into a tree -- mirroring exactly what a real mail server
 * evaluating this record would have to fetch. `budget` is a single object
 * shared across the whole recursion so the lookup count is the TOTAL across
 * every node, not per-node. `visited` guards against a circular include
 * (A includes B includes A) hanging the page in an infinite fetch loop.
 */
async function resolveSpfNode(domain, record, depth, budget, visited) {
  const node = { domain, record, terms: [], includes: [], ips: [], macros: [], error: null, circular: false };
  if (!record) {
    node.error = "No v=spf1 TXT record found here.";
    return node;
  }
  if (visited.has(domain)) {
    node.circular = true;
    node.error = "Circular include — this domain is already part of the chain above.";
    return node;
  }
  visited.add(domain);

  const terms = parseSpfBody(record).map(classifySpfTerm);
  node.terms = terms;

  for (const t of terms) {
    if (t.raw.includes("%{")) node.macros.push(t.raw);
    if (t.type === "ip4" || t.type === "ip6") node.ips.push(t.value);
    if (!SPF_LOOKUP_TYPES.has(t.type)) continue;
    budget.count++;
    if ((t.type !== "include" && t.type !== "redirect") || !t.value) continue;
    if (depth >= SPF_MAX_DEPTH) {
      node.includes.push({ term: t, child: { domain: t.value, record: null, error: "Not expanded — reached the depth this tool follows (matches RFC 7208's own 10-lookup cap).", terms: [], includes: [], ips: [], macros: [] } });
      continue;
    }
    let childRecord = null;
    let fetchError = null;
    try {
      childRecord = await lookupSpf(t.value);
    } catch (err) {
      fetchError = err.message;
    }
    const child = await resolveSpfNode(t.value, childRecord, depth + 1, budget, visited);
    if (!childRecord && fetchError) child.error = fetchError;
    node.includes.push({ term: t, child });
  }
  return node;
}

function parseSpfBody(record) {
  return record.trim().split(/\s+/).slice(1); // drop the leading "v=spf1"
}

async function lookupDmarc(domain) {
  const txts = await lookupTxt(`_dmarc.${domain}`);
  return txts.find((t) => t.toLowerCase().startsWith("v=dmarc1")) ?? null;
}

const COMMON_DKIM_SELECTORS = [
  "google", "selector1", "selector2", "k1", "k2", "k3", "default",
  "dkim", "dkim1", "mail", "smtp", "mandrill", "sendgrid", "mailgun",
  "zoho", "protonmail", "protonmail2", "protonmail3", "amazonses",
  "s1", "s2", "everlytickey1", "everlytickey2", "cm", "litesrv",
];

const PROVIDER_SIGNATURES = [
  { name: "Google Workspace", matchesMx: /aspmx\.l\.google\.com|google\.com$/i, matchesSpf: /_spf\.google\.com/i, selectors: ["google"] },
  { name: "Microsoft 365", matchesMx: /mail\.protection\.outlook\.com/i, matchesSpf: /spf\.protection\.outlook\.com/i, selectors: ["selector1", "selector2"] },
  { name: "Zoho Mail", matchesMx: /zoho\.(com|eu|in)/i, matchesSpf: /zoho(mail)?\.(com|eu|in)/i, selectors: ["zoho", "zmail"] },
  { name: "ProtonMail", matchesMx: /protonmail\.ch|proton\.me/i, matchesSpf: /protonmail\.ch|_spf\.protonmail/i, selectors: ["protonmail", "protonmail2", "protonmail3"] },
  { name: "Mailgun", matchesSpf: /mailgun\.org/i, selectors: ["mg", "k1", "krs", "smtp", "mailo"] },
  { name: "SendGrid", matchesSpf: /sendgrid\.net/i, selectors: ["s1", "s2", "smtpapi", "em"] },
  { name: "Mailchimp / Mandrill", matchesSpf: /servers\.mcsv\.net|mandrillapp\.com/i, selectors: ["k1", "k2", "k3", "mandrill"] },
  { name: "Amazon SES", matchesSpf: /amazonses\.com/i, selectors: ["amazonses"] },
  { name: "Postmark", matchesSpf: /spf\.mtasv\.net/i, selectors: ["20161025", "postmark", "pm"] },
  { name: "HubSpot", matchesSpf: /hubspotemail\.net/i, selectors: ["hs1", "hs2", "hubspot"] },
  { name: "Klaviyo", matchesSpf: /_spf\.klaviyomail\.com/i, selectors: ["dkim", "k1", "k2"] },
  { name: "Fastmail", matchesMx: /messagingengine\.com/i, selectors: ["fm1", "fm2", "fm3"] },
  { name: "GoDaddy Email", matchesMx: /secureserver\.net/i, selectors: ["smartermail", "dkim", "default"] },
  { name: "Rackspace Email", matchesMx: /emailsrvr\.com/i, selectors: ["rs1", "rs2", "default"] },
  { name: "iCloud Mail", matchesMx: /icloud\.com/i, selectors: ["sig1"] },
  { name: "Yandex Mail", matchesMx: /mx\.yandex\.net/i, selectors: ["mail"] },
];

function isDkimShaped(txt) {
  return /v=dkim1|p=/i.test(txt);
}

const WILDCARD_PROBE_SELECTOR = "glitch-dkim-wildcard-probe-x7f2q9";

async function lookupDkim(domain, extraSelector, mxRecords, spfRecord) {
  const mxHosts = mxRecords.map((r) => r.exchange).join(" ");
  const spfText = spfRecord ?? "";
  const detected = PROVIDER_SIGNATURES.filter(
    (p) => (p.matchesMx && p.matchesMx.test(mxHosts)) || (p.matchesSpf && p.matchesSpf.test(spfText)),
  );
  const cleanedExtra = extraSelector?.trim();
  const ordered = [
    ...(cleanedExtra ? [cleanedExtra] : []),
    ...detected.flatMap((p) => p.selectors),
    ...COMMON_DKIM_SELECTORS,
  ];
  const selectors = [...new Set(ordered)];

  const [probeTxts, ...selectorResults] = await Promise.all([
    lookupTxt(`${WILDCARD_PROBE_SELECTOR}._domainkey.${domain}`),
    ...selectors.map(async (selector) => {
      const txts = await lookupTxt(`${selector}._domainkey.${domain}`);
      const record = txts.find(isDkimShaped);
      return record ? { selector, record } : null;
    }),
  ]);

  const wildcard = probeTxts.some(isDkimShaped);
  const hits = selectorResults.filter(Boolean);
  return { hits: wildcard ? [] : hits, wildcard, detectedProviders: detected.map((p) => p.name) };
}

async function getRdapBootstrap() {
  if (rdapBootstrapCache) return rdapBootstrapCache;
  const res = await fetch(RDAP_BOOTSTRAP);
  const json = await res.json();
  const map = new Map();
  for (const [tlds, urls] of json.services) {
    for (const tld of tlds) map.set(tld.toLowerCase(), urls);
  }
  rdapBootstrapCache = map;
  return map;
}

function vcardField(vcardArray, name) {
  if (!Array.isArray(vcardArray) || vcardArray[0] !== "vcard") return undefined;
  const entry = vcardArray[1]?.find((e) => e[0] === name);
  return entry?.[3];
}

function findRegistrar(entities) {
  for (const e of entities || []) {
    if (e.roles?.includes("registrar")) {
      return vcardField(e.vcardArray, "fn") || vcardField(e.vcardArray, "org");
    }
  }
  return undefined;
}

function eventDate(events, action) {
  return events?.find((e) => e.eventAction === action)?.eventDate;
}

async function lookupRdap(domain) {
  const tld = domain.split(".").pop();
  const bootstrap = await getRdapBootstrap();
  const urls = bootstrap.get(tld);
  if (!urls || !urls.length) {
    return { notCovered: true, tld };
  }
  const base = urls[0].endsWith("/") ? urls[0] : `${urls[0]}/`;
  const res = await fetch(`${base}domain/${domain}`);
  if (!res.ok) {
    if (res.status === 404) return { notFound: true, tld, server: base };
    throw new Error(`RDAP query failed (${res.status})`);
  }
  const json = await res.json();
  return {
    raw: json,
    server: base,
    registrar: findRegistrar(json.entities),
    createdDate: eventDate(json.events, "registration"),
    updatedDate: eventDate(json.events, "last changed"),
    expiryDate: eventDate(json.events, "expiration"),
    nameServers: (json.nameservers || []).map((n) => n.ldhName).filter(Boolean),
    status: json.status || [],
  };
}

// ---------------------------------------------------------------------
// UI wiring
// ---------------------------------------------------------------------

const els = {
  form: document.getElementById("lookupForm"),
  domain: document.getElementById("domainInput"),
  selector: document.getElementById("selectorInput"),
  advancedToggle: document.getElementById("advancedToggle"),
  advancedRow: document.getElementById("advancedRow"),
  submit: document.getElementById("submitBtn"),
  error: document.getElementById("errorBox"),
  results: document.getElementById("results"),
};

els.advancedToggle.addEventListener("click", () => {
  const hidden = els.advancedRow.hasAttribute("hidden");
  if (hidden) els.advancedRow.removeAttribute("hidden");
  else els.advancedRow.setAttribute("hidden", "");
  els.advancedToggle.textContent = hidden ? "Hide DKIM selector override" : "DKIM selector not detected automatically? Override it";
});

function badge(kind, text) {
  const span = document.createElement("span");
  span.className = `badge badge-${kind}`;
  span.textContent = text;
  return span;
}

function cardShell(title, subtitle, badgeEl) {
  const card = document.createElement("div");
  card.className = "card";
  const head = document.createElement("div");
  head.className = "card-head";
  const titleGroup = document.createElement("div");
  titleGroup.className = "card-title-group";
  const titleEl = document.createElement("span");
  titleEl.className = "card-title";
  titleEl.textContent = title;
  titleGroup.appendChild(titleEl);
  if (subtitle) {
    const subEl = document.createElement("span");
    subEl.className = "card-subtitle";
    subEl.textContent = subtitle;
    titleGroup.appendChild(subEl);
  }
  head.appendChild(titleGroup);
  head.appendChild(badgeEl);
  card.appendChild(head);
  const body = document.createElement("div");
  card.appendChild(body);
  return { card, body };
}

function emptyNote(text) {
  const p = document.createElement("p");
  p.className = "empty";
  p.textContent = text;
  return p;
}

function recordBox(text) {
  const div = document.createElement("div");
  div.className = "record-box";
  div.textContent = text;
  return div;
}

function renderMx(mx) {
  const { card, body } = mx.length
    ? mx.length === 1 && mx[0].isNullMx
      ? cardShell("MX", null, badge("neutral", "null MX"))
      : cardShell("MX", `${mx.length} record${mx.length === 1 ? "" : "s"}`, badge("good", "configured"))
    : cardShell("MX", null, badge("warn", "no records"));

  if (mx.length === 0) {
    body.appendChild(emptyNote("No MX records — mail sent to this domain has nowhere to go."));
  } else if (mx.length === 1 && mx[0].isNullMx) {
    body.appendChild(emptyNote("This domain explicitly declares it accepts no mail at all (RFC 7505 null MX) — a deliberate “don’t send mail here” record, not a missing one."));
  } else {
    const table = document.createElement("table");
    table.className = "mx-table";
    for (const r of mx) {
      const tr = document.createElement("tr");
      const tdP = document.createElement("td");
      tdP.className = "mx-priority";
      tdP.textContent = r.priority;
      const tdE = document.createElement("td");
      tdE.textContent = r.exchange;
      tr.append(tdP, tdE);
      table.appendChild(tr);
    }
    body.appendChild(table);
  }
  return card;
}

/**
 * Hard fail (-all) is not simply "stricter than, and therefore better than"
 * soft fail (~all) -- that was this tool's original assumption, and it's
 * backwards for a domain that actually sends mail. Once DMARC is in the
 * picture, "any SPF result that isn't an aligned pass is a failure" either
 * way (RFC 7489), so -all buys no extra DMARC-level security over ~all. What
 * it DOES do is act at the SMTP level, before DKIM/DMARC ever get evaluated
 * -- so a legitimately relayed message (common for any multi-domain org,
 * any forwarding setup) can be hard-rejected even with a fully valid DKIM
 * signature that would have proven it authentic. RFC 7489 10.1 warns
 * operators of exactly this. -all is the right, safe choice ONLY for a
 * domain that sends no mail at all (the null-MX case already detected
 * above) -- there, there's no legitimate mail flow for it to break.
 * https://www.mailhardener.com/blog/why-mailhardener-recommends-spf-softfail-over-fail
 */
function assessSpf(spf, mx, dmarcPolicy) {
  if (!spf) return { kind: "warn", label: "not found", note: "No SPF (v=spf1) TXT record on the root domain." };

  const sendsMail = mx.length > 0 && !(mx.length === 1 && mx[0].isNullMx);
  const isHard = /-all\s*$/.test(spf);
  const isSoft = /~all\s*$/.test(spf);
  const dmarcEnforcing = dmarcPolicy === "reject" || dmarcPolicy === "quarantine";

  if (isHard && !sendsMail) {
    return { kind: "good", label: "hard fail (-all)", note: "Correct for a domain that sends no mail — nothing legitimate for it to break." };
  }
  if (isHard && sendsMail) {
    return {
      kind: "warn",
      label: "hard fail (-all)",
      note: "This domain sends mail, so -all is a real risk, not just “stricter”: it rejects at the SMTP level before DKIM/DMARC are evaluated, so a legitimately relayed message with a valid DKIM signature can still be hard-rejected. Once DMARC is enforcing, -all adds no extra protection over ~all — consider switching.",
    };
  }
  if (isSoft && dmarcEnforcing) {
    return { kind: "good", label: "soft fail (~all)", note: "The recommended pairing — DMARC (p=" + dmarcPolicy + ") does the enforcing, without SPF risking a legitimate relayed message before DKIM gets a say." };
  }
  if (isSoft) {
    return { kind: "neutral", label: "soft fail (~all)", note: "Reasonable on its own, but pair it with an enforcing DMARC policy (p=quarantine or p=reject) for this to actually stop spoofed mail." };
  }
  if (/\+all\s*$/.test(spf)) {
    return { kind: "bad", label: "+all (pass everyone)", note: "This authorizes ANY server to send as this domain — effectively no SPF protection at all. Almost certainly a misconfiguration." };
  }
  return { kind: "neutral", label: "no all qualifier", note: "No explicit ~all/-all at the end — most SPF checkers treat this as neutral (?all), which validates nothing." };
}

function copyButton(text) {
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "copy-btn";
  btn.textContent = "Copy";
  btn.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(text);
      btn.textContent = "Copied";
    } catch {
      btn.textContent = "Copy failed";
    }
    setTimeout(() => { btn.textContent = "Copy"; }, 1200);
  });
  return btn;
}

function recordBoxWithCopy(label, text) {
  const wrap = document.createElement("div");
  wrap.className = "record-box-wrap";
  const box = document.createElement("div");
  box.className = "record-box";
  box.textContent = label ? `${label}: ${text}` : text;
  wrap.append(box, copyButton(text));
  return wrap;
}

function infoBar(kind, text) {
  const div = document.createElement("div");
  div.className = `info-bar info-bar-${kind}`;
  div.textContent = text;
  return div;
}

/** One collapsible node in the SPF include tree — the record itself (with a
 *  copy button), any ip4/ip6 mechanisms as scannable chips, a macro warning
 *  if the record can't be resolved statically, and a toggle per include
 *  that reveals the same structure one level deeper. Collapsed by default:
 *  a domain with several includes would otherwise dump every provider's
 *  entire SPF record on screen at once. */
function renderSpfNode(node) {
  const wrap = document.createElement("div");
  wrap.className = "spf-node";

  if (node.record) {
    wrap.appendChild(recordBoxWithCopy(node.domain, node.record));
  } else {
    const err = document.createElement("div");
    err.className = node.circular ? "spf-node-warn" : "spf-node-error";
    err.textContent = `${node.domain}: ${node.error || "no SPF record"}`;
    wrap.appendChild(err);
  }

  if (node.ips.length) {
    const chips = document.createElement("div");
    chips.className = "ip-chips";
    for (const ip of node.ips) {
      const chip = document.createElement("span");
      chip.className = "ip-chip";
      chip.textContent = ip;
      chips.appendChild(chip);
    }
    wrap.appendChild(chips);
  }

  if (node.macros.length) {
    wrap.appendChild(infoBar("warn", `Contains a macro that can't be resolved statically (${node.macros.join(", ")}) — a real SPF check would need the actual sending IP/hostname to evaluate this mechanism.`));
  }

  for (const inc of node.includes) {
    const row = document.createElement("div");
    row.className = "spf-include-row";
    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "spf-include-toggle";
    toggle.textContent = `▶ ${inc.term.raw}`;
    const childWrap = document.createElement("div");
    childWrap.className = "spf-include-child";
    childWrap.hidden = true;
    childWrap.appendChild(renderSpfNode(inc.child));
    toggle.addEventListener("click", () => {
      childWrap.hidden = !childWrap.hidden;
      toggle.textContent = `${childWrap.hidden ? "▶" : "▼"} ${inc.term.raw}`;
    });
    row.append(toggle, childWrap);
    wrap.appendChild(row);
  }

  return wrap;
}

function countMacros(node, seen = new Set()) {
  for (const m of node.macros) seen.add(m);
  for (const inc of node.includes) countMacros(inc.child, seen);
  return seen;
}

async function renderSpf(spf, mx, dmarcPolicy, domain) {
  const { kind, label, note } = assessSpf(spf, mx, dmarcPolicy);
  const { card, body } = cardShell("SPF", null, badge(kind, label));

  if (!spf) {
    body.appendChild(emptyNote(note));
    return card;
  }

  const budget = { count: 0 };
  const tree = await resolveSpfNode(domain, spf, 0, budget, new Set());
  body.appendChild(renderSpfNode(tree));

  const lookupKind = budget.count > 10 ? "bad" : budget.count === 10 ? "warn" : "good";
  body.appendChild(infoBar(lookupKind, `SPF DNS lookups: ${budget.count} (max 10, per RFC 7208)${budget.count > 10 ? " — OVER THE LIMIT: mail servers will PermError and may treat this as if SPF were unconfigured." : ""}`));

  const macros = countMacros(tree);
  if (macros.size) {
    body.appendChild(infoBar("warn", `${macros.size} mechanism${macros.size === 1 ? "" : "s"} in this chain use a macro that can't be resolved statically.`));
  }

  body.appendChild(infoBar(kind, note));

  return card;
}

function dmarcPolicyOf(dmarc) {
  return dmarc?.match(/p=([a-z]+)/i)?.[1]?.toLowerCase();
}

function renderDmarc(dmarc, policy) {
  if (!dmarc) {
    const { card, body } = cardShell("DMARC", null, badge("warn", "not found"));
    body.appendChild(emptyNote("No DMARC (v=DMARC1) TXT record at _dmarc.<domain>."));
    return card;
  }
  const kind = policy === "reject" ? "good" : policy === "quarantine" ? "warn" : "neutral";
  const { card, body } = cardShell("DMARC", null, badge(kind, `policy: ${policy ?? "unknown"}`));
  body.appendChild(recordBoxWithCopy(null, dmarc));
  return card;
}

function renderDkim(dkim) {
  const providerNote = dkim.detectedProviders.length
    ? `mail provider detected: ${dkim.detectedProviders.join(", ")}`
    : "no mail provider detected from MX/SPF — tried generic selectors only";

  if (dkim.wildcard) {
    const { card, body } = cardShell("DKIM", providerNote, badge("neutral", "wildcard DNS"));
    body.appendChild(emptyNote("This domain answers any subdomain query with a record, so every selector auto-tried “matched” — none of those hits are trustworthy. If you know the real selector, override it above."));
    return card;
  }
  if (dkim.hits.length === 0) {
    const { card, body } = cardShell("DKIM", providerNote, badge("warn", "none found"));
    body.appendChild(emptyNote(
      dkim.detectedProviders.length
        ? `${dkim.detectedProviders.join(", ")} was detected from MX/SPF and its own selector convention was tried automatically, but nothing matched — DKIM likely isn't configured, or a custom selector was chosen. Override it above if you know it.`
        : "No mail provider was recognizable from MX/SPF, so only generic default selectors were tried automatically. DKIM has no discovery mechanism — the real selector could still exist under a name that wasn't tried. Override it above if you know it.",
    ));
    return card;
  }
  const { card, body } = cardShell("DKIM", `${providerNote} · ${dkim.hits.length} selector${dkim.hits.length === 1 ? "" : "s"} found`, badge("good", "configured"));
  const list = document.createElement("div");
  list.className = "dkim-list";
  for (const h of dkim.hits) {
    const hit = document.createElement("div");
    hit.className = "dkim-hit";
    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "spf-include-toggle";
    toggle.textContent = `▶ ${h.selector}._domainkey`;
    const detail = document.createElement("div");
    detail.className = "spf-include-child";
    detail.hidden = true;
    detail.appendChild(recordBoxWithCopy(null, h.record));
    toggle.addEventListener("click", () => {
      detail.hidden = !detail.hidden;
      toggle.textContent = `${detail.hidden ? "▶" : "▼"} ${h.selector}._domainkey`;
    });
    hit.append(toggle, detail);
    list.appendChild(hit);
  }
  body.appendChild(list);
  return card;
}

function formatDate(iso) {
  if (!iso) return undefined;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().slice(0, 10);
}

function renderWhois(rdap, rdapError) {
  if (rdapError) {
    const { card, body } = cardShell("WHOIS (via RDAP)", null, badge("bad", "lookup failed"));
    body.appendChild(emptyNote(String(rdapError.message || rdapError)));
    return card;
  }
  if (rdap.notCovered) {
    const { card, body } = cardShell("WHOIS (via RDAP)", null, badge("neutral", "no RDAP for ." + rdap.tld));
    body.appendChild(emptyNote(`IANA lists no RDAP server for .${rdap.tld} — this TLD's registry hasn't published one. This is a real gap in RDAP coverage, not a bug here; there is no way to fetch WHOIS data for this domain from a browser.`));
    return card;
  }
  if (rdap.notFound) {
    const { card, body } = cardShell("WHOIS (via RDAP)", rdap.server, badge("warn", "not found"));
    body.appendChild(emptyNote("The registry's RDAP server returned no record for this exact domain."));
    return card;
  }

  const { card, body } = cardShell("WHOIS (via RDAP)", null, badge("neutral", rdap.server));
  const grid = document.createElement("div");
  grid.className = "whois-grid";
  const rows = [
    ["Registrar", rdap.registrar],
    ["Created", formatDate(rdap.createdDate)],
    ["Updated", formatDate(rdap.updatedDate)],
    ["Expires", formatDate(rdap.expiryDate)],
    ["Name servers", rdap.nameServers.join(", ")],
    ["Status", rdap.status.join(", ")],
  ];
  for (const [label, value] of rows) {
    if (!value) continue;
    const labelEl = document.createElement("div");
    labelEl.className = "whois-label";
    labelEl.textContent = label;
    const valueEl = document.createElement("div");
    valueEl.className = "whois-value";
    valueEl.textContent = value;
    grid.append(labelEl, valueEl);
  }
  body.appendChild(grid);

  const toggle = document.createElement("button");
  toggle.type = "button";
  toggle.className = "raw-toggle";
  toggle.textContent = "Show raw RDAP response";
  const rawBox = document.createElement("pre");
  rawBox.className = "raw-box";
  rawBox.hidden = true;
  rawBox.textContent = JSON.stringify(rdap.raw, null, 2);
  toggle.addEventListener("click", () => {
    rawBox.hidden = !rawBox.hidden;
    toggle.textContent = rawBox.hidden ? "Show raw RDAP response" : "Hide raw RDAP response";
  });
  body.append(toggle, rawBox);
  return card;
}

els.form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const domain = els.domain.value.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  if (!domain) return;
  const domainRe = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63})+$/i;
  els.error.hidden = true;
  els.results.innerHTML = "";
  if (!domainRe.test(domain)) {
    els.error.textContent = "Enter a valid domain, e.g. example.com";
    els.error.hidden = false;
    return;
  }

  els.submit.disabled = true;
  els.submit.textContent = "Looking up…";
  try {
    const [mx, spf] = await Promise.all([lookupMx(domain), lookupSpf(domain)]);
    const [dmarc, dkim, rdapSettled] = await Promise.all([
      lookupDmarc(domain),
      lookupDkim(domain, els.selector.value, mx, spf),
      lookupRdap(domain).then((v) => ({ ok: true, value: v })).catch((err) => ({ ok: false, error: err })),
    ]);

    const dmarcPolicy = dmarcPolicyOf(dmarc);
    els.results.appendChild(renderMx(mx));
    els.results.appendChild(await renderSpf(spf, mx, dmarcPolicy, domain));
    els.results.appendChild(renderDmarc(dmarc, dmarcPolicy));
    els.results.appendChild(renderDkim(dkim));
    els.results.appendChild(rdapSettled.ok ? renderWhois(rdapSettled.value, null) : renderWhois(null, rdapSettled.error));
  } catch (err) {
    els.error.textContent = "Could not complete the lookup — the DNS resolver may be unreachable. Try again in a moment.";
    els.error.hidden = false;
  } finally {
    els.submit.disabled = false;
    els.submit.textContent = "Look up";
  }
});
