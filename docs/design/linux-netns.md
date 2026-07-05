# Design: kernel-level network isolation for the Linux sandbox (netns + proxy bridge)

> Status: **proposed** (design only — no code yet). Tracks
> [issue #114](https://github.com/navikt/cplt/issues/114).
> Scope: Linux only. macOS Seatbelt already enforces the equivalent (see below).
>
> Read [SECURITY.md](../../SECURITY.md) (network section) and
> [docs/proxy.md](../proxy.md) (proxy-forced mode) first — this document extends
> both. It is a PRD: it fixes the *what* and the *why*, sketches the *how*, and
> records the decisions. Implementation lands in follow-up PRs.

---

## 1. Problem & goal

On Linux, cplt's outbound-network story is two independent layers:

1. **Landlock TCP-connect rules** (`sandbox_landlock.rs`, ABI v4+ / kernel 6.7+).
   These are **port-based**: a rule is `NetPort::new(port, AccessNet::ConnectTcp)`
   — it allows connecting to *that port on any host*. There is no way to say
   "port 443 only to `127.0.0.1`". See the `NetRule` type
   (`sandbox_landlock.rs`) and `generate_policy()`'s network block.
2. **The cplt CONNECT proxy** (`proxy.rs`), which does the real work: hostname
   allow/block lists, resolved-IP SSRF guard, port policy, upstream chaining.
   The agent is pointed at it via `HTTP_PROXY` / `HTTPS_PROXY` set in
   `sandbox_exec.rs` (`http://127.0.0.1:<proxy_port>`).

The proxy runs on **host loopback** (`proxy::start()` binds `127.0.0.1:<port>`).
For the agent to reach it, Bubblewrap deliberately **does not** create a network
namespace: `build_bwrap_args()` in `sandbox_bubblewrap.rs` emits `--unshare-pid`,
`--unshare-ipc`, `--unshare-uts`, `--unshare-cgroup`, `--unshare-user` but
**never `--unshare-net`** (asserted by the `args_isolate_expected_namespaces`
test). The agent therefore shares the host network namespace — it can see host
loopback, the LAN, and the internet, constrained only by Landlock's port rules.

**Goal.** Provide, on Linux, a **kernel-enforced default-deny egress** where the
*only* path off the machine is the cplt proxy — matching what macOS Seatbelt
already gives via `localhost:<proxy_port>` pinning. Concretely:

- **G1 — Forced proxy egress.** A sandboxed process attempting a direct
  `connect()` to any external host (on any port) is blocked by the kernel. The
  proxy is the sole reachable egress socket.
- **G2 — Localhost isolation.** Host loopback services (a dev database on
  `127.0.0.1:5432`, the host's own SSH, a metadata shim, another cplt session's
  proxy) are **unreachable** from inside the sandbox, except the one proxy
  endpoint cplt deliberately exposes.
- **G3 — Preserve auto-detect / graceful fallback.** No hard new dependency, no
  privilege escalation. Where the mechanism cannot be built, cplt degrades to
  today's Landlock port-based behavior with an honest `ui::warn` — it **never
  silently opens** the network.

**Non-goals** (unchanged from #114): inbound service exposure into the sandbox;
moving domain filtering into the kernel (that stays in `proxy.rs` — the namespace
only *forces traffic through* the proxy); IPv6-only host support (see Open
Questions); parity for kernels without unprivileged user namespaces.

---

## 2. Why the current proxy-forced Linux story is incomplete

`--proxy-forced` (issue #53) is the existing attempt to make the proxy mandatory.
In `generate_policy()` it drops the default `*:443` seed and emits **only** the
proxy port (plus configured localhost ports):

```rust
let mut net_rules = if config.proxy_forced {
    Vec::new()                    // no *:443
} else {
    vec![NetRule { port: 443 }]
};
// ... proxy_port pushed in below
```

`check_proxy_forced_enforceable()` fails closed if the kernel can't enforce
`ConnectTcp` (ABI < v4), so proxy-forced never silently launches with open
networking. That closes the *direct `:443`* bypass — `env -u HTTPS_PROXY curl
https://evil.com` is kernel-denied because 443 is no longer an allowed port.

**The residual.** Because Landlock is port-based, allowing the proxy port allows
that port *on every host*. The code says so directly
(`generate_policy()`, network block):

> Residual (Linux only): because Landlock is port-based, allowing the proxy port
> also allows `evil.com:<proxy_port>` if something listens there. That narrow
> channel is closed by #114 (netns + localhost pinning). On macOS the SBPL
> profile pins to `localhost:<proxy_port>`, so there is no residual.

So on Linux today, with proxy-forced on, a sandboxed process can still open a
**direct** TCP connection to `evil.com:<proxy_port>` — bypassing the proxy's
domain filtering entirely — provided the attacker's host answers on that exact
(ephemeral, but discoverable from the process's own `HTTPS_PROXY`) port. It is
narrow, but it is a real hole in the "only the proxy gets out" promise, and it
grows with every extra `--allow-port` (each opens a direct, unfiltered kernel
egress channel on that port).

**The macOS contrast.** Seatbelt SBPL can express an *address+port* predicate:
the profile pins egress to `localhost:<proxy_port>`. A connect to
`evil.com:<proxy_port>` does not match `localhost`, so it is kernel-denied. No
residual. Landlock has no equivalent predicate — this is a fundamental LSM
capability gap, not a policy oversight.

**How a netns closes it.** Move the sandbox into its **own** network namespace
that has *no route to anything* except a single loopback endpoint wired to the
cplt proxy. Then:

- A direct `connect()` to `evil.com:<any_port>` has **no route** — the packet
  cannot leave the namespace. This is enforced by the kernel's routing/namespace
  machinery, not by a port allowlist, so it is address-complete (G1).
- The only reachable socket is the proxy bridge on the namespace's loopback.
  Host loopback services live in the *host's* netns and are simply not present
  in the sandbox's netns (G2).

The port-based Landlock rule becomes redundant belt-and-suspenders inside the
netns, and the `evil.com:<proxy_port>` residual disappears because there is no
route to `evil.com` at all.

---

## 3. Design options

All options must stay **unprivileged / rootless** (cplt runs as the invoking
user; the user namespace maps to the invoking UID with no real capabilities —
see the bwrap module docs). Options requiring `CAP_NET_ADMIN` on the host are
disqualified for the default path.

### Option A — `--unshare-net` + unix-socket proxy bridge *(recommended)*

**How it works.** Add `--unshare-net` to `build_bwrap_args()`. Inside the fresh
netns, loopback (`lo`) is present but starts DOWN; it is brought UP within the
namespace (see Open Question O1 on doing this unprivileged). The proxy is exposed
*inside* the namespace as a loopback endpoint by a tiny **forwarder** that cplt
owns:

- The host cplt proxy additionally listens on a **unix domain socket** at a path
  cplt controls (e.g. under the scratch dir, which already gets a writable
  Landlock rule and a writable bwrap bind). A unix socket crosses the netns
  boundary because it is a *filesystem* object, not a network object — the
  socket file is visible inside the mount namespace regardless of `--unshare-net`.
- Inside the netns, a small forwarder accepts TCP on `127.0.0.1:<port>` and
  splices each connection to the host proxy's unix socket. This is the natural
  home for the existing **re-entry helper**: it already runs in-namespace,
  pre-`main()`, single-threaded, and already `execve`s the agent
  (`bubblewrap::run_inner`). The forwarder would be spawned by the helper (a
  `fork()` before the final `execve`) so `HTTP_PROXY=http://127.0.0.1:<port>`
  continues to resolve.

**Traffic forcing.** The agent's `HTTPS_PROXY` still points at
`127.0.0.1:<port>` (unchanged wiring in `sandbox_exec.rs`). That TCP connect now
lands on the in-namespace forwarder → host unix socket → real proxy → filtered
egress. A *direct* connect to any other address has no route (netns has only
`lo`), so it fails at the kernel. G1 and G2 are both satisfied by construction.

**Requires.** Only `bwrap` (already a soft dependency) and the ability to create
a netns via the user namespace bwrap already creates — **no new binary, no
`CAP_NET_ADMIN`, no veth**. The forwarder is cplt's own code. The unix socket
uses the existing scratch-dir plumbing.

**Failure/fallback.** If `--unshare-net` fails at `test_functionality()` (the
existing probe runs the real args against `/bin/true`), or the forwarder can't
bind/relay, auto-detect degrades: fall back to the **non-netns bwrap path** (or
to Landlock-only), keeping today's port-based behavior, with a
`ui::warn`. Under explicit `--use-bubblewrap` a demanded-but-unavailable netns is
a hard error, mirroring the current bwrap strictness (`resolve()` /
`BubblewrapWrapper::strict`).

**Cost / risk.** The re-entry helper gains a moving part (a surviving forwarder
process) — the fork/exec ordering is delicate (see §4). Bringing `lo` UP inside
an unprivileged netns needs care (Open Question O1).

### Option B — `pasta` / `slirp4netns` user-mode networking

**How it works.** Create the netns (`--unshare-net`), then attach a user-mode
network stack: `pasta` (passt) or `slirp4netns` runs as an unprivileged host
process and provides a virtual interface inside the namespace, translating the
sandbox's packets to host sockets. Both are the mechanism rootless Podman uses.
`pasta` supports outbound port restrictions and can be told to only forward
specific ports.

**Traffic forcing.** A user-mode stack by default gives the sandbox a *working
route to the internet* — the opposite of what we want. To force proxy-only
egress we would still have to firewall inside the netns (nftables in the
namespace, which the user *can* configure since it's their own netns) or bind
pasta to forward *only* a single port mapped to the host proxy. That is strictly
more moving parts than Option A to reach the same "only the proxy" endpoint,
while also shipping a full TCP/UDP NAT we don't need.

**Requires.** A new runtime dependency (`pasta` or `slirp4netns` in PATH).
Unprivileged — good — but it is an external binary with its own version/behaviour
surface, and it is not always installed.

**Failure/fallback.** Same graceful-degradation contract as Option A (warn +
fall back). But the dependency-detection matrix grows: bwrap present *and* pasta
present *and* compatible.

**Why not chosen.** Heavier than the requirement. #114 needs *one loopback
endpoint to the proxy and nothing else*, not a general-purpose NAT. A full stack
is more attack surface and more that can silently route around the proxy if
misconfigured. Keep it as a **fallback bridge transport** if Option A's
`lo`-UP-unprivileged problem proves intractable on some kernels.

### Option C — veth pair + nftables

**How it works.** Create a veth pair, move one end into the sandbox netns,
address both ends, and use nftables to DNAT/allow only the proxy and drop
everything else.

**Requires.** `CAP_NET_ADMIN` on the host to create/move the veth and program
nftables in the *host* netns. That is a **privilege cplt does not have and must
not require** — it breaks the rootless model that the user namespace exists to
preserve. Disqualified for the default path. (A privileged/opt-in deployment
could use it, but that is out of scope for #114's rootless goal.)

### Recommendation

**Option A (`--unshare-net` + unix-socket bridge via the re-entry helper).** It
is the only option that (a) adds no new dependency and no privilege, (b) reuses
machinery cplt already owns and audits (the re-entry helper, the scratch-dir
bind, the confirm-pipe fallback), and (c) yields exactly the minimal endpoint
#114 asks for — one proxy socket, nothing else routable. Option B is the
designated fallback transport if bringing `lo` UP unprivileged is not portable;
Option C is rejected on the privilege requirement.

---

## 4. Interaction with existing pieces

**Composition with the bwrap re-entry helper (fd/pipe/exec ordering).** Today
`exec_bwrap()` (`sandbox_exec.rs`) sets up two pipes — the **policy pipe**
(`ENV_INNER_POLICY`, read end inherited by the helper) and the **confirm pipe**
(`ENV_CONFIRM_FD`, write end inherited) — then spawns `bwrap -- <cplt helper>`.
The helper (`bubblewrap::run_inner`) reads the policy, applies Landlock+seccomp
via `apply_landlock_and_seccomp_now()`, writes the confirm byte, scrubs its env,
and `execve`s the agent. The netns bridge slots in **between** "apply
Landlock+seccomp" and "execve the agent":

1. Parent (`exec_bwrap`) passes the **unix socket path** to the helper (a new
   field in the serialized `InnerPolicy`, alongside `net_ports` / `agent_argv`).
2. Helper, in-namespace, brings `lo` UP (or defers to the pasta fallback),
   `fork()`s the forwarder that binds the in-namespace TCP listener
   `127.0.0.1:<port>` and relays each accepted connection to the host unix
   socket.
3. **Ordering constraint:** the confirm byte must be written only *after* the
   forwarder is listening, so the parent's "sandbox is up" signal also means
   "egress path is up". If the forwarder fails to bind, the helper must **not**
   write the confirm byte and must `_exit(126)` — the parent then falls back
   exactly as it does today on a missing confirmation (auto-detect) or hard-fails
   (explicit). This reuses the existing fallback channel with zero new plumbing.
4. **Landlock ordering:** `apply_landlock_and_seccomp_now()` restricts
   *filesystem + TCP connect*, and seccomp does not block `socket`/`bind`/
   `accept`, so an in-netns loopback listener is fine. The forwarder's
   `connect()` to the host proxy travels over a **filesystem** path (the unix
   socket file), which Landlock governs via a read+write rule on that path — the
   scratch dir already carries write, so placing the socket there is the
   least-new-policy choice (analogous to `config.extra_socket` handling in
   `generate_policy()`). If a Landlock `ConnectTcp` restriction would interfere
   with the forwarder's own loopback accept/relay, the forwarder must be forked
   *before* `restrict_self()`; nailing down this ordering is the main
   implementation subtlety and is covered by a test (§6).

**`HTTPS_PROXY` env.** Unchanged. `sandbox_exec.rs` still injects
`HTTP_PROXY`/`HTTPS_PROXY = http://127.0.0.1:<proxy_port>` and
`NO_PROXY=localhost,127.0.0.1,::1`. Inside the netns, `127.0.0.1:<proxy_port>`
now resolves to the in-namespace forwarder instead of the host proxy directly —
transparent to the agent. The forwarder binds the *same* `<proxy_port>` number
inside the isolated netns (no host collision — it is a separate netns), so the
env value needs no change. `NO_PROXY` still exempts loopback so the agent talks
to the forwarder without recursing.

**Domain filtering.** Entirely unchanged and still host-side: the forwarder is a
dumb byte-splice (like `proxy::relay`), it does **no** filtering. Every CONNECT
still terminates at the real `handle_connect()` on the host, which runs the
allowlist/blocklist/SSRF/port checks. The netns only guarantees the bytes can
reach *nothing but* that proxy.

**DNS.** This is the sharpest interaction. Inside `--unshare-net` with only `lo`,
the agent has **no route to a DNS resolver** (no UDP/53 to the host or LAN).
Two coherent models:

- **Proxy-side resolution (recommended).** The agent uses HTTPS via CONNECT, so
  it sends `CONNECT host:443` to the proxy and never resolves the name itself for
  proxied traffic — resolution happens host-side in `resolve_locally()`
  (`proxy.rs`), which is exactly where the resolved-IP SSRF guard already lives.
  This is the cleanest fit and *improves* security (the SSRF guard becomes
  unavoidable). Non-proxied name lookups (e.g. a tool calling `getaddrinfo`
  directly for a non-HTTP protocol) will fail — which is the *intended* posture
  under forced-proxy egress (raw-TCP tools losing direct network is by design;
  see docs/proxy.md "Raw-TCP tradeoff").
- **Stub resolver in the netns.** If some agent needs local resolution, run a
  tiny DNS stub on the netns loopback that forwards over the same unix bridge to
  a host-side resolver. More moving parts; deferred to a later phase unless a
  concrete agent needs it. `/etc/resolv.conf` is already read-allowed by
  `LINUX_SYSTEM_READ_PATHS`, so a `127.0.0.1` stub entry could be bind-mounted in
  if we go this route.

MVP takes proxy-side resolution and documents the raw-`getaddrinfo` limitation.

**`gh_proxy`.** The `gh` guard (`gh_proxy.rs`) is a **command-level** wrapper (a
shell shim ahead of `gh` in PATH that calls back into cplt for allow/deny) — it
is not a network path, so netns does not change its behavior. `gh` itself makes
HTTPS calls to `api.github.com`, which flow through `HTTPS_PROXY` → the bridge →
the proxy like any other agent traffic. The only requirement is that the same
`HTTPS_PROXY` env reaches the `gh` subprocess (it does — env is inherited), so
`gh` keeps working under netns with no special-casing.

---

## 5. Failure modes & fallback

The invariant, matching `check_proxy_forced_enforceable()`'s existing
fail-closed stance: **never silently open the network**. Every failure either
degrades to a *more* restrictive posture or refuses to launch.

| Condition | Auto-detect (default) | Explicit `--use-bubblewrap` (strict) |
|---|---|---|
| `bwrap` missing | Landlock+seccomp only, `ui::warn` (today's behavior) | Hard error (today's behavior) |
| `--unshare-net` unsupported (no unpriv userns net) | Fall back to **non-netns bwrap** (port-based Landlock), `ui::warn` | Hard error |
| `lo` cannot be brought UP unprivileged | Try pasta fallback (if present) → else non-netns bwrap, `ui::warn` | Hard error |
| Forwarder fails to bind/relay | Helper withholds confirm byte → parent falls back per existing confirm-pipe logic | Hard error |
| Bridge up but proxy disabled/absent | Refuse: a netns with no egress endpoint is a bricked run — error clearly (mirror the proxy-forced-without-proxy rejection in `main.rs`) | Hard error |

Crucially, a netns fallback lands on **port-based Landlock**, which is *less*
complete (the `evil.com:<proxy_port>` residual returns) but still deny-by-default
on ports — it is never *more* open than today. The warning must say so honestly:
"kernel network isolation unavailable; using port-based egress filtering (a
narrow same-port residual remains) — see docs/proxy.md."

The netns path should be gated behind the same auto-detect/opt-in model as bwrap
(`sandbox.use_bubblewrap`), possibly with a dedicated sub-toggle
(`sandbox.net_isolation = auto|on|off`) so a user can keep bwrap's process/mount
isolation while disabling only the network namespace if it breaks a workflow.

---

## 6. Testing strategy

Reuse the **observed-enforcement** pattern already in `tests/integration_linux.rs`:
tests gate on capability via `require_landlock!(...)` and, in CI, escalate skips
to panics when `CPLT_TEST_REQUIRE_SANDBOX=1` (`require_sandbox_enforced()`), so a
CI runner that *should* enforce cannot quietly skip. Network tests follow the
existing `/dev/tcp` differential — bind a real listener so the test distinguishes
"blocked by the kernel" (EPERM / no route) from "nothing listening"
(ECONNREFUSED), exactly like `outbound_tcp_blocked_by_landlock` and
`allow_localhost_port_permits_tcp_connect` do today.

A new `net_isolation` block (gated on `bwrap` + `--unshare-net` availability,
require-mode in CI) should assert, all from inside the sandbox:

1. **Direct external egress is kernel-blocked.** Bind a listener on the *host*
   netns; from inside the sandbox `echo > /dev/tcp/<host-ip>/<port>` must fail
   (no route), not merely be refused. Differential against a control run without
   netns proves the netns is what blocks it. This is the direct analogue of the
   existing `:443` differential and is the core G1 assertion.
2. **The proxy path reaches an allowlisted origin.** With the bridge up and an
   allowlist permitting a test origin, a proxied `CONNECT` (via `HTTPS_PROXY`)
   to that origin succeeds — proving the bridge carries sanctioned traffic and
   the forwarder→unix-socket→proxy chain works end to end.
3. **A host-loopback service is unreachable (G2).** Start a listener on the host
   at `127.0.0.1:<svc>`; from inside the netns, a connect to `127.0.0.1:<svc>`
   must fail — the host's loopback is not the sandbox's loopback. Pair it with a
   positive control: a connect to the *proxy* endpoint on loopback succeeds. This
   is the test that today's port-based path **cannot** pass (that is the whole
   point of #114) and is the regression guard for the residual.
4. **Fallback honesty.** On a host/config where `--unshare-net` is unavailable,
   assert cplt emits the degradation warning and still applies port-based
   Landlock (no open network) — i.e. the fail-closed contract from §5.

Unit tests (`sandbox_bubblewrap.rs`, cross-platform) cover the pure-logic half:
`build_bwrap_args()` now includes `--unshare-net` when net isolation is on and
omits it when off; `InnerPolicy` round-trips the socket path; the argument
ordering (netns flag present, socket bind emitted after the tmpfs like the other
writable binds) holds. These mirror the existing `args_*` tests and run on macOS.

---

## 7. Security posture (stated honestly)

**What netns + bridge provides:**

- ✅ **Kernel-enforced default-deny egress (G1).** Direct connects to external
  hosts have no route; the proxy is the sole egress. This closes the
  `evil.com:<proxy_port>` port-based residual that Landlock cannot
  (`generate_policy()` network comment) and brings Linux to macOS parity on the
  "force all egress through proxy" row.
- ✅ **Localhost isolation (G2).** Host loopback services are outside the
  sandbox's netns and unreachable — the protection Landlock's port rules
  structurally cannot give (port 443 to `127.0.0.1` is indistinguishable from
  port 443 to a remote host).

**What it does NOT provide:**

- ❌ **It is not a confidentiality or filesystem control.** Landlock remains the
  filesystem boundary; the mount namespace still only makes the host root
  read-only. (Unchanged from the bwrap posture in SECURITY.md.)
- ❌ **It does not filter content.** All domain/allowlist/SSRF decisions still
  live in `proxy.rs`. The netns forces traffic *to* the proxy; it does not judge
  it. A permissive proxy config is still permissive.
- ❌ **Raw / non-proxy-aware tools lose direct network — by design.** A tool that
  ignores `HTTPS_PROXY` or needs a non-CONNECT protocol cannot reach the network
  (no route). This is the *intended* forced-proxy posture, identical in spirit to
  today's proxy-forced "raw-TCP tradeoff" (docs/proxy.md), now enforced by
  routing rather than a port allowlist.
- ❌ **DNS via raw `getaddrinfo` for non-proxied traffic will fail** under the
  MVP's proxy-side-resolution model (§4). Documented, not a silent breakage.
- ❌ **Not available where unprivileged user-namespace networking is disabled.**
  Falls back to port-based Landlock with an honest warning (§5).

**SECURITY.md updates when implemented** (do not make these now — the capability
does not exist yet; SECURITY.md must stay honest):

- The comparison table: `Network: localhost isolation` and `Network: force all
  egress through proxy` gain a **✅ kernel** entry for the `Linux (+ Bubblewrap)`
  column *when netns is active*, with a footnote that the non-netns fallback
  keeps the ⚠️ port-based residual.
- The "What bwrap does NOT provide → No network isolation" bullet is rewritten:
  network isolation *is* now provided when the netns bridge is active; the
  residual note and the #114 link are replaced with the fallback caveat.
- The `generate_policy()` residual comment and docs/proxy.md's Linux
  proxy-forced paragraph drop "until #114" and instead point at this netns doc,
  distinguishing "netns active (no residual)" from "fallback (port-based
  residual)".

---

## 8. Open questions, risks, phasing

**Open questions.**

- **O1 — Bringing `lo` UP unprivileged.** In a netns created via an unprivileged
  user namespace, `lo` exists but starts DOWN; setting it UP needs
  `CAP_NET_ADMIN` *within that user namespace* (which the userns grants for its
  *own* net namespace). Confirm bwrap can do this (`--unshare-net` in Flatpak
  brings up a loopback-only stack) or whether cplt must issue the
  `RTM_NEWLINK` / `SIOCSIFFLAGS` itself in the helper. If not portable, fall back
  to Option B (pasta) as the bridge transport. **This is the primary technical
  risk and should be spiked before committing to Option A.**
- **O2 — Unix socket vs. inherited socketpair.** A filesystem unix socket in the
  scratch dir is simplest for Landlock reasoning, but an inherited `socketpair()`
  fd (passed like the policy pipe) would avoid *any* shared filesystem endpoint
  and any risk of another sandbox reaching the socket file. Evaluate: the
  forwarder could relay onto an inherited fd-pair to the host proxy thread
  instead of dialing a path. Leaning toward socketpair for defense in depth if
  multiplexing many agent connections over one pair is tractable.
- **O3 — IPv6.** `NO_PROXY` includes `::1`; the in-namespace listener and the
  SSRF guard must be consistent for v6 loopback. MVP can be v4-loopback-only for
  the bridge and document it.
- **O4 — Concurrent cplt sessions.** With the host-shared netns today, two
  sessions' proxies coexist on distinct ports; with a per-session netns each is
  fully isolated (a plus for G2), but the socket-path / fd naming must be
  per-session.
- **O5 — Toggle surface.** One flag (reuse `use_bubblewrap`) or a dedicated
  `net_isolation` / `--net-isolation`? A dedicated toggle lets users keep
  process/mount isolation while opting out of network isolation if a workflow
  breaks — recommended, defaulting to `auto`.

**Risks.**

- Re-entry-helper complexity: a surviving forwarder changes the helper from
  "apply policy then `execve`" to "apply policy, `fork()` a background relay, then
  `execve`". `execve` replaces the process image — so the forwarder **must** be a
  separate process (fork before `execve`), reaped / `--die-with-parent`-scoped so
  it never outlives the agent. Get this wrong and you leak a relay or lose the
  egress path. Highest-risk code; needs the §6 tests plus a leak/teardown test.
- Silent-open regression: any bug where netns setup fails *after* the port-based
  Landlock rules were relaxed (because we assumed netns would carry egress) could
  open the network. Mitigation: keep the port-based Landlock rules applied
  **as-is** even under netns (belt-and-suspenders — they cost nothing inside the
  netns and guarantee the fallback direction is always *more* closed).
- Kernel/distro variance in unprivileged userns networking (Debian's
  `kernel.unprivileged_userns_clone`, RHEL defaults) — same class of variance
  bwrap already handles via `test_functionality()`; extend that probe to exercise
  `--unshare-net` so detection can't drift from the real invocation.

**Phasing.**

- **Phase 0 — Spike (O1).** Prove `--unshare-net` + loopback-UP + a hand-rolled
  forwarder reaching the host proxy works unprivileged on the CI kernel and 2–3
  common distros. Decide Option A vs. Option B transport.
- **Phase 1 — MVP.** Option A with proxy-side DNS, socketpair-or-scratch bridge,
  auto-detect + graceful fallback, the four §6 integration tests + unit tests.
  Netns is opt-in (`net_isolation = on` / a flag) so it ships without regressing
  the default path.
- **Phase 2 — Default-on under bwrap + docs.** Once stable, enable netns whenever
  bwrap + `--unshare-net` are available; update SECURITY.md and docs/proxy.md per
  §7; flip the comparison-table rows.
- **Phase 3 (optional).** In-namespace DNS stub (O2 model B) for agents that need
  local resolution; pasta transport as a supported fallback; IPv6 loopback (O3).

---

## Appendix: grounding references

- `src/sandbox_bubblewrap.rs` — `build_bwrap_args()` (namespace flags, **no
  `--unshare-net`**), `resolve()` / `BubblewrapWrapper` (auto-detect + strict),
  `run_inner()` / `bwrap_inner_entry()` / `serialize_policy()` / `InnerPolicy`
  (the re-entry helper and its policy transfer), `ENV_INNER_POLICY` /
  `ENV_CONFIRM_FD`.
- `src/sandbox_exec.rs` — `exec_bwrap()` (policy pipe + confirm pipe + spawn
  ordering), proxy env injection (`HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`).
- `src/sandbox_landlock.rs` — `NetRule`, `generate_policy()` network block (the
  documented port-based **residual**), `apply_landlock_and_seccomp_now()` (the
  in-namespace apply), `check_proxy_forced_enforceable()` (fail-closed).
- `src/proxy.rs` — `start()` (binds `127.0.0.1:<port>`), `handle_connect()` /
  `resolve_locally()` (host-side resolution + SSRF guard), `relay()` (the byte
  splice the forwarder mirrors).
- `src/gh_proxy.rs` — command-level `gh` guard (unaffected by netns).
- `tests/integration_linux.rs` — `require_landlock!` / `require_sandbox_enforced`
  (CI require-mode), the `/dev/tcp` connect differential
  (`outbound_tcp_blocked_by_landlock`, `allow_localhost_port_permits_tcp_connect`).
- `SECURITY.md` — network comparison table + "Linux namespace isolation
  (Bubblewrap)" section; `docs/proxy.md` — proxy-forced mode and the Linux
  residual note.
