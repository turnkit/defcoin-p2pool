# Defcoin P2Pool Technical Guide

This guide is the public technical reference for the Defcoin P2Pool Python 3
fork. It consolidates the previous operational, provenance, Python 3 resource,
and Defcoin-specific change notes into one document.

## Overview

P2Pool is decentralized mining-pool software. Instead of trusting one central
pool database to track shares, P2Pool miners cooperate on a separate sharechain.
When the pool finds a Defcoin block, the coinbase transaction pays miners based
on recent valid P2Pool shares.

This fork keeps that P2Pool model and updates the Defcoin deployment path:

- Python 3 runtime and dependency auditing.
- Defcoin Core Nu compatibility.
- Dual parent-chain message magic during migration.
- Defcoin User-Agent filtering for legacy-magic parent-chain address gossip.
- Defcoin-specific P2Pool parent-chain identity:
  `/DefcoinP2Pool:<version>/`.
- RPC-based local best-header polling and block submission to reduce local
  parent-chain peer churn.
- Share version `36` to remove the old lost-key P2Pool donation dust output
  from new share templates.
- Bounded deterministic caches for repeated conversion work.
- A backend/frontend split so operators can build their own web frontends.

The recommended Defcoin full-node wallet is
[Defcoin Core Nu](https://github.com/defcoincore/Defcoin-Core-Nu).

The public repository name is `defcoin-p2pool`. The older
`p2pool-defcoin` name may appear in upstream lineage notes because historical
Defcoin P2Pool repositories used that naming pattern.

## Repository layout

The repository is split by responsibility:

- `backend/` contains the Python P2Pool backend, Defcoin network rules,
  Stratum work generation, P2P protocol code, tests, requirements, and helper
  scripts.
- `frontend/` contains static web UI assets. The backend mines and serves
  miners without depending on a specific frontend design.
- `docs/` contains this guide and public images used by the README.
- `run_p2pool.py` is a compatibility launcher that preserves the historical
  root command while loading `backend/run_p2pool.py`.

The backend serves `frontend/web-static` by default. Operators can supply a
custom frontend with `--web-static /path/to/web-static`.

## Lineage and provenance

The live Defcoin pool code was originally derived from the Python 2 P2Pool era.
Its immediate upstream was the old `charlesrocket/p2pool-defcoin` repository,
which GitHub redirects to `hellbyte/p2pool-defcoin`. The code lineage also
matches the `jtoomim/p2pool` generation of P2Pool, based on protocol/share
version markers and module layout.

A 2020 [g4tekeep3r Defcoin P2Pool writeup][g4tekeep3r-dfc-p2pool] also
credits charlesrocket for spearheading the Defcoin P2Pool port and links the
`charlesrocket/p2pool-defcoin` repository. That source is useful historical
context for the public Defcoin P2Pool lineage and for the old port `9355`
P2Pool nodes it listed.

Important lineage markers:

- P2Pool protocol version: `3501`.
- Defcoin share format before this fork: version `35`.
- SegWit share support: version `34`.
- New donation-dust-fixed Defcoin share format: version `36`.

The goal of this repository is not to ask an archived upstream to accept a pull
request. It is to publish the current Defcoin P2Pool implementation in a clean,
auditable form so other Defcoin pool operators can compare, run, and adapt it.

[g4tekeep3r-dfc-p2pool]: https://www.g4tekeep3r.com/2020/08/16/dfc-p2pool/

## Defcoin-specific network behavior

Defcoin is configured in two places:

- `backend/p2pool/bitcoin/networks/defcoin.py` describes the Defcoin parent
  chain: scrypt proof of work, address versions, block period, RPC/P2P ports,
  genesis markers, and parent-chain P2P message magic.
- `backend/p2pool/networks/defcoin.py` describes the Defcoin P2Pool sharechain:
  share period, P2Pool ports, bootstrap peers, worker ports, and P2Pool network
  identifiers.

Common Defcoin operator ports:

| Purpose | Typical port |
| --- | ---: |
| Defcoin Core P2P | `1337` |
| Defcoin Core RPC | `1335` |
| Defcoin Core Nu backend P2P compatibility port on dc903 | `10332` |
| P2Pool peer network | `13370` |
| Stratum worker port used by the public ASIC pool | `13372` |

Operators should open only the ports required for their deployment.

Do not run a public P2Pool peer listener on `1337` on a server that is also
running a Defcoin Core node. Port `1337` is Defcoin Core's normal P2P node
port, so binding P2Pool there prevents ordinary wallets and seeders from
reaching the server's Core node on the expected default port. Use a separate
P2Pool peer port such as `13370`, advertise it explicitly, and point P2Pool at
the local Core node with `--bitcoind-p2p-port 1337`.

## Dual parent-chain magic

Defcoin inherited a legacy Litecoin-family parent-chain message header:
`fbc0b6db`. Modern Defcoin wallets can use the Defcoin-specific header
`defc014e`.

This fork supports a transition model:

- Outbound parent-chain P2P prefers `defc014e` when
  `DEFCOIN_P2POOL_USE_NEW_MAGIC=1` is set.
- Compatibility mode can still accept legacy `fbc0b6db`.
- The first valid header from a peer selects that peer's reply magic.
- Each peer is answered with the same magic it used.

This is not a Defcoin blockchain hard fork. The magic bytes are a P2P packet
boundary check, not a consensus rule. The purpose is to let modern Defcoin
wallets reduce unrelated Litecoin-family traffic while preserving a migration
path for older Defcoin wallets.

Legacy support should be treated as temporary migration code. When supported
wallets, pools, and seeds have moved to Defcoin-specific `defc014e` traffic,
operators can disable legacy `fbc0b6db` compatibility and remove the
pollution-filtering scaffolding that exists only to make the transition safe.

## User-Agent and address-gossip filtering

Legacy-magic parent-chain peers can include unrelated Litecoin-family nodes. To
reduce address-table pollution, legacy-magic peers must identify with a
Defcoin-prefixed User-Agent before their gossiped addresses are accepted.

The documented valid prefix is:

```text
/Defcoin
```

`/DefcoinCore:1.0.0/` is valid because it starts with `/Defcoin`.

The P2Pool parent-chain connector identifies itself to Defcoin Core as:

```text
/DefcoinP2Pool:<version>/
```

This User-Agent is only for the Defcoin parent-chain P2P connection. The P2Pool
share-network version string remains separate so share-protocol compatibility is
not changed by the Defcoin User-Agent policy.

The filtering goal is to drop non-Defcoin legacy peers before their `addr`
messages can seed address tables or be rebroadcast. This avoids poisoning the
small Defcoin network with unrelated peer addresses while still allowing valid
Defcoin peers on nonstandard ports when they identify as Defcoin.

The live Defcoin Core node may also use a short-lived bad-User-Agent prefilter
for repeated public inbound non-`/Defcoin` legacy-magic attempts. That cache is
not part of P2Pool share consensus and should not be treated as peer identity.
It exists only to reduce repeated Litecoin-family connection noise while legacy
magic remains enabled.

For local pool operation, best-block-header polling prefers Defcoin Core RPC
`getblockheader` rather than a local P2P `getheaders` request. This keeps the
P2Pool-to-Defcoin Core loopback connection stable and avoids unnecessary local
peer reconnect churn. If an older or simulated node does not provide
`getblockheader`, the code falls back to the historical local P2P header
request.

Block submission to the local Defcoin Core node also uses RPC. The older P2Pool
path sent a block over the local parent-chain P2P socket and submitted the same
block over RPC. Modern Defcoin Core accepts and relays the RPC-submitted block,
so the redundant local P2P block send is disabled to prevent unnecessary local
peer disconnects after pool-found blocks.

These RPC changes do not centralize mining. They only change how the local
P2Pool process talks to the local Defcoin Core parent-chain node. P2Pool share
validation, Stratum mining, peer-to-peer share propagation, and coinbase payout
calculation remain P2Pool responsibilities.

## Share version 36 donation dust fix

Old Defcoin P2Pool shares inherited JP's P2Pool developer donation script. In
Defcoin it resolves to:

```text
DQ8AwqR2XJE9G5dSEfspJYH7Spre85dj6L
```

That historical destination is treated as a lost-key address for Defcoin
operations. Earlier P2Pool templates could send tiny rounding outputs there.

This fork adds `DonationDustFixedShare` as share version `36`:

- Old shares remain verifiable.
- New version `36` templates remove the spendable legacy donation output.
- A zero-value OP_RETURN padding output preserves the P2Pool coinbase hashlink
  shape needed for share validation.
- Spendable remainder that formerly landed in the legacy donation output is
  routed back into the normal payout construction.

Code locations:

- `backend/p2pool/data.py` defines `DonationDustFixedShare`,
  `DUSTFIX_PADDING_SCRIPT`, donation address handling, coinbase payout
  construction, and expected payout calculation.
- `backend/p2pool/work.py` stops recording author-donation weight once the
  active share type no longer pays the legacy donation output.
- `backend/p2pool/main.py` reports the disabled developer donation output at
  startup for operators.

This is not a Defcoin blockchain hard fork. It is a P2Pool share-template and
share-version change. Operators sharing the same Defcoin P2Pool network should
coordinate the update. On a tiny network, coordinated operators can set:

```bash
DEFCOIN_P2POOL_DUSTFIX_FLAG_DAY=1
```

so version `36` can follow version `35` immediately instead of waiting for a
normal P2Pool upgrade-vote window.

## Backend operation

Run this pool next to a fully synced Defcoin Core or Defcoin Core Nu node.

Install:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r backend/requirements.txt
python -m pip install -e backend/litecoin_scrypt
```

Public node example:

```bash
DEFCOIN_P2POOL_USE_NEW_MAGIC=1 \
python run_p2pool.py \
  --net defcoin \
  --allow-obsolete-bitcoind \
  -a YOUR_DEFCOIN_OPERATOR_ADDRESS \
  --p2pool-port 13370 \
  --external-ip YOUR_PUBLIC_IP:13370 \
  --worker-port 0.0.0.0:13372 \
  --bitcoind-address 127.0.0.1 \
  --bitcoind-p2p-port 1337 \
  --fee 1.5
```

`-a` sets the operator/default payout address. `--fee` sets the public worker
fee, applied by occasionally assigning worker shares to the operator address
instead of the miner-submitted username address. This fee is separate from the
legacy P2Pool developer donation script fixed by share version `36`.
`--p2pool-port` is the P2Pool peer/share-network listener, `--external-ip`
advertises that peer endpoint to other P2Pool nodes, and `--worker-port` is the
miner stratum/status endpoint. Keep these separate from the local Defcoin Core
P2P listener on `1337`.

UPnP is disabled by default in this Defcoin fork. Use `--enable-upnp` only for
consumer NAT deployments where automatic router port mapping is intentionally
wanted. Hosted pool servers should keep UPnP disabled and manage exposed ports
explicitly with the host firewall and reverse proxy.

Historical upstream crash reports are disabled by default. Operators who
explicitly want to send caught exception traces to the old upstream p2pool
error endpoint can opt in with `--enable-bugreport`. Public pool deployments
should normally leave this disabled so operational details stay on the host.

The fee can be checked from the API:

```bash
curl http://127.0.0.1:13372/fee
```

Mining endpoint example:

```text
stratum+tcp://YOUR_POOL_HOST:13372
```

Use the miner payout address as the Stratum username and any password.

## Frontend operation

The backend defaults to:

```text
frontend/web-static
```

Custom frontend example:

```bash
python run_p2pool.py --net defcoin --web-static /path/to/custom/web-static ...
```

The active frontend calls the backend HTTP endpoints for pool status, payouts,
hashrate, graph data, and peer information. Frontend authors can treat those
endpoints as the integration boundary and replace the static UI without changing
mining logic.

## Performance caches

This fork adds bounded `functools.lru_cache` usage only where the function is
deterministic and repeatedly called with the same values:

- `target_to_average_attempts`
- `average_attempts_to_target`
- `target_to_difficulty`
- `difficulty_to_target`
- `pubkey_hash_to_address`
- `address_to_script2`
- `address_to_pubkey_hash`
- `donation_script_to_address`

The caches are intentionally small and avoid peer state, sharechain mutation,
timestamps, random choices, and any value whose correctness depends on current
network state.

Local benchmark command:

```bash
python backend/dev/cache_benchmark.py
```

Current repeated-calculation benchmark results:

| Function | Uncached | Cached | Speedup |
| --- | ---: | ---: | ---: |
| `target_to_average_attempts` | 0.075015s | 0.017260s | 4.35x |
| `target_to_difficulty` | 0.078973s | 0.014797s | 5.34x |
| `difficulty_to_target` | 0.091125s | 0.016866s | 5.40x |
| `pubkey_hash_to_address` | 0.717119s | 0.011649s | 61.56x |
| `address_to_script2` | 0.084987s | 0.010155s | 8.37x |
| `donation_script_to_address` | 0.005286s | 0.000376s | 14.05x |

The dispatcher that guesses a script type is deliberately not cached. It is
pure in normal operation, but tests and review tools commonly monkey-patch the
specific parser helpers; caching only the lower-level deterministic conversions
keeps the optimization useful without hiding those correctness checks.

## Python 3 migration and resource comparison

The live dc903 service was sampled with the saved Python 2 service and this
Python 3 port on 2026-05-25.

| Runtime | Samples | Avg CPU | CPU range | Avg RSS | Avg cgroup memory |
| --- | ---: | ---: | ---: | ---: | ---: |
| Python 2 | 30 | 8.96% | 4.00% to 31.40% | 230,129 KB | 236,736 KB |
| Python 3 | 30 | 9.30% | 3.90% to 33.40% | 202,083 KB | 188,193 KB |

CPU was effectively similar within the quality of this measurement. Python 3
used less memory in this sample and is materially safer to maintain because
Python 2.7 is end-of-life.

The Python 3 port keeps the existing Defcoin P2Pool sharechain behavior while
allowing current dependency audits, linting, and security hardening.

The Python 3 runtime has been deployed on the dc903 pool. Later repository
commits may be CI or documentation-only changes; operators should still run the
test/audit gates and do a controlled service restart before treating a new
commit as production-deployed.

## Dependency and security policy

Runtime dependency files live under `backend/`:

- `backend/requirements.txt`
- `backend/conf/requirements-testing.txt`
- `backend/conf/requirements-development.txt`

Audit commands:

```bash
pip-audit -r backend/requirements.txt
pip-audit -r backend/conf/requirements-testing.txt
pip-audit -r backend/conf/requirements-development.txt
npx --yes retire --path frontend/web-static --outputformat text
bandit --severity-level medium -r backend/p2pool backend/run_p2pool.py run_p2pool.py -x backend/p2pool/test
```

The current quality environment reported no known vulnerabilities for runtime,
test, or development Python requirements, and no vulnerable bundled web assets
after the frontend dependency refresh. Bandit reported no medium or high
findings in runtime code. Package updates should remain conservative: P2Pool
consensus and share validation code should favor stable, tested dependencies
over unnecessary churn.

Vendored compatibility packages such as `SOAPpy` and `wstools` are legacy code
kept for compatibility with optional NAT traversal and historical P2Pool code.
UPnP is opt-in, XML parsing paths use `defusedxml`, and remote WSDL loading is
scheme-restricted. Linting is therefore focused on fatal Python errors, porting
risks, security-sensitive patterns, and changed code rather than blindly
restyling old vendored modules.

The repository includes a GitHub Actions CI workflow that runs the compile
check, fatal-error Ruff gate, selected Twisted tests, `pip-audit`, Bandit
medium/high checks, and a Retire.js audit for bundled static frontend assets.

## Tests and quality gates

Recommended local checks:

```bash
python backend/dev/python3_port_compile_check.py
ruff check --select E9,F63,F7,F82 backend/p2pool backend/run_p2pool.py run_p2pool.py
cd backend && python -m twisted.trial p2pool.test.test_data p2pool.test.test_node p2pool.test.bitcoin.test_data
cd ..
python backend/dev/cache_benchmark.py
git diff --check
```

Use live deployment testing carefully. The Defcoin P2Pool network can be very
small, so a pool operator should confirm that Stratum miners reconnect, shares
are accepted, the web API responds, and the parent-chain node stays synced
after changes.

## Operational hardening checklist

A public Defcoin P2Pool server should use explicit operating-system boundaries
instead of relying on the Python process to protect itself:

- Run P2Pool under an unprivileged service account.
- Keep Defcoin RPC bound to loopback only.
- Expose only required public ports: web, Defcoin parent-chain P2P, P2Pool peer
  P2P, and Stratum.
- Use a default-drop firewall policy.
- Put public HTTP endpoints behind nginx or another reverse proxy with security
  headers, CSP, request limits for API paths, and ordinary TLS renewal.
- Run P2Pool with UPnP disabled on hosted servers.
- Disable upstream bug reporting unless the operator intentionally opts in.
- Cap journal and application log growth so bad peers cannot fill the disk.
- Monitor service state, web/API health, open ports, disk pressure, memory
  pressure, certificate expiry, and Defcoin RPC block count.
- Keep local backups and restoration notes. Restore tests are valuable, but
  should be done deliberately with the operator present because this stack is a
  live mining service.

The dc903 deployment uses a small systemd timer named
`defcoin-ops-health-check.timer` for non-invasive checks. It writes compact
status lines to journald and does not restart services automatically.

## P2Pool peer handshake logging

The P2Pool peer network is separate from the Defcoin Core parent-chain peer
network. On a tiny sharechain, valid peers are valuable, so this fork avoids
over-aggressive duplicate-host rejection.

Policy:

- Accept sockets long enough to read the P2Pool `version` message and peer
  nonce.
- Do not reject a peer only because another connection from the same IP address
  exists.
- Keep established-peer log lines because they record the live peer set.
- Log invalid handshakes such as too-old protocol versions, repeated version
  messages, and self-connections.
- For duplicate peer nonces, disconnect the duplicate after identification and
  rate-limit the log message by host.

This preserves useful abnormal-event logging without filling logs with ordinary
duplicate-connection churn.

## License and attribution

This repository follows the inherited P2Pool license: GNU General Public
License version 3. See `COPYING`.

Bundled third-party or vendored code remains under its inherited terms as
provided by the upstream P2Pool tree and its dependencies. Operators who
redistribute modified binaries or services should review GPLv3 obligations and
provide corresponding source.

## AI-assisted development note

This Defcoin P2Pool port and documentation cleanup were developed with AI
assistance for source migration, documentation consolidation, code review,
testing guidance, benchmark scripting, and repetitive polish work, specifically
OpenAI Codex using GPT-5.5 Extra High reasoning settings. Human review,
live-service verification, reproducible tests, and open-source auditability
remain required.
