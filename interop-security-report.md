## Brief/Intro

Off-chain interop policy enforcement is required for the OP Stack’s cross-L2 messaging design. If an operator deploys or runs an OP Stack chain with interop features enabled but does not enforce the off-chain access-list policy (i.e., nodes/ingress do not call the supervisor to verify CrossL2Inbox access lists), a user can forge a relay by crafting an access list that “looks valid” locally. This lets them pass `validateMessage` checks and have the messenger relay arbitrary calls, including to the Superchain ETH bridge, allowing unauthorized ETH withdrawals from the L2 liquidity reserve. In short: misconfigured or disabled policy turns an operational requirement into a high-impact security vulnerability.

## Vulnerability Details

### Design overview (on-chain relies on off-chain)

- Interop messages are validated on-chain by `CrossL2Inbox.validateMessage`. It accepts an “identifier” (origin chain, block, log index, timestamp, checksum) and relies on the caller supplying an access list that maps to the expected storage keys so validation can be performed efficiently.
- The correctness of that identifier and access list is not proven on-chain. Instead, clients are required to reject transactions at ingress unless the access list was checked against a canonical view of cross-chain logs maintained by the op-supervisor service.

The supervisor’s critical enforcement point is the `CheckAccessList` API, which parses each access entry, enforces inter-chain timestamp/link constraints, and verifies the initiating log exists at `(chain, block, logIndex)` with the expected payload checksum before allowing relay:

```text
590:635:optimism/op-supervisor/supervisor/backend/backend.go
// (illustrative excerpt)
remaining, acc, err := types.ParseAccess(entries)
if !su.linker.CanExecute(execChainID, execDescr.Timestamp, acc.ChainID, acc.Timestamp) { return types.ErrConflict }
msgBlockFromDB, err := su.checkAccessWithDB(acc)
if err != nil { return types.ErrConflict }
if err := su.checkSafety(acc.ChainID, msgBlockFromDB, minSafety); err != nil { return types.ErrConflict }
```

Supervisor errors are explicit:

```text
29:70:optimism/op-supervisor/supervisor/types/error.go
ErrConflict        = errors.New("conflicting data")
ErrFailsafeEnabled = errors.New("failsafe is enabled, rejecting all CheckAccessList requests")
```

### Where enforcement must happen (ingress filter)

Transactions must be filtered at admission (mempool) so a relay with fabricated identifiers/access lists never lands on-chain without prior supervisor verification. In `op-geth`, this is implemented as a txpool ingress filter:

```text
43:74:op-geth/core/txpool/ingress_filters.go
func (f *interopAccessFilter) FilterTx(ctx context.Context, tx *types.Transaction) bool {
  hashes := f.api.TxToInteropAccessList(tx)
  if len(hashes) == 0 { return true }
  t, err := f.api.CurrentInteropBlockTime()
  if err != nil { return false } // fail-closed if interop API unavailable
  exDesc := interoptypes.ExecutingDescriptor{Timestamp: t, Timeout: f.timeout, ChainID: f.chainID}
  return f.api.CheckAccessList(ctx, hashes, interoptypes.CrossUnsafe, exDesc) == nil
}
```

However, this filter is only enabled when BOTH interop flags are set. Otherwise, there is no interop policy enforcement:

```text
353:360:op-geth/eth/backend.go
// only enable interop mempool filtering if both are set
if config.InteropMessageRPC != "" && config.InteropMempoolFiltering {
  chainID := uint256.MustFromBig(chainConfig.ChainID)
  poolFilters = append(poolFilters, txpool.NewInteropFilter(eth, *chainID))
}
```

The flags are surfaced via CLI:

```text
980:1000:op-geth/cmd/utils/flags.go
--rollup.interoprpc              (RPC endpoint for supervisor)
--rollup.interopmempoolfiltering (enable tx admission filter)
``;

When the filter is active, `op-geth` calls the supervisor RPC before admitting the tx:

```text
51:55:op-geth/eth/interop/interop.go
err := s.interopRPC.CheckAccessList(ctx, inboxEntries, minSafety, execDesc) // supervisor_checkAccessList
```

### Root cause

The interop on-chain contracts assume an operational invariant: nodes must consult the supervisor and drop any transaction whose access list does not match canonical source-chain logs. This assumption is sound only if every ingress path enforces the policy. If an operator:

- fails to set `--rollup.interoprpc` and `--rollup.interopmempoolfiltering`, or
- uses an execution client that does not implement the ingress filter, or
- runs alternative infrastructure that accepts/bundles transactions without supervisor checks,

then fabricated interop relays can be included on-chain, because the on-chain contracts are not self-contained proofs and will “validate” against attacker-chosen access lists.

The supervisor documentation explicitly describes a “failsafe” mode that rejects all `CheckAccessList` calls (causing ingress to drop txs). This further confirms that the intended security property is enforced operationally pre-inclusion, not by on-chain proofs.

```text
315:346:optimism/op-supervisor/README.md
When failsafe is active, the supervisor will reject all CheckAccessList requests, allowing ingress to drop such transactions.
```

### Why this is exploitable under misconfiguration

If interop is enabled on a chain but the mempool filtering is absent or bypassed, anyone can:

1) Craft a `relayMessage` call to the interop messenger with a made-up `Identifier` (origin chain, block, logIndex, timestamp, chainId) and payload.
2) Attach an EIP-2930 access list targeting the interop `CrossL2Inbox` storage expected by `validateMessage` so that local checks appear to succeed.
3) Without a supervisor check at admission, the tx can be mined, and the messenger executes the forged relay, calling any target with attacker-chosen calldata.

With enforcement correctly enabled, the same tx is rejected pre-inclusion because supervisor returns `ErrConflict` (no such source log or checksum mismatch).

## Impact Details

The most severe and concrete impact in interop-enabled deployments is unauthorized minting via the Superchain ETH bridge path:

- The forged relay can invoke `SuperchainETHBridge.relayETH`, which in turn calls `ETHLiquidity.mint(amount)` to pay out ETH to the bridge and onward to the recipient. `ETHLiquidity` restricts caller to the bridge, but the call is coming from the messenger’s relay, which sets the transient cross-domain sender to the bridge address, so on-chain authorization passes.
- `ETHLiquidity` is pre-funded at genesis with a very large ETH balance (per genesis scripts) to support seamless bridging, so mint does not require a matching burn on the source if the relay can be forged.

Practical effects if policy is not enforced:

- Drain the target chain’s L2 ETH liquidity reserve by repeatedly forging relays to the bridge, extracting ETH to attacker-controlled accounts.
- Relay arbitrary calls to any target contract, impersonating arbitrary senders encoded in the cross-domain payload, leading to privilege escalations in interop-aware applications.

Scope clarifications:

- OP Mainnet (today) does not expose L2→L2 interop contracts in production; thus this exact interop forging path must be evaluated on interop-enabled networks. The vulnerability is systemic to any deployment that enables interop but fails to enforce the policy.
- The risk exists across any chain/operator that enables interop features and misconfigures ingress (e.g., missing the required flags or using non-compliant infra).

## References

- Supervisor access-list verification and link checks (off-chain requirement):
  - `optimism/op-supervisor/supervisor/backend/backend.go` (CheckAccessList)
  - `optimism/op-supervisor/supervisor/types/error.go` (ErrConflict, ErrFailsafeEnabled)
  - `optimism/op-supervisor/README.md` (failsafe and ingress behavior)
- Geth integration points (where to enforce):
  - `op-geth/core/txpool/ingress_filters.go` (FilterTx calling supervisor)
  - `op-geth/eth/backend.go` (only enables filter if both flags set)
  - `op-geth/cmd/utils/flags.go` (CLI flags)
  - `op-geth/eth/interop/interop.go` (supervisor RPC call)
- Contract paths (bridge behavior):
  - `SuperchainETHBridge.relayETH` and `ETHLiquidity.mint` (pre-funded reserve, restricted caller)

## Proof of Concept

Two complementary PoCs demonstrate both exploitability under misconfiguration and correct behavior under enforcement:

1) Local PoC (devnet)

- Start an interop-enabled devnet (or two-chain local) with `op-geth` and do NOT set `--rollup.interoprpc` and `--rollup.interopmempoolfiltering`.
- Craft and send a `relayMessage` to the L2 interop messenger with a fabricated `Identifier` and an access list targeting `CrossL2Inbox` storage slots read by `validateMessage`.
- Observe: tx is included and relay executes; when targeting the Superchain ETH bridge, the call chain mints ETH via `ETHLiquidity` and pays the recipient.
- Repeat with the mempool filter enabled and supervisor running; observe immediate admission rejection (or non-inclusion) since supervisor returns `ErrConflict`.

2) Passive mainnet audit (no tx, safe)

- Run a scanner that enumerates recent relays on the chain’s messenger and checks that each maps back to a real source event (for L2→L1: provenance via L1 messenger logs; for L2→L2 interop-enabled chains: `ExecutingMessage` events on the source chain).
- If every relay maps to a real source log/checksum, it is strong evidence that ingress policy is being enforced. Any relay lacking a valid source is a red flag.

Operational recommendation (fix):

- Enforce policy at all ingress points by configuring `op-geth` with both flags and pointing it at a healthy supervisor:
  - `--rollup.interoprpc=<supervisor-rpc>`
  - `--rollup.interopmempoolfiltering`
- Ensure alternative components (RPC gateways, block builders, sequencers) do not bypass the ingress filter.
- Consider monitoring for supervisor `ErrConflict` rates and alert on policy-disabled operation.

