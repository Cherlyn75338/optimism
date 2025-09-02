## Brief/Intro

OP Stack interop relies on node-level policy (op-geth + op-supervisor) to validate EIP-2930 access lists for cross-L2 relays. If a chain operator misconfigures the sequencer/execution client by omitting mempool filtering and/or the supervisor endpoint, any user can submit a crafted EIP-2930 transaction that “warms” the `CrossL2Inbox` checksum slot and call `L2ToL2CrossDomainMessenger.relayMessage` with arbitrary sender/target/calldata. This forges cross‑L2 messages on that chain and can lead to arbitrary contract calls and asset inflation/drain on the affected L2. This is an operational misconfiguration vulnerability, not a Solidity flaw, and it is isolated to misconfigured deployments.

## Vulnerability Details

### Design overview

Contracts intentionally do not implement full provenance checks for cross‑L2 messages. Instead, the `CrossL2Inbox` contract enforces that the message checksum slot is “warm” (EIP‑2930 preaccess) and leaves cross‑chain safety to client policy managed by the `op-supervisor`.

Relevant Solidity:

```201:219:/workspace/optimism/packages/contracts-bedrock/src/L2/L2ToL2CrossDomainMessenger.sol
    function relayMessage(
        Identifier calldata _id,
        bytes calldata _sentMessage
    )
        external
        payable
        nonReentrant
        returns (bytes memory returnData_)
    {
        // Ensure the log came from the messenger.
        if (_id.origin != Predeploys.L2_TO_L2_CROSS_DOMAIN_MESSENGER) {
            revert IdOriginNotL2ToL2CrossDomainMessenger();
        }

        // Signal that this is a cross chain call that needs to have the identifier validated
        ICrossL2Inbox(Predeploys.CROSS_L2_INBOX).validateMessage(_id, keccak256(_sentMessage));
```

```74:81:/workspace/optimism/packages/contracts-bedrock/src/L2/CrossL2Inbox.sol
function validateMessage(Identifier calldata _id, bytes32 _msgHash) external {
    bytes32 checksum = calculateChecksum(_id, _msgHash);
    (bool isWarm,) = _isWarm(checksum);
    if (!isWarm) revert NotInAccessList();
    emit ExecutingMessage(_msgHash, _id);
}
```

Classic cross-domain messenger (L1/L2) similarly does not enforce EIP‑2930 gating; it checks local invariants and executes the message:

```222:306:/workspace/optimism/packages/contracts-bedrock/src/universal/CrossDomainMessenger.sol
function relayMessage(...) external payable {
  require(paused() == false, ...);
  ...
  require(_isUnsafeTarget(_target) == false, ...);
  require(successfulMessages[versionedHash] == false, ...);
  bool success = SafeCall.call(_target, ...);
  ...
}
```

### Where the policy lives (node side)

The interop access-list policy is enforced in `op-geth` by a txpool ingress filter that calls `op-supervisor` via `supervisor_checkAccessList`. This filter only gets installed if BOTH flags are set: `--rollup.interoprpc` (endpoint) and `--rollup.interopmempoolfiltering` (gate).

Filter wiring and flags:

```351:356:/workspace/op-geth/eth/backend.go
if config.InteropMessageRPC != "" && config.InteropMempoolFiltering {
    chainID := uint256.MustFromBig(chainConfig.ChainID)
    poolFilters = append(poolFilters, txpool.NewInteropFilter(eth, *chainID))
}
```

```43:66:/workspace/op-geth/core/txpool/ingress_filters.go
func (f *interopAccessFilter) FilterTx(ctx context.Context, tx *types.Transaction) bool {
    hashes := f.api.TxToInteropAccessList(tx)
    if len(hashes) == 0 { return true }
    t, err := f.api.CurrentInteropBlockTime()
    if err != nil { return false }
    exDesc := interoptypes.ExecutingDescriptor{Timestamp: t, Timeout: f.timeout, ChainID: f.chainID}
    return f.api.CheckAccessList(ctx, hashes, interoptypes.CrossUnsafe, exDesc) == nil
}
```

`op-geth` calls the supervisor JSON‑RPC method:

```51:56:/workspace/op-geth/eth/interop/interop.go
err := cl.client.CallContext(ctx, nil, "supervisor_checkAccessList", inboxEntries, minSafety, executingDescriptor)
```

Supervisor backend enforces safety/link checks or failsafe:

```569:639:/workspace/optimism/op-supervisor/supervisor/backend/backend.go
func (su *SupervisorBackend) CheckAccessList(...) error {
    if su.isFailsafeEnabled() { return types.ErrFailsafeEnabled }
    ...
    remaining, acc, err := types.ParseAccess(entries)
    if !su.linker.CanExecute(execChainID, execDescr.Timestamp, acc.ChainID, acc.Timestamp) { return types.ErrConflict }
    msgBlockFromDB, err := su.checkAccessWithDB(acc)
    if err != nil { return types.ErrConflict }
    if err := su.checkSafety(acc.ChainID, msgBlockFromDB, minSafety); err != nil { return types.ErrConflict }
}
```

The address used to pick interop access-list entries is hardcoded to the `CrossL2Inbox` predeploy:

```5:5:/workspace/op-geth/params/interop.go
var InteropCrossL2InboxAddress = common.HexToAddress("0x4200000000000000000000000000000000000022")
```

### Root cause

- The contracts rely on “warm slot” (EIP‑2930) but do not prove message provenance on-chain.
- The node must enforce policy by consulting `op-supervisor` and rejecting interop access lists that are not approved.
- If the operator:
  - omits `--rollup.interopmempoolfiltering` (even if `--rollup.interoprpc` is set), or
  - omits both flags,
  then the txpool filter is not installed and op-geth will accept interop EIP‑2930 transactions without supervisor validation.
- In this state, any account can forge a valid `CrossL2Inbox.validateMessage` by pre‑warming the checksum slot and then call `L2ToL2CrossDomainMessenger.relayMessage` to execute arbitrary payloads under an arbitrary “sender” on that chain.

### Exploit summary

An attacker crafts a transaction that:

1) Computes a bogus `Identifier` and message payload, then `msgHash = keccak256(payload)`.
2) Computes the checksum slot per `CrossL2Inbox.calculateChecksum(_id, _msgHash)` and includes it in an EIP‑2930 access list for address `0x4200…0022`.
3) ABI-encodes and calls `L2ToL2CrossDomainMessenger.relayMessage(_id, payload)`.

With the filter disabled, the mempool admits the tx, `validateMessage` sees the slot as warm, and the messenger proceeds to call the target with attacker‑chosen `sender` injected into transient context.

## Impact Details

Impact scope is the misconfigured chain; other L2s are unaffected. Potential outcomes:

- Arbitrary cross‑L2 message forgery:
  - Call any target with arbitrary calldata.
  - Impersonate any “sender” (used by apps via messenger guards).
- Asset risks on that L2:
  - Token bridges or minting flows that trust interop messages may be abused to mint/unlock assets without real source-chain action (inflation/drain).
  - Protocols protected by `onlyCrossDomainMessenger/from X` can be reconfigured or drained.
- Cross‑L1 impact:
  - L1 ETH cannot be minted; canonical L1 proofs/portals are not bypassed.
  - L1 asset loss is possible only if an L2 token minted via forged relay can be redeemed 1:1 on L1 without additional verification (asset-specific; must be analyzed per bridge).

Severity: High for the affected L2—complete bypass of cross‑L2 authenticity guarantees, leading to arbitrary execution and potential fund loss on that L2.

## References

- Contracts invoking access-list validate:
  - `L2ToL2CrossDomainMessenger.relayMessage`: `packages/contracts-bedrock/src/L2/L2ToL2CrossDomainMessenger.sol`
  - `CrossL2Inbox.validateMessage`: `packages/contracts-bedrock/src/L2/CrossL2Inbox.sol`
- Node-side enforcement:
  - `op-geth` filter wiring: `eth/backend.go` (lines 351–356)
  - Ingress filter logic: `core/txpool/ingress_filters.go` (lines 43–66)
  - Supervisor RPC call: `eth/interop/interop.go` (lines 51–56)
  - Supervisor backend checks: `op-supervisor/supervisor/backend/backend.go` (lines 569–639)
- Interop predeploy address binding: `op-geth/params/interop.go`

OP docs
- Interop devnet notes: `https://docs.optimism.io/interop/tools/devnet`
- Superchain registry (addresses): `https://github.com/ethereum-optimism/superchain-registry`

## Proof of Concept

Demonstration is safest on a devnet you control. We provide a Go probe that constructs the forged EIP‑2930 tx and submits it. Expected results:

- With filtering ON (both flags set and supervisor reachable): mempool rejects tx; SendTransaction errors.
- With filtering OFF (filter disabled by flags): tx is mined; forged relay executes.

### Probe

The tool is in `interop-probe/main.go` and:
- Computes the exact checksum slot via `calculateChecksum` logic.
- Builds an EIP‑2930 AccessList that warms `(CROSS_L2_INBOX, checksum)`.
- ABI-encodes and calls `relayMessage(_id, _sentMessage)` with an arbitrary `sender` and payload.

Usage (safe check):

```bash
./interop-probe --check --rpc https://sepolia.optimism.io
# prints code lengths for CROSS_L2_INBOX and L2ToL2CrossDomainMessenger
```

Devnet runbook:

1) Start interop-enabled op-geth
   - Vulnerable: omit either `--rollup.interoprpc` or `--rollup.interopmempoolfiltering`.
   - Safe: set both and run a reachable supervisor.

2) Fund a test key.

3) Dry-run (prints signed tx; no send):

```bash
./interop-probe --dry \
  --rpc http://127.0.0.1:8545 \
  --priv 0x<funded_key> \
  --target 0x<TARGET> \
  --data 0x<calldata> \
  --xSender 0x1111111111111111111111111111111111111111 \
  --sourceChainId 1111 \
  --gas 1200000
```

4) Submit (observe behavior):

```bash
./interop-probe \
  --rpc http://127.0.0.1:8545 \
  --priv 0x<funded_key> \
  --target 0x<TARGET> \
  --data 0x<calldata> \
  --xSender 0x1111111111111111111111111111111111111111 \
  --sourceChainId 1111 \
  --gas 1200000
```

Filtering ON (expected):
```
SendTransaction error (likely filtered): <error>
```

Filtering OFF (expected):
```
Submitted. Waiting for receipt...
Status: 1, GasUsed: <...>
```

This PoC works because the Solidity-only check is “slot warmth” (EIP‑2930). With policy disabled, provenance is never validated and the forged `Identifier` + `msgHash` pair passes `validateMessage`.

