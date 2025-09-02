Interop Access-List Probe (devnet only)

Purpose

- Craft an EIP-2930 transaction that warms CROSS_L2_INBOX (0x4200…0022) with a forged checksum and calls L2ToL2CrossDomainMessenger.relayMessage. Use it to demonstrate:
  - With filtering ON (both flags set): mempool rejects (tx not mined)
  - With filtering OFF: tx can be mined and relay executes (misconfigured chain)

Build

```bash
cd interop-probe
go mod init interop-probe && go mod tidy  # if needed
go build -o interop-probe
```

Run (devnet)

1) Start interop-enabled op-geth devnet

- Vulnerable (do NOT do this in prod): do not set the 2 flags
  - omit: --rollup.interoprpc and --rollup.interopmempoolfiltering
- Safe: set both flags to a running supervisor

2) Fund a test key and run the probe

```bash
./interop-probe \
  --rpc http://127.0.0.1:8545 \
  --priv 0x<hex_private_key_with_funds> \
  --target 0x<target_contract_on_L2> \
  --data 0x<encoded_function_call> \
  --xSender 0x1111111111111111111111111111111111111111 \
  --sourceChainId 1111 \
  --gas 1200000 --maxFee 10 --maxTip 1
```

Expected results

- Filtering ON: SendTransaction fails (mempool rejects), no receipt.
- Filtering OFF: tx is accepted; a receipt is returned; the messenger call executes with the forged sender.

Safety note

- Use only on local/dev/test networks you control. Never probe mainnet with this tool.

