package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

var rpcURLs = []string{
	"https://eth.llamarpc.com",
	"https://cloudflare-eth.com",
	"https://ethereum.publicnode.com",
	"https://1rpc.io/eth",
}

var rpcIndex int

func nextRPC() string {
	u := rpcURLs[rpcIndex%len(rpcURLs)]
	rpcIndex++
	return u
}

const (
	contractHex = "AC7b5d06fa1e77D08aea40d46cB7C5923A87A0cc"
	chainID     = 1
)

func keccak256(data ...[]byte) []byte {
	h := sha3.NewLegacyKeccak256()
	for _, d := range data { h.Write(d) }
	return h.Sum(nil)
}

func pad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func privToAddr(priv []byte) []byte {
	key := secp256k1.PrivKeyFromBytes(priv)
	pub := key.PubKey().SerializeUncompressed()
	return keccak256(pub[1:])[12:]
}

type rpcResp struct {
	Result string `json:"result"`
	Error  *struct{ Message string `json:"message"` } `json:"error"`
}

func rpcCall(method string, params []interface{}) (string, error) {
	body, _ := json.Marshal(map[string]interface{}{"jsonrpc":"2.0","method":method,"params":params,"id":1})
	url := nextRPC()
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil { return "", err }
	defer resp.Body.Close()
	var r rpcResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", fmt.Errorf("json decode: %w", err)
	}
	if r.Error != nil { return "", fmt.Errorf("%s", r.Error.Message) }
	return r.Result, nil
}

func callUint256(sig string) (*big.Int, error) {
	sel := "0x" + hex.EncodeToString(keccak256([]byte(sig))[:4])
	res, err := rpcCall("eth_call", []interface{}{map[string]string{"to":"0x"+contractHex,"data":sel},"latest"})
	if err != nil { return nil, err }
	res = strings.TrimPrefix(res, "0x")
	if len(res) < 64 { return nil, fmt.Errorf("挖矿未开放（合约未初始化）") }
	n, _ := new(big.Int).SetString(res[:64], 16)
	return n, nil
}

func computeChallenge(miner []byte, epoch *big.Int) []byte {
	ct, _ := hex.DecodeString(contractHex)
	return keccak256(pad32(big.NewInt(chainID).Bytes()), pad32(ct), pad32(miner), pad32(epoch.Bytes()))
}

func mineRange(challenge []byte, diff *big.Int, start, step uint64, found *int32, result *uint64, wg *sync.WaitGroup) {
	defer wg.Done()
	nonce := start
	nb := make([]byte, 32)
	for atomic.LoadInt32(found) == 0 {
		binary.BigEndian.PutUint64(nb[24:], nonce)
		if new(big.Int).SetBytes(keccak256(challenge, nb)).Cmp(diff) < 0 {
			atomic.StoreInt32(found, 1)
			atomic.StoreUint64(result, nonce)
			return
		}
		nonce += step
	}
}

func bigBytes(n *big.Int) []byte {
	if n.Sign() == 0 { return []byte{} }
	return n.Bytes()
}

func rlpBytes(b []byte) []byte {
	if len(b) == 0 { return []byte{0x80} }
	if len(b) == 1 && b[0] < 0x80 { return b }
	if len(b) <= 55 { return append([]byte{byte(0x80+len(b))}, b...) }
	lb := bigBytes(big.NewInt(int64(len(b))))
	return append(append([]byte{byte(0xb7+len(lb))}, lb...), b...)
}

func rlpList(items ...[]byte) []byte {
	var body []byte
	for _, it := range items { body = append(body, it...) }
	if len(body) <= 55 { return append([]byte{byte(0xc0+len(body))}, body...) }
	lb := bigBytes(big.NewInt(int64(len(body))))
	return append(append([]byte{byte(0xf7+len(lb))}, lb...), body...)
}

func signAndSend(privBytes, minerAddr []byte, nonce uint64) error {
	fnSel := keccak256([]byte("mine(uint256)"))[:4]
	data := append(fnSel, pad32(new(big.Int).SetUint64(nonce).Bytes())...)
	ct, _ := hex.DecodeString(contractHex)

	txNonceHex, _ := rpcCall("eth_getTransactionCount", []interface{}{"0x"+hex.EncodeToString(minerAddr),"latest"})
	txNonce, _ := new(big.Int).SetString(strings.TrimPrefix(txNonceHex,"0x"), 16)
	gasPriceHex, _ := rpcCall("eth_gasPrice", []interface{}{})
	gasPrice, _ := new(big.Int).SetString(strings.TrimPrefix(gasPriceHex,"0x"), 16)

	cid := big.NewInt(chainID)
	sigHash := keccak256(rlpList(
		rlpBytes(bigBytes(txNonce)), rlpBytes(bigBytes(gasPrice)), rlpBytes(bigBytes(big.NewInt(200000))),
		rlpBytes(ct), rlpBytes([]byte{}), rlpBytes(data),
		rlpBytes(bigBytes(cid)), rlpBytes([]byte{}), rlpBytes([]byte{}),
	))

	privKey := secp256k1.PrivKeyFromBytes(privBytes)
	sig := ecdsa.SignCompact(privKey, sigHash, false)
	v := big.NewInt(int64(sig[0]-27) + 35 + 2*chainID)

	raw := rlpList(
		rlpBytes(bigBytes(txNonce)), rlpBytes(bigBytes(gasPrice)), rlpBytes(bigBytes(big.NewInt(200000))),
		rlpBytes(ct), rlpBytes([]byte{}), rlpBytes(data),
		rlpBytes(bigBytes(v)), rlpBytes(sig[1:33]), rlpBytes(sig[33:65]),
	)

	res, err := rpcCall("eth_sendRawTransaction", []interface{}{"0x"+hex.EncodeToString(raw)})
	if err != nil { return err }
	fmt.Println("[+] tx:", res)
	return nil
}

func main() {
	privKeyHex := strings.TrimSpace(os.Getenv("HASH_PRIVKEY"))
	if privKeyHex == "" {
		data, err := os.ReadFile("config.txt")
		if err != nil {
			fmt.Println("请创建 config.txt 并写入私钥（64位十六进制，不含0x）")
			os.Exit(1)
		}
		privKeyHex = strings.TrimSpace(string(data))
	}
	privBytes, err := hex.DecodeString(strings.TrimPrefix(privKeyHex, "0x"))
	if err != nil || len(privBytes) != 32 {
		fmt.Println("私钥格式错误")
		os.Exit(1)
	}
	minerAddr := privToAddr(privBytes)
	fmt.Printf("[*] 矿工地址: 0x%s\n", hex.EncodeToString(minerAddr))
	fmt.Printf("[*] 线程数: %d\n", runtime.NumCPU())

	waitPrinted := false
	for {
		diff, err := callUint256("currentDifficulty()")
		if err != nil {
			if strings.Contains(err.Error(), "未开放") || strings.Contains(err.Error(), "reverted") {
				if !waitPrinted {
					fmt.Println("[~] 挖矿未开放，等待中（每30秒检查一次）...")
					waitPrinted = true
				}
				time.Sleep(30 * time.Second)
				continue
			}
			fmt.Println("[!] RPC错误:", err, "，重试中...")
			time.Sleep(5 * time.Second)
			continue
		}
		waitPrinted = false
		epoch, err := callUint256("currentEpoch()")
		if err != nil { fmt.Println("[!] epoch:", err); time.Sleep(5*time.Second); continue }
		fmt.Printf("[*] epoch=%s  diff=0x%x\n", epoch, diff)

		challenge := computeChallenge(minerAddr, epoch)
		threads := runtime.NumCPU()
		var foundFlag int32
		var resultNonce uint64
		var wg sync.WaitGroup
		var startBuf [8]byte
		rand.Read(startBuf[:])
		start := binary.BigEndian.Uint64(startBuf[:])

		t0 := time.Now()
		for i := 0; i < threads; i++ {
			wg.Add(1)
			go mineRange(challenge, diff, start+uint64(i), uint64(threads), &foundFlag, &resultNonce, &wg)
		}
		wg.Wait()
		fmt.Printf("[+] nonce=%d  耗时=%.1fs  提交中...\n", resultNonce, time.Since(t0).Seconds())
		if err := signAndSend(privBytes, minerAddr, resultNonce); err != nil {
			fmt.Println("[!] 提交失败:", err)
		}
		time.Sleep(2 * time.Second)
	}
}
