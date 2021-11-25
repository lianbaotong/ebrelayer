package ethereum

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	chain33Common "github.com/33cn/chain33/common"
	dbm "github.com/33cn/chain33/common/db"
	chain33Types "github.com/33cn/chain33/types"
	wcom "github.com/33cn/chain33/wallet/common"
	x2ethTypes "github.com/lianbaotong/ebrelayer/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pborman/uuid"
)

var (
	ethAccountKey = []byte("EthereumAccount4EthRelayer")
	start         = int(1)
)

//Key ...
type Key struct {
	ID uuid.UUID // Version 4 "random" for unique id not derived from key data
	// to simplify lookups we also store the address
	Address common.Address
	// we only store privkey as pubkey/address can be derived from it
	// privkey in this struct is always in plaintext
	PrivateKey *ecdsa.PrivateKey
}

//NewAccount ...
func (ethRelayer *Relayer4Ethereum) NewAccount(passphrase string) (privateKeystr, addr string, err error) {
	_, privateKeystr, addr, err = newKeyAndStore(ethRelayer.db, crand.Reader, passphrase)
	if err != nil {
		return "", "", err
	}
	return
}

//GetAccount ...
func (ethRelayer *Relayer4Ethereum) GetAccount(passphrase string) (privateKey, addr string, err error) {
	accountInfo, err := ethRelayer.db.Get(ethAccountKey)
	if nil != err {
		return "", "", err
	}
	Chain33Account := &x2ethTypes.Account4Relayer{}
	if err := chain33Types.Decode(accountInfo, Chain33Account); nil != err {
		return "", "", err
	}
	decryptered := wcom.CBCDecrypterPrivkey([]byte(passphrase), Chain33Account.Privkey)
	privateKey = chain33Common.ToHex(decryptered)
	addr = Chain33Account.Addr
	return
}

//GetValidatorAddr ...
func (ethRelayer *Relayer4Ethereum) GetValidatorAddr() (validators x2ethTypes.ValidatorAddr4EthRelayer, err error) {
	var chain33AccountAddr string
	accountInfo, err := ethRelayer.db.Get(ethAccountKey)
	if nil == err {
		ethAccount := &x2ethTypes.Account4Relayer{}
		if err := chain33Types.Decode(accountInfo, ethAccount); nil == err {
			chain33AccountAddr = ethAccount.Addr
		}
	}

	if 0 == len(chain33AccountAddr) {
		return x2ethTypes.ValidatorAddr4EthRelayer{}, x2ethTypes.ErrNoValidatorConfigured
	}

	validators = x2ethTypes.ValidatorAddr4EthRelayer{
		EthereumValidator: chain33AccountAddr,
	}
	return
}

func (ethRelayer *Relayer4Ethereum) ImportPrivateKey(passphrase, privateKeyStr string) (addr string, err error) {
	privateKeySlice, err := chain33Common.FromHex(privateKeyStr)
	if nil != err {
		return "", err
	}
	privateKey, err := crypto.ToECDSA(privateKeySlice)
	if nil != err {
		return "", err
	}

	ethSender := crypto.PubkeyToAddress(privateKey.PublicKey)
	ethRelayer.privateKey4Ethereum = privateKey
	ethRelayer.ethSender = ethSender
	ethRelayer.unlockchan <- start

	addr = chain33Common.ToHex(ethSender.Bytes())
	encryptered := wcom.CBCEncrypterPrivkey([]byte(passphrase), privateKeySlice)
	ethAccount := &x2ethTypes.Account4Relayer{
		Privkey: encryptered,
		Addr:    addr,
	}
	encodedInfo := chain33Types.Encode(ethAccount)
	err = ethRelayer.db.SetSync(ethAccountKey, encodedInfo)

	return
}

func (ethRelayer *Relayer4Ethereum) ImportPrivateKeyPasspin(passphrase, privateKeyPasspin string) (err error) {
	if nil != err {
		return err
	}
	ethRelayer.keyPasspin = privateKeyPasspin
	ethRelayer.unlockchan <- start

	passpinLen := len(privateKeyPasspin)
	if passpinLen > 32 {
		return errors.New("Passpin should not longer than 32")
	}
	key := make([]byte, 32)
	copy(key, []byte(privateKeyPasspin))

	encryptered := wcom.CBCEncrypterPrivkey([]byte(passphrase), key)
	ethAccount := &x2ethTypes.Account4Relayer{
		PasspinOfprivkey: encryptered,
		PasspinLen:       int32(passpinLen),
		Addr:             ethRelayer.ethSender.String(),
	}
	encodedInfo := chain33Types.Encode(ethAccount)
	err = ethRelayer.db.SetSync(ethAccountKey, encodedInfo)

	return
}

//RestorePrivateKeyOrPasspin ...
func (ethRelayer *Relayer4Ethereum) RestorePrivateKeyOrPasspin(passphrase string) error {
	accountInfo, err := ethRelayer.db.Get(ethAccountKey)
	if nil != err {
		//此处未能成功获取信息，就统一认为未设置过相关信息
		relayerLog.Info("No private key or passpin saved for Relayer4Ethereum")
		return nil
	}
	ethAccount := &x2ethTypes.Account4Relayer{}
	if err := chain33Types.Decode(accountInfo, ethAccount); nil != err {
		relayerLog.Info("RestorePrivateKeys", "Failed to decode due to:", err.Error())
		return err
	}
	if ethRelayer.signViaHsm {
		decryptered := wcom.CBCDecrypterPrivkey([]byte(passphrase), ethAccount.PasspinOfprivkey)
		ethRelayer.rwLock.Lock()
		ethRelayer.keyPasspin = string(decryptered[:ethAccount.PasspinLen])
		ethRelayer.rwLock.Unlock()
		ethRelayer.unlockchan <- start
	} else {
		decryptered := wcom.CBCDecrypterPrivkey([]byte(passphrase), ethAccount.Privkey)
		privateKey, err := crypto.ToECDSA(decryptered)
		if nil != err {
			relayerLog.Info("RestorePrivateKeys", "Failed to ToECDSA:", err.Error())
			return err
		}

		ethRelayer.rwLock.Lock()
		ethRelayer.privateKey4Ethereum = privateKey
		ethRelayer.ethSender = crypto.PubkeyToAddress(privateKey.PublicKey)
		ethRelayer.rwLock.Unlock()
		ethRelayer.unlockchan <- start
	}

	return nil
}

//StoreAccountWithNewPassphase ...
func (ethRelayer *Relayer4Ethereum) StoreAccountWithNewPassphase(newPassphrase, oldPassphrase string) error {
	accountInfo, err := ethRelayer.db.Get(ethAccountKey)
	if nil != err {
		relayerLog.Info("StoreAccountWithNewPassphase", "pls check account is created already, err", err)
		return err
	}
	Chain33Account := &x2ethTypes.Account4Relayer{}
	if err := chain33Types.Decode(accountInfo, Chain33Account); nil != err {
		return err
	}

	if ethRelayer.signViaHsm {
		decryptered := wcom.CBCDecrypterPrivkey([]byte(oldPassphrase), Chain33Account.PasspinOfprivkey)
		encryptered := wcom.CBCEncrypterPrivkey([]byte(newPassphrase), decryptered)
		Chain33Account.PasspinOfprivkey = encryptered
	} else {
		decryptered := wcom.CBCDecrypterPrivkey([]byte(oldPassphrase), Chain33Account.Privkey)
		encryptered := wcom.CBCEncrypterPrivkey([]byte(newPassphrase), decryptered)
		Chain33Account.Privkey = encryptered
	}

	encodedInfo := chain33Types.Encode(Chain33Account)
	return ethRelayer.db.SetSync(ethAccountKey, encodedInfo)
}

//checksum: first four bytes of double-SHA256.
func checksum(input []byte) (cksum [4]byte) {
	h := sha256.New()
	_, err := h.Write(input)
	if err != nil {
		return
	}
	intermediateHash := h.Sum(nil)
	h.Reset()
	_, err = h.Write(intermediateHash)
	if err != nil {
		return
	}
	finalHash := h.Sum(nil)
	copy(cksum[:], finalHash[:])
	return
}

func newKeyAndStore(db dbm.DB, rand io.Reader, passphrase string) (privateKey *ecdsa.PrivateKey, privateKeyStr, addr string, err error) {
	key, err := newKey(rand)
	if err != nil {
		return nil, "", "", err
	}
	privateKey = key.PrivateKey
	privateKeyBytes := math.PaddedBigBytes(key.PrivateKey.D, 32)
	Encryptered := wcom.CBCEncrypterPrivkey([]byte(passphrase), privateKeyBytes)
	ethAccount := &x2ethTypes.Account4Relayer{
		Privkey: Encryptered,
		Addr:    key.Address.Hex(),
	}
	_ = db

	privateKeyStr = chain33Common.ToHex(privateKeyBytes)
	addr = ethAccount.Addr
	return
}

func newKey(rand io.Reader) (*Key, error) {
	privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), rand)
	if err != nil {
		return nil, err
	}
	return newKeyFromECDSA(privateKeyECDSA), nil
}

func newKeyFromECDSA(privateKeyECDSA *ecdsa.PrivateKey) *Key {
	id := uuid.NewRandom()
	key := &Key{
		ID:         id,
		Address:    crypto.PubkeyToAddress(privateKeyECDSA.PublicKey),
		PrivateKey: privateKeyECDSA,
	}
	return key
}
