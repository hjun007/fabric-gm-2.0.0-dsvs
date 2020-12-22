package sw_test

import (
	"fmt"
	"github.com/cetcxinlian/cryptogm/sm2"
	"github.com/cetcxinlian/cryptogm/sm3"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric/bccsp/sw"
	"github.com/hyperledger/fabric/msp"
	"math/big"
	"os"
	"testing"
)

func TestDsvs(t *testing.T) {

	os.Setenv("DSVS_CONFIG_FILE", "/home/hj/go/fabric-samples/bjca-sm2-dsvs-2.0.0/dsvs/peer0.org1/BJCA_SVS_Config.ini")
	os.Setenv("DSVS_LIB_FILE", "/home/hj/go/fabric-samples/bjca-sm2-dsvs-2.0.0/dsvs/libsvscc.so")

	configFile := []byte(os.Getenv("DSVS_CONFIG_FILE"))

	serverCert, err := sw.GetServerCert(configFile)
	if err != nil {
		fmt.Println("get server cert error")
		return
	}
	fmt.Printf("%s\n", serverCert)
	fmt.Println(len(serverCert))

	msg := []byte("hello world")
	digest := sm3.SumSM3(msg)
	signData, err := sw.SignHashedData(configFile, digest)
	if err != nil {
		fmt.Println("sign failed")
	}
	fmt.Printf("sig:%2x\n", signData)
	fmt.Println(len(signData))
	r, s, _ := sw.UnmarshalSM2Signature(signData)
	//fmt.Printf("r:%x\n", r)
	//fmt.Printf("s:%x\n", s)
	R, S, _ := sw.UnmarshalSM2Signature(signData)
	fmt.Printf("R:%2x\n", R.Bytes())
	fmt.Printf("S:%2x\n", S.Bytes())

	isOk, err := sw.VerifyByHashedData(configFile, serverCert, digest, signData)
	if err != nil {
		fmt.Println("verify failed")
	}
	fmt.Println(isOk)

	x, y, _ := sw.GetPubKeyFromX509CertPEM(serverCert)
	fmt.Printf("%2x\n", x)
	fmt.Printf("%2x\n", y)

	Px := big.Int{}
	Py := big.Int{}
	Px.SetBytes(x)
	Py.SetBytes(y)
	sm2PK := sm2.PublicKey{Curve: sm2.P256Sm2(), X: &Px, Y: &Py}
	ok := sm2.VerifyById(&sm2PK, msg, []byte("Peer0Org1"), r, s)
	fmt.Println(ok)

}

func TestSignature(t *testing.T) {

	//os.Setenv("DSVS_CONFIG_FILE", "/home/hj/go/fabric-samples/bjca-sm2-dsvs-2.0.0/dsvs/peer0.org1/BJCA_SVS_Config.ini")
	os.Setenv("DSVS_LIB_FILE", "/home/hj/go/fabric-samples/bjca-sm2-dsvs-2.0.0/dsvs/libsvscc.so")

	sig := big.Int{}
	digest := big.Int{}
	configFile := "/home/hj/go/fabric-samples/bjca-sm2-dsvs-2.0.0/dsvs/peer1.org1/BJCA_SVS_Config.ini"

	sig.SetString("304502202e56f9178a0613d9afda17f34061305fb2cf26b3a893ec63d4a0816c5d1e7e4a022100c2cfd0cdb349405b771b3733da9a51361df88bfe15a5fe122d7de17f6d60a829", 16)
	digest.SetString("64049a26070c02f29f4709a41225db8060a5f691aa722337e9b9ad10f58de54f", 16)
	cert, _ := sw.GetServerCert([]byte(configFile))

	ok, _ := sw.VerifyByHashedData([]byte(configFile), cert, digest.Bytes(), sig.Bytes())
	fmt.Println(ok)

	r, s, _ := sw.UnmarshalSM2Signature(sig.Bytes())

	x, y, _ := sw.GetPubKeyFromX509CertPEM(cert)
	Px := big.Int{}
	Py := big.Int{}
	Px.SetBytes(x)
	Py.SetBytes(y)
	sm2PK := sm2.PublicKey{Curve: sm2.P256Sm2(), X: &Px, Y: &Py}
	ok = sm2.VerifyWithDigest(&sm2PK, digest.Bytes(), r, s)
	fmt.Println(ok)

}

func TestMSP(t *testing.T) {

	os.Setenv("DSVS_CONFIG_FILE", "/home/hj/go/fabric-samples/bjca-sm2-dsvs-2.0.0/dsvs/peer0.org1/BJCA_SVS_Config.ini")
	os.Setenv("DSVS_LIB_FILE", "/home/hj/go/fabric-samples/bjca-sm2-dsvs-2.0.0/dsvs/libsvscc.so")

	mspDir := "/home/hj/go/fabric-samples/bjca-sm2-dsvs-2.0.0/crypto-config/peer0.org1/msp"
	conf, err := msp.GetLocalMspConfig(mspDir, factory.GetDefaultOpts(), "SampleOrg")
	if err != nil {
		fmt.Printf("Setup should have succeeded, got err %s instead", err)
		os.Exit(-1)
	}

	ks, err := sw.NewFileBasedKeyStore(nil, "./msp/keystore", true)
	if err != nil {
		fmt.Printf("New fileks err: %s", err)
		os.Exit(-1)
	}

	localMSPV143, err := msp.NewBccspMspWithKeyStore(msp.MSPv1_4_3, ks, factory.GetDefault())
	if err != nil {
		fmt.Printf("Constructor for msp should have succeeded, got err %s instead", err)
		os.Exit(-1)
	}

	err = localMSPV143.Setup(conf)
	if err != nil {
		fmt.Printf("Setup for msp should have succeeded, got err %s instead", err)
		os.Exit(-1)
	}

	sid, err := localMSPV143.GetDefaultSigningIdentity()
	if err != nil {
		fmt.Printf("get signing identity failed: %s", err)
		os.Exit(-1)
	}
	sig, err := sid.Sign([]byte("hello world"))
	if err != nil {
		fmt.Printf("sign failed: %s", err)
		os.Exit(-1)
	}
	fmt.Printf("%2x\n", sig)


	err = sid.Verify([]byte("hello world"), sig)
	if err != nil {
		fmt.Println("verify false")
	}
	fmt.Println("verify true")
}
