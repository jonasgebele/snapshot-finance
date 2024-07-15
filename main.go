package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/flashbots/suapp-examples/framework"
	"golang.org/x/crypto/sha3"
)

func createSignedTokenTransfer(client *ethclient.Client, privateKey *ecdsa.PrivateKey, nonce uint64, toAddress common.Address, tokenAddress common.Address, amount *big.Int) (*types.Transaction, error) {
    value := big.NewInt(0)
    gasPrice, err := client.SuggestGasPrice(context.Background())
    if err != nil {
        return nil, err
    }

    transferFnSignature := []byte("transfer(address,uint256)")
    hash := sha3.NewLegacyKeccak256()
    hash.Write(transferFnSignature)
    methodID := hash.Sum(nil)[:4]

    paddedAddress := common.LeftPadBytes(toAddress.Bytes(), 32)
    paddedAmount := common.LeftPadBytes(amount.Bytes(), 32)

    var data []byte
    data = append(data, methodID...)
    data = append(data, paddedAddress...)
    data = append(data, paddedAmount...)

    gasLimit := uint64(2000000)

    tx := types.NewTransaction(nonce, tokenAddress, value, gasLimit, gasPrice, data)
    signedTx, err := types.SignTx(tx, types.HomesteadSigner{}, privateKey)
    if err != nil {
        return nil, err
    }

    return signedTx, nil
}

// createTransaction creates a normal Ethereum transaction and returns the RLP encoded transaction as a hex string.
func createTransaction(client *ethclient.Client, privateKey *ecdsa.PrivateKey, toAddress common.Address, value *big.Int) (string, error) {
    // Convert the private key into a public key and then to an Ethereum address
    publicKey := privateKey.Public()
    publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
    if !ok {
        return "", fmt.Errorf("cannot cast public key to ECDSA")
    }
    fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

    // Retrieve the current nonce for the sender's address
    nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
    if err != nil {
        return "", fmt.Errorf("failed to get nonce: %v", err)
    }

    // Get the current recommended gas price from the Ethereum network
    gasPrice, err := client.SuggestGasPrice(context.Background())
    if err != nil {
        return "", fmt.Errorf("failed to suggest gas price: %v", err)
    }

    // Define the transaction parameters
    gasLimit := uint64(21000) // Typical gas limit for a simple ETH transfer

    // Create the transaction
    tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, nil)

    // Obtain the network's chain ID
    chainID, err := client.NetworkID(context.Background())
    if err != nil {
        return "", fmt.Errorf("failed to get chain ID: %v", err)
    }

    // Sign the transaction using the provided private key
    signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
    if err != nil {
        return "", fmt.Errorf("failed to sign transaction: %v", err)
    }

    // Encode the signed transaction into RLP format
    var buf bytes.Buffer
    err = signedTx.EncodeRLP(&buf)
    if err != nil {
        return "", fmt.Errorf("failed to encode transaction: %v", err)
    }
    rawTxHex := hex.EncodeToString(buf.Bytes())

    return rawTxHex, nil
}

func main() {
	// Connect to the Ethereum client
	client, err := ethclient.Dial("https://sepolia.infura.io/v3/93302e94e89f41afafa250f8dce33086")
	if err != nil {
		log.Fatalf("failed to connect to the Ethereum client: %v", err)
	}

	// Load Suapp user info
    suappUserPrivateKey, err := crypto.HexToECDSA("XXX")
    if err != nil {
        log.Fatalf("failed to load Suapp user private key: %v", err)
    }
    suappUserPublicKey := suappUserPrivateKey.Public()
    suappUserPublicKeyECDSA, _ := suappUserPublicKey.(*ecdsa.PublicKey)
    suappUserAddress := crypto.PubkeyToAddress(*suappUserPublicKeyECDSA)

	// Load liquidity provider info
    liquidityProviderPrivateKey, err := crypto.HexToECDSA("X")
    if err != nil {
        log.Fatalf("failed to load liquidity provider private key: %v", err)
    }
    liquidityProviderPublicKey := liquidityProviderPrivateKey.Public()
    liquidityProviderPublicKeyECDSA, _ := liquidityProviderPublicKey.(*ecdsa.PublicKey)
    liquidityProviderAddress := crypto.PubkeyToAddress(*liquidityProviderPublicKeyECDSA)

	// Display addresses
    fmt.Println("Suapp User Address:", suappUserAddress.Hex())
    fmt.Println("Liquidity Provider Address:", liquidityProviderAddress.Hex())

	// Initialize the framework
    fr := framework.New()

    // Deploy the contract using the framework's deployment utility
    contract := fr.Suave.DeployContract("transaction-signing.sol/TransactionSigning.json")
    
	// 1
    // Register the Binance API Key with the contract to fetch prices
    api_key := "X"
    contract.SendConfidentialRequest("registerBinanceAPIKey", nil, []byte(api_key))

	// 2
	// Send the private key of the liquidity provider as a confidential reques
	private_key := "X"
	contract.SendConfidentialRequest("registerPrivateKey", nil, []byte(private_key))

	// 3
	// User sends RLP encoded Transaction to the SUAPP

	// ------------------------------------------------------------------
	nonce, err := client.PendingNonceAt(context.Background(), suappUserAddress)
    if err != nil {
        log.Fatal(err)
    }

	// https://stg.secured.finance/faucet/
    toAddress := common.HexToAddress("0xb8b255a975db5da46A7965364797876878808de1")
    tokenAddress := common.HexToAddress("0xF31B086459C2cdaC006Feedd9080223964a9cDdB")
    amount := new(big.Int)
    amount.SetString("100000000", 10) // 1 token

    signedTx, err := createSignedTokenTransfer(client, suappUserPrivateKey, nonce, toAddress, tokenAddress, amount)
    if err != nil {
        log.Fatal(err)
    }

	// Encode the transaction to RLP
	ts := types.Transactions{signedTx}
	b := new(bytes.Buffer)
	ts.EncodeIndex(0, b)
	rawTokenTxBytes := b.Bytes()
	rawTokenTxHex := hex.EncodeToString(rawTokenTxBytes)

	fmt.Printf(rawTokenTxHex)
	// ---------------------------------------------------------------------------


	// Set the value to transfer (0.01 ETH in wei)
	value := big.NewInt(1e16)

	// Create and send the deposit transaction
	rawDepositTxHex, err := createTransaction(client, suappUserPrivateKey, liquidityProviderAddress, value)
	if err != nil {
		log.Fatalf("Error creating transaction: %v", err)
	}
	fmt.Printf("Raw RLP Encoded Deposit Transaction Hex: %s\n", rawDepositTxHex)

	// Decode the RLP-encoded transaction hex string to bytes
	rawTxBytes, err := hex.DecodeString(rawDepositTxHex)
	if err != nil {
		log.Fatalf("Failed to decode raw transaction: %v", err)
	}
	fmt.Println(rawTxBytes)

	// Set minimum received amount for the transaction
	minReceived := big.NewInt(12345)

	// Prepare arguments for the confidential request
	args := []interface{}{minReceived}

	// Send RLP encoded transaction to the SUAPP via a confidential request
	receipt := contract.SendConfidentialRequest("deposit_transaction", args, rawTxBytes)




	RLPEncodedInputTransactionEvent, err := contract.Abi.Events["RLPEncodedTransaction"].ParseLog(receipt.Logs[0])
	if err != nil {
		log.Fatal(err)
	}
	r := RLPEncodedInputTransactionEvent["rlpEncodedTxn"].(string)
	fmt.Println("[EMIT] - RLP encoded Transaction as input: ", r)

	InputAmountEvent, err := contract.Abi.Events["Number"].ParseLog(receipt.Logs[1])
	if err != nil {
		log.Fatal(err)
	}
	input_amount := InputAmountEvent["n"].(*big.Int)
	fmt.Println("[EMIT] - Amount of Input Transaction: ", input_amount)

	InputTransactionAddressEvent, err := contract.Abi.Events["Address"].ParseLog(receipt.Logs[2])
	if err != nil {
		log.Fatal(err)
	}
	input_to_address := InputTransactionAddressEvent["adr"].(common.Address)
	fmt.Println("[EMIT] - to-Address of Input Transaction: ", input_to_address)



	InputTransactionDataEvent, err := contract.Abi.Events["TransactionData"].ParseLog(receipt.Logs[3])
	if err != nil {
		log.Fatal(err)
	}
	input_data := InputTransactionDataEvent["b"].(string)
	fmt.Println("[EMIT] - Data of Input Transaction: ", input_data)



	EmmittedDepositTransactionEvent, err := contract.Abi.Events["TransactionIDEmitted"].ParseLog(receipt.Logs[4])
	if err != nil {
		log.Fatal(err)
	}
	emitted_deposit_transaction := EmmittedDepositTransactionEvent["request"].(string)
	fmt.Println("[EMIT] - Deposit Txn: ", emitted_deposit_transaction)

	SimulatedFilledExchangeRateEvent, err := contract.Abi.Events["SimulatedFilledExchangeRate"].ParseLog(receipt.Logs[5])
	if err != nil {
		log.Fatal(err)
	}
	emitted_exchange_rate := SimulatedFilledExchangeRateEvent["amount"].(*big.Int)
	fmt.Println("[EMIT] - Deposit Txn Amount: ", emitted_exchange_rate)

	EmmittedWithdrawalTransactionEvent, err := contract.Abi.Events["TransactionIDEmitted"].ParseLog(receipt.Logs[6])
	if err != nil {
		log.Fatal(err)
	}
	emitted_withdrawal_transaction := EmmittedWithdrawalTransactionEvent["request"].(string)
	fmt.Println("[EMIT] - Withdrawal Txn: ", emitted_withdrawal_transaction)

}

// Bundle both transactions! instead of market maker address call an contract function/ coinbase transfer
