// SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.8;

import "suave-std/suavelib/Suave.sol";
import "suave-std/Transactions.sol";
import "suave-std/Suapp.sol";
import "suave-std/Context.sol";
import "suave-std/protocols/EthJsonRPC.sol";
import "solady/src/utils/JSONParserLib.sol";

contract TransactionSigning is Suapp {
    using JSONParserLib for *;
    using Transactions for *;

    // Define the Infura API URL as a constant or state variable
    string public constant INFURA_URL = "https://sepolia.infura.io/v3/93302e94e89f41afafa250f8dce33086";

    Suave.DataId signingKeyBid;
    string public KEY_PRIVATE_KEY = "KEY1";

    EthJsonRPC ethJsonRPC;

    // Initialize the EthJsonRPC contract with a hardcoded URL
    constructor() {
        ethJsonRPC = new EthJsonRPC(INFURA_URL);
    }
    // onchain-offchain pattern to register the new private key in the Confidential storage

    function updateKeyCallback(Suave.DataId _signingKeyBid) public {
        signingKeyBid = _signingKeyBid;
    }

    function registerPrivateKey() public returns (bytes memory) {
        bytes memory keyData = Context.confidentialInputs();

        address[] memory peekers = new address[](1);
        peekers[0] = address(this);

        Suave.DataRecord memory bid = Suave.newDataRecord(0, peekers, peekers, "private_key");
        Suave.confidentialStore(bid.id, KEY_PRIVATE_KEY, keyData);

        return abi.encodeWithSelector(this.updateKeyCallback.selector, bid.id);
    }

    event TransactionIDEmitted(string request);
    event DepositTransactionDetails(address to, uint256 nonce, uint256 value);
    event TransactionData(string b);

    function depositCallback() public emitOffchainLogs {}

    function deposit_transaction(uint256 worst_acceptable_execution_rate) public returns (bytes memory) {
        bytes memory rlpEncodedTransaction = Suave.confidentialInputs();
        emit RLPEncodedTransaction(toHexString(rlpEncodedTransaction));

        Transactions.EIP155 memory eip155Txn1 = Transactions.decodeRLP_EIP155(rlpEncodedTransaction);

        // Declare variables
        uint256 transactionValue;
        address withdrawal_sender_Address;
        bool is_eth_input_asset;

        // Determine transaction type based on value and data length
        if (eip155Txn1.value > 0 && eip155Txn1.data.length < 5) {
            // It's a direct Ethereum transfer
            transactionValue = eip155Txn1.value;
            withdrawal_sender_Address = eip155Txn1.to;
            is_eth_input_asset = true;
        } else if (eip155Txn1.value == 0 && eip155Txn1.data.length == 68) {
            // It's a token transfer
            // Extracting and converting data segments explicitly in memory
            bytes memory dataSegment = new bytes(32);

            // Extracting the address
            for (uint256 i = 0; i < 32; i++) {
                dataSegment[i] = eip155Txn1.data[4 + i];
            }
            withdrawal_sender_Address = address(uint160(uint256(bytes32(dataSegment))));

            // Extracting the value
            for (uint256 i = 0; i < 32; i++) {
                dataSegment[i] = eip155Txn1.data[36 + i];
            }
            transactionValue = uint256(bytes32(dataSegment));
            is_eth_input_asset = false;
        } else {
            // Invalid transaction type or unexpected data format
            revert("Unsupported transaction type or data format.");
        }

        // Use transactionValue and withdrawal_sender_Address for further processing
        emit Number(transactionValue);
        emit Address(withdrawal_sender_Address);
        // Emit transaction data based on type
        if (is_eth_input_asset) {
            emit TransactionData("BUY ETH FOR USDC");
        } else {
            emit TransactionData("BUY USDC FOR ETH");
        }

        string[] memory headers = new string[](1);
        headers[0] = "Content-Type: application/json";

        Suave.HttpRequest memory request = Suave.HttpRequest({
            url: "https://sepolia.infura.io/v3/93302e94e89f41afafa250f8dce33086",
            method: "POST",
            headers: headers,
            body: abi.encodePacked(
                '{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["',
                toHexString(rlpEncodedTransaction),
                '"],"id":11155111}'
            ),
            withFlashbotsSignature: false
        });

        bytes memory response = Suave.doHTTPRequest(request);

        emit TransactionIDEmitted(string(response));

        address withdrawal_recipient_Address = msg.sender;
        uint256 totalAmount;
        uint256 exchange_rate = getBinanceDepth(is_eth_input_asset, transactionValue);

        if (is_eth_input_asset) {
            // For token purchases, multiply by the exchange rate
            totalAmount = (transactionValue * exchange_rate) / 100_000_000_000_000_000_000; // 18 digits for eth<>gwei, 6 digits for ERC-20
        } else {
            // For ETH transfers, divide by the exchange rate
            totalAmount = (transactionValue * 100_000_000_000_000_000_000) / exchange_rate;
        }

        // TODO: check the exchange rate for limit order that may be provided
        emit SimulatedFilledExchangeRate(exchange_rate);

        bytes memory response_tx2 = withdraw_transaction(
            withdrawal_sender_Address, withdrawal_recipient_Address, totalAmount, is_eth_input_asset
        );

        emit TransactionIDEmitted(string(response_tx2));

        return abi.encodeWithSelector(this.depositCallback.selector);
    }

    // -------------------------------------------------------------------

    // offchain-onchain pattern to sign a transaction using the private key stored in the Suapp
    event TxnSignature(bytes32 r, bytes32 s);
    event RLPEncodedTransaction(string rlpEncodedTxn);
    event Nonce(uint256 nonce);
    event Number(uint256 n);
    event Address(address adr);

    function withdraw_transaction(address sender, address recipient, uint256 amount, bool is_eth_input_asset)
        public
        returns (bytes memory)
    {
        // Define the token contract address outside of any conditional logic to ensure it's available when needed
        address tokenContractAddress = 0xF31B086459C2cdaC006Feedd9080223964a9cDdB;

        // Retrieve the signing key using Suave
        bytes memory signingKey = Suave.confidentialRetrieve(signingKeyBid, KEY_PRIVATE_KEY);

        // Get the nonce of the address
        uint256 nonce = ethJsonRPC.nonce(sender);

        // Prepare transaction data
        bytes memory transactionData;
        if (is_eth_input_asset) {
            // Prepare a call to transfer tokens, typically ERC20 `transfer(address to, uint256 value)`
            transactionData = abi.encodeWithSelector(bytes4(keccak256("transfer(address,uint256)")), recipient, amount);
        } else {
            // If ETH transfer, the data field is usually empty
            transactionData = "";
        }

        Transactions.EIP1559Request memory txnWithToAddress = Transactions.EIP1559Request({
            to: is_eth_input_asset ? tokenContractAddress : recipient,
            gas: 210000,
            maxFeePerGas: 11000000000,
            maxPriorityFeePerGas: 11000000000,
            value: is_eth_input_asset ? 0 : amount, // Send 0 value if token transfer
            nonce: nonce,
            data: transactionData,
            chainId: 11155111,
            accessList: ""
        });

        Transactions.EIP1559 memory txn = Transactions.signTxn(txnWithToAddress, string(signingKey));

        bytes memory rlpEncodedTransaction = Transactions.encodeRLP(txn);

        string[] memory headers = new string[](1);
        headers[0] = "Content-Type: application/json";

        Suave.HttpRequest memory request = Suave.HttpRequest({
            url: INFURA_URL,
            method: "POST",
            headers: headers,
            body: abi.encodePacked(
                '{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["',
                toHexString(rlpEncodedTransaction),
                '"],"id":11155111}'
            ),
            withFlashbotsSignature: false
        });

        bytes memory response = Suave.doHTTPRequest(request);

        return response;
    }

    function bytes32ToString(bytes32 _bytes32) public pure returns (string memory) {
        // Creating a buffer that is large enough to hold the string representation of bytes32 (up to 32 bytes)
        bytes memory buffer = new bytes(32);
        uint256 charCount = 0; // Counter for actual characters (non-zero bytes)

        // Iterate over each byte in the bytes32
        for (uint256 i = 0; i < 32; i++) {
            // Only add bytes that are not zero to buffer
            if (_bytes32[i] != 0) {
                buffer[charCount] = _bytes32[i];
                charCount++;
            }
        }

        // Resize the buffer to fit the actual number of non-zero bytes
        bytes memory stringBuffer = new bytes(charCount);
        for (uint256 j = 0; j < charCount; j++) {
            stringBuffer[j] = buffer[j];
        }

        // Convert buffer to a string and return
        return string(stringBuffer);
    }

    function toHexString(bytes memory data) internal pure returns (string memory) {
        bytes memory hexAlphabet = "0123456789abcdef";
        bytes memory str = new bytes(2 + data.length * 2);
        str[0] = "0";
        str[1] = "x";
        for (uint256 i = 0; i < data.length; i++) {
            str[2 + i * 2] = hexAlphabet[uint256(uint8(data[i] >> 4))];
            str[3 + i * 2] = hexAlphabet[uint256(uint8(data[i] & 0x0f))];
        }
        return string(str);
    }

    // --------------------------------------------------------------------------------

    event CentralizedExchangeLiquidityDepthResponse(string price);
    event SimulatedFilledExchangeRate(uint256 amount);

    // State variable to specify the depth of the order book to retrieve in the Binance API call.
    string public order_book_depth = "100";

    // DataId for storing the Binance API key securely using Suave's confidential storage system.
    Suave.DataId centralizedExchangeAPIKey;

    // Public state variable that specifies the namespace key under which the Binance API key is stored in Suave's confidential storage.
    string public CEX_API_KEY = "KEY2";

    function updateAPIKeyCallback(Suave.DataId _centralizedExchangeAPIKey) public {
        centralizedExchangeAPIKey = _centralizedExchangeAPIKey;
    }

    function registerBinanceAPIKey() public returns (bytes memory) {
        bytes memory keyData = Context.confidentialInputs();

        address[] memory peekers = new address[](1);
        peekers[0] = address(this);

        Suave.DataRecord memory api_key = Suave.newDataRecord(0, peekers, peekers, "api_key");
        Suave.confidentialStore(api_key.id, CEX_API_KEY, keyData);

        return abi.encodeWithSelector(this.updateAPIKeyCallback.selector, api_key.id);
    }

    function emitBinanceDepthResponseCallback() public emitOffchainLogs {}

    // Fetches market depth data from Binance API and calculates the average price based on a specified amount.
    function getBinanceDepth(bool is_buy, uint256 totalAmount) public returns (uint256) {
        // Retrieve the API key securely from the confidential storage system.
        bytes memory api_key = Suave.confidentialRetrieve(centralizedExchangeAPIKey, CEX_API_KEY);

        // Construct the API URL dynamically using the order book depth.
        string memory url =
            string(abi.encodePacked("https://api.binance.com/api/v3/depth?symbol=ETHUSDT&limit=", order_book_depth));

        // Assemble HTTP headers, including the API key for authorization.
        string[] memory headers = new string[](2);
        headers[0] = "Content-Type: application/json;charset=utf-8";
        headers[1] = string(abi.encodePacked("X-MBX-APIKEY: ", string(api_key)));

        // Prepare the HTTP request with specified headers and no body (GET request).
        Suave.HttpRequest memory request =
            Suave.HttpRequest({url: url, method: "GET", headers: headers, body: "", withFlashbotsSignature: false});

        // Execute the HTTP request and parse the JSON response.
        bytes memory response = Suave.doHTTPRequest(request);
        JSONParserLib.Item memory item = string(response).parse();

        uint256 accumulatedAmount = 0;
        uint256 accumulatedPrice = 0;

        // Determine whether to process 'asks' or 'bids' based on the transaction type.
        string memory category = is_buy ? '"asks"' : '"bids"';
        uint256 i = 0;

        // Loop through the order book data until the required amount is accumulated.
        while (accumulatedAmount < totalAmount) {
            if (i >= 50) {
                // Limit the number of iterations to avoid excessive gas costs.
                break;
            }

            // Extract and convert price and amount data from the order book entry.
            string memory priceString = trimQuotes(item.at(category).at(i).at(0).value());
            string memory amountString = trimQuotes(item.at(category).at(i).at(1).value());

            uint256 priceUint = stringToUint(priceString); // Convert price from string to uint256.
            uint256 amountUint = stringToUint(amountString); // Convert amount from string to uint256.

            // Adjust the amount if exceeding the needed amount to fulfill the order.
            uint256 amountNeeded = totalAmount - accumulatedAmount;
            if (amountUint > amountNeeded) {
                amountUint = amountNeeded; // Use only the necessary amount to meet the totalAmount.
            }

            accumulatedAmount += amountUint; // Add to the total accumulated amount.
            accumulatedPrice += priceUint * amountUint; // Add to the total price based on the current price.

            // Emit a response if enough liquidity has been found.
            if (accumulatedAmount >= totalAmount) {
                // emit CentralizedExchangeLiquidityDepthResponse("Enough liquidity to fill order on Binance.");
                break;
            }

            i++;
        }

        // Check if the accumulated amount is less than the required amount after processing.
        if (accumulatedAmount < totalAmount) {
            // emit CentralizedExchangeLiquidityDepthResponse("Not enough liquidity to fill the order on Binance.");
        }

        // Calculate the average price by dividing the total price by the total accumulated amount.
        uint256 averagePrice = accumulatedPrice / accumulatedAmount;

        return averagePrice; // Return the average price for the fulfilled amount.
    }

    function stringToUint(string memory s) public pure returns (uint256) {
        bytes memory b = bytes(s);
        uint256 result = 0;
        for (uint256 i = 0; i < b.length; i++) {
            uint256 c = uint256(uint8(b[i]));
            if (c >= 48 && c <= 57) {
                result = result * 10 + (c - 48);
            }
        }
        return result;
    }

    function trimQuotes(string memory input) private pure returns (string memory) {
        bytes memory inputBytes = bytes(input);
        require(
            inputBytes.length >= 2 && inputBytes[0] == '"' && inputBytes[inputBytes.length - 1] == '"', "Invalid input"
        );

        bytes memory result = new bytes(inputBytes.length - 2);

        for (uint256 i = 1; i < inputBytes.length - 1; i++) {
            result[i - 1] = inputBytes[i];
        }

        return string(result);
    }
}
