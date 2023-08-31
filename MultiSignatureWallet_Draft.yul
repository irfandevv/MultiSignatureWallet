/**
  * @title MultiSignatureWallet
  * @author Nick Dodson <thenickdodson@gmail.com>
  * @notice 312 byte Weighted EIP712 Signing Compliant Delegate-Call Enabled MultiSignature Wallet for the Ethereum Virtual Machine
  */
object "MultiSignatureWallet" {
  code {
    // constructor: uint256(signatures required) + address[] signatories (bytes32 sep|chunks|data...)
    codecopy(0, 312, codesize()) // setup constructor args: mem positon 0 | code size 280 (before args)

    for { let i := 96 } gt(mload(i), 0) { i := add(i, 32) } { // iterate through signatory addresses, address > 0
        sstore(mload(i), 1) // address => 1 (weight map
    }

    sstore(1, mload(0)) // map contract address => signatures required (moved ahead of user initiated address => weight setting)

    datacopy(0, dataoffset("Runtime"), datasize("Runtime")) // now switch over to runtime code from constructor
    return(0, datasize("Runtime"))
  }
  object "Runtime" {
    code {
        if eq(calldatasize(), 0) {
            mstore(0, callvalue())
            log1(0, 32, caller()) // log caller / value
            stop()
        } // fallback log zero

        // call data: bytes4(sig) bytes32(dest) bytes32(gasLimit) bytes(data) bytes32[](signatures) | supports fallback
        calldatacopy(220, 0, calldatasize()) // copy calldata to memory

        let dataSize := mload(352) // size of the bytes data
        let nonce := sload(0)

        // build EIP712 release hash
        mstore(128, 0x6310997d8ae730b875ec1971d9c8ed1643e462fee32f01134f9275a5370b69d2) // EIP712 Execute TypeHash: Execute(address verifyingContract,uint256 nonce,address destination,uint256 gasLimit,bytes data)
        mstore(160, address()) // use the contract address as salt for replay protection
        mstore(192, nonce) // map wallet nonce to memory (nonce: storage(address + 1)) */
        mstore(288, keccak256(384, dataSize)) // we have to hash the bytes data due to EIP712... why....

        mstore(0, 0x1901)
        mstore(32, 0xb0609d81c5f719d8a516ae2f25079b20fb63da3e07590e23fbf0028e6745e5f2) // EIP712 Domain Seperator: EIP712Domain(string name,string version,uint256 chainId)
        mstore(64, keccak256(128, 192)) // EIP712 Execute() Hash

        let eip712Hash := keccak256(30, 66) // EIP712 final signing hash
        let signatureMemoryPosition := add(224, mload(320)) // new memory position -32 bytes from sig start
        let previousAddress := 1 // comparison variable, used to check for duplicate signer accounts

        for { let i := sload(caller()) } lt(i, sload(1)) { } { // signature validation: loop through signatures (i < required signatures)
            mstore(signatureMemoryPosition, eip712Hash) // place hash before each sig in memory: hash + v + r + s | hash + vN + rN + sN

            let ecrecoverResult := call(3000, 1, 0, signatureMemoryPosition, 128, 96, 32) // call ecrecover precompile with ecrecover(hash,v,r,s) | failing is okay here
            let recoveredAddress := mload(96)

            if or(iszero(ecrecoverResult), or(eq(caller(), recoveredAddress), iszero(gt(recoveredAddress, previousAddress)))) {
                revert(0, 0)
            }
            // ecrecover must be success | recoveredAddress cannot be caller
            // | recovered address must be unique / grater than previous | recovered address must be greater than 1

            previousAddress := recoveredAddress // set previous address for future comparison
            signatureMemoryPosition := add(signatureMemoryPosition, 96)
            i := add(i, sload(recoveredAddress))
        }

        sstore(0, add(1, nonce)) // increase nonce: nonce = nonce + 1

        if iszero(delegatecall(mload(256), mload(224), 384, dataSize, 0, 0)) { revert(0, 0) }
    }
  }
}

/*
==============================
Contract Storage Layout
==============================

0            | Nonce
1            | Required Signatures
[signatory address] => signatory weight

==============================
Constructor Memory Layout
==============================

0     | Signatory Threshold -- uint256 weightedThreshold
32    | Signatory Array Length -- address[] signatories
64    | Number of Signatories -- uint256
96    | First Signatory -- address
+32   | .. N Signatory -- address

==============================
Runtime Memory Layout
==============================

0       | EIP712 Prefix          | 0x1901
32      | Domain Seperator Hash  | keccak256("EIP712Domain(string name,string version,uint256 chainId)")
64      | Execute Hash           |
96      | ECRecovered Address    | ecrecover address
128     | Execute Typehash       | keccak256("Execute(address verifyingContract,uint256 nonce,address destination,uint256 gasLimit,bytes data)")
160     | Contract Address       | address() // used for replay attack prevention
192     | Nonce                  | sload(add(address(), 1)) // used for double spend prevention
224     | Destination            | delegate call target (specified in calldata)
256     | Gas Limit              | delegate call gas limit (specified in calldata)
288     | Hash of Data           | keccak256(of data)
320     | End of Bytes Data      | End of bytes data (specified in calldata)
352     | Data size              | bytes data raw size (specified in calldata)
384     | Bytes Data             | raw bytes data (specified in calldata)
*/
