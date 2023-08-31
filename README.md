```markdown
## MultiSignatureWallet (311 bytes)

The smallest known EIP712 compliant MultiSignatureWallet for the Ethereum Virtual Machine.

## Features:

- Close-To-The-Metal: Easily auditable at the opcode level (easier for formal verification)
- Tiny deployment cost (311 Bytes / 233 opcodes)
- Reduced execution cost (when executing transactions)
- Written with a similar security profile to common multi-signature designs
- Standard Numerical Nonce system to prevent double-spends
- EIP712 Signing Compliant (signing works with all major Ethereum wallets)
- Delegate-Call Enabled
- Specify an unfixed amount of signatories and thresholds
- MIT License; completely open source to do with as you please

## Design

The design of this multi-signature wallet was based around Christian Lundkvist's Simple-Multisig.

[Christian's Wallet](https://github.com/christianlundkvist/simple-multisig)

Our design accomplishes a similar security profile to Christian's simple-multisig for a substantially lower deployment and execution cost.

While this was designed in Yul (an experimental language), the instruction complexity compiled allows us to better understand
what is going on under the hood and thus potentially better verify the wallet's design integrity.

***This wallet has yet to be audited and is experimental.***

## Implementation

The final wallet code can be found in the `MultiSignatureWallet.yul` file.

View it now by copying the Yul code into [Yulit in your browser](https://yulit.surge.sh)!

## Stats

Below are stats comparing Christian's simple-multisig with its Yul implemented counterpart. The results are fairly staggering.

#### Contract Size (bytes):

Christian:   2301 bytes

Nick:        ***311 bytes***

#### Opcodes Used:

Christian:   1926 opcodes

Nick:        ***233 opcodes***

#### Deployment Cost (using 2 Signatories):

Christian:

 transaction cost: 	656197 gas

 execution cost: 	454473 gas

Nick:

 transaction cost: 	***190592 gas***

 execution cost: 	***144616 gas***

## Reference Implementation (Solidity)

Below is a rough design of the Yul implemented version with specific optimizations made. Hashes are pre-computed and tucked into the execution method to avoid expensive storage reads.

```solidity
pragma solidity ^0.5.0;

contract EIP712MultiSig {
    uint256 public nonce;
    uint256 public threshold;
    mapping(address => bool) public isOwner;

    function () external payable {}

    constructor(address[] memory owners, uint256 requiredSignatures) public {
        threshold = requiredSignatures;
        for (uint256 i = 0; i < owners.length; i++)
            isOwner[owners[i]] = true;
    }

    function execute(address dest, bytes calldata data, bytes32[] calldata signatures) external {
        bytes32 hash = keccak256(abi.encodePacked(
          "\x19\x01",
          bytes32(0xb0609d81c5f719d8a516ae2f25079b20fb63da3e07590e23fbf0028e6745e5f2),
          keccak256(abi.encode(0x4a0a6d86122c7bd7083e83912c312adabf207e986f1ac10a35dfeb610d28d0b6, dest, nonce++, data))));

        address prev;

        for (uint256 i = 0; i < threshold; i++) {
            address addr = ecrecover(hash, uint8(signatures[i][31]), signatures[i + 1], signatures[1 + 2]);
            assert(isOwner[addr] == true);
            assert(addr > prev); // check for duplicates or zero value
            prev = addr;
        }

        if(!dest.delegatecall(data)) revert();
    }
}
