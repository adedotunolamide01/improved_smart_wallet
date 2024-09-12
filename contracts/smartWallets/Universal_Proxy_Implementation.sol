// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/token/ERC1155/utils/ERC1155HolderUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

// UniversalProxyImplementation contract that can handle ERC1155 tokens and execute signed transactions
contract UniversalProxyImplementation is Initializable, ERC1155HolderUpgradeable {
    // Address of the contract owner
    address public owner;

    // Mapping to store nonces for each address (used for replay protection)
    mapping(address => uint256) public nonces;

    // Events to log various actions and states
    event TransactionExecuted(address indexed to, uint256 value, bytes data);
    event LogSigner(address signer);
    event LogSender(address sender);
    event LogOwner(address owner);
    event LogHash(string hashString);
    event LogTo(address to);
    event LogValue(uint256 value);
    event LogData(bytes data);
    event LogNonce(uint256 nonce);
    event LogSignature(bytes signature);

    // Initialize the contract with the owner's address
    function initialize(address _owner) public initializer {
        owner = _owner;
    }

    // Fallback function to accept ETH transfers
    receive() external payable {}

    // Fallback function to handle arbitrary calls and forward them to the owner
    fallback() external payable {
        require(msg.sender == owner, "Not authorized");
        (bool success, ) = owner.call{value: msg.value}(msg.data);
        require(success, "Call failed");
    }

    // Utility function to convert bytes32 to a string (used for logging hashes)
    function bytes32ToString(bytes32 _bytes32) public pure returns (string memory) {
        bytes memory bytesArray = new bytes(64);
        bytes memory alphabet = "0123456789abcdef";

        for (uint256 i = 0; i < 32; i++) {
            bytes1 byteValue = _bytes32[i];
            uint8 upper = uint8(byteValue >> 4);
            uint8 lower = uint8(byteValue & 0x0F);
            bytesArray[i * 2] = alphabet[upper];
            bytesArray[i * 2 + 1] = alphabet[lower];
        }
        return string(bytesArray);
    }

    // Function to execute a signed transaction
    function executeTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        uint256 nonce,
        bytes calldata signature
    ) external payable {
        // Log transaction details for debugging
        emit LogTo(to);
        emit LogValue(value);
        emit LogData(data);
        emit LogNonce(nonce);
        emit LogSignature(signature);

        // Create a message hash that will be signed off-chain
        bytes32 messageHash = keccak256(abi.encodePacked(to, value, data, nonce));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));

        // Recover the address that signed the message
        address signer = recoverSigner(ethSignedMessageHash, signature);
        emit LogSigner(signer);

        // Ensure that the signer is the owner of the contract
        require(signer == owner, string(abi.encodePacked("Invalid signature ", signer, owner)));

        // Verify the nonce to prevent replay attacks
        require(nonce == nonces[msg.sender], "Invalid nonce");

        // Increment the nonce to prevent reuse
        nonces[msg.sender]++;
        emit LogSender(msg.sender);
        emit LogNonce(nonces[msg.sender]);

        // Execute the transaction and forward any ETH if required
        (bool success, ) = to.call{value: value}(data);
        require(success, "Transaction failed");

        // Log the successful transaction execution
        emit TransactionExecuted(to, value, data);
    }

    // Internal function to recover the signer's address from the signature
    function recoverSigner(bytes32 _ethSignedMessageHash, bytes memory _signature) internal pure returns (address) {
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(_signature);
        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    // Internal function to split a signature into its components (v, r, s)
    function splitSignature(bytes memory sig) internal pure returns (uint8, bytes32, bytes32) {
        require(sig.length == 65, "Invalid signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return (v, r, s);
    }

    // Handle receiving single ERC1155 tokens
    function onERC1155Received(
        address,
        address,
        uint256,
        uint256,
        bytes memory
    ) public virtual override returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    // Handle receiving batch ERC1155 tokens
    function onERC1155BatchReceived(
        address,
        address,
        uint256[] memory,
        uint256[] memory,
        bytes memory
    ) public virtual override returns (bytes4) {
        return this.onERC1155BatchReceived.selector;
    }

    // Support for the ERC1155 interface, enabling compatibility with ERC1155 tokens
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC1155HolderUpgradeable) returns (bool) {
        return ERC1155HolderUpgradeable.supportsInterface(interfaceId);
    }
}
