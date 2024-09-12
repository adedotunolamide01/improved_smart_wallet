

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./Universal_Proxy_Implementation.sol";

contract ProxyFactory {
    event ProxyCreated(address proxyAddress, address owner, address implementation);

    function createProxy(address _owner, address _implementation, bytes32 _salt) public returns (address) {
        bytes memory bytecode = abi.encodePacked(type(UniversalProxyImplementation).creationCode, abi.encode(_owner, _implementation));
        address proxyAddress;

        assembly {
            proxyAddress := create2(0, add(bytecode, 0x20), mload(bytecode), _salt)
            if iszero(extcodesize(proxyAddress)) {
                revert(0, 0)
            }
        }

        emit ProxyCreated(proxyAddress, _owner, _implementation);
        return proxyAddress;
    }

    function initializeProxy(address payable proxyAddress, address _owner) public {
        (bool success,) = proxyAddress.call(abi.encodeWithSignature("initialize(address)", _owner));
        require(success, "Initialization failed");
    }

    function computeAddress(address _owner, address _implementation, bytes32 _salt) public view returns (address) {
        bytes memory bytecode = abi.encodePacked(type(UniversalProxyImplementation).creationCode, abi.encode(_owner, _implementation));
        bytes32 hash = keccak256(abi.encodePacked(bytes1(0xff), address(this), _salt, keccak256(bytecode)));
        return address(uint160(uint(hash)));
    }
}