import { expect } from "chai";
import { ethers } from "ethers";

describe("ProxyFactory", function () {
    let ProxyFactory;
    let proxyFactory: any;
    let UniversalProxyImplementation;
    let universalProxyImplementation: any;
    let owner: any;
    let proxyAddress: string;
    let implementationAddress: string;
    let universalProxyImplementationAbi: any[];

    // Predefined addresses and salt
    const salt = '0x1234512345123451234512345123451234512345123451234512345123451234';
    const ownerAccount = '0x19198342d5b320fbfe5d19ed33bc586c7027ef3f';
    // const contractArgs: any = [masterAccount];

    before(async function () {
        // Deploy the ProxyFactory contract
        ProxyFactory = await ethers.getContractFactory("ProxyFactory");
        proxyFactory = await ProxyFactory.deploy(); // Deploy without constructor arguments
        await proxyFactory.deployed(); // Wait for the deployment to complete

        // Deploy the UniversalProxyImplementation contract
        UniversalProxyImplementation = await ethers.getContractFactory("UniversalProxyImplementation");
        universalProxyImplementation = await UniversalProxyImplementation.deploy(); // Deploy without constructor arguments
        await universalProxyImplementation.deployed(); // Wait for deployment to complete

        // Get the ABI for the deployed UniversalProxyImplementation contract
        universalProxyImplementationAbi = UniversalProxyImplementation.interface.fragments;

        // Get the address of the deployed contract
        implementationAddress = universalProxyImplementation.address;
        console.log('Implementation Address: ', implementationAddress);

        // Get the signers (accounts) available in the Remix/Hardhat environment
        [owner] = await ethers.getSigners();
    });

    it("should execute transaction successfully", async function () {
        // Define the transaction parameters
        let txData = {
            to: '0x23e24e89ab595de928083059c676d32c4367f6d5', // Receiver address
            value: '0x0', // Transaction value
            data: '0xa9059cbb000000000000000000000000fd5b4625ad353d962257194712a7bd91c12013ab0000000000000000000000000000000000000000000000000000000000000064', // Encoded function call
            nonce: 0n // Transaction nonce
        };
        let computedSignature = '0x6fbf5030df885b5ddf29b0549cccbbb7d23b1073e645e33cdaf4f32700d043a476235caff5883e045c3e6f549d3462ae45dee831138abfeb353001d6363911e11c';

        // Compute the address where the proxy will be deployed
        const computedAddress = await proxyFactory.computeAddress(ownerAccount, implementationAddress, salt);
        console.log('computedAddress: ', computedAddress);

        // Listen for the ProxyCreated event and capture the proxy address
        let proxyAddressPromise = new Promise((resolve, reject) => {
            proxyFactory.on("ProxyCreated", (proxyAddress: any, owner: any, implementation: any, event: any) => {
                console.log(`ProxyCreated event: ProxyAddress=${proxyAddress}, Owner=${owner}, Implementation=${implementation}`);
                resolve(proxyAddress);
            });
        });

        console.log('ownerAccount: ', ownerAccount);
        
        // Create the proxy contract
        const tx = await proxyFactory.createProxy(ownerAccount, implementationAddress, salt);
        const receipt = await tx.wait(); // Wait for the transaction to be mined

        // Get the proxy address from the event
        proxyAddress = await proxyAddressPromise as string;
        console.log('proxyAddress: ', proxyAddress);

        // Initialize the proxy contract
        const initProxyTx = await proxyFactory.initializeProxy(proxyAddress, ownerAccount);
        const initReceipt = await initProxyTx.wait();

        // Get the contract instance at the proxy address
        const contract = await ethers.getContractAt(universalProxyImplementationAbi, proxyAddress);

        // Set up event listeners for logging
        contract.on("LogSigner", (signer) => {
            console.log("log signer: ", signer.toString());
        });
        contract.on("LogSender", (signer) => {
            console.log("log sender: ", signer.toString());
        });
        contract.on("LogOwner", (signer) => {
            console.log("log owner: ", signer.toString());
        });
        contract.on("LogHash", (signer) => {
            console.log("log hash: ", signer.toString());
        });
        contract.on("LogTo", (signer) => {
            console.log("log to: ", signer.toString());
        });
        contract.on("LogValue", (signer) => {
            console.log("log value: ", signer.toString());
        });
        contract.on("LogData", (signer) => {
            console.log("log data: ", signer.toString());
        });
        contract.on("LogNonce", (signer) => {
            console.log("log nonce: ", signer.toString());
        });
        contract.on("LogSignature", (signer) => {
            console.log("log signature: ", signer.toString());
        });
        contract.on("TransactionExecuted", (to, value, data) => {
            console.log("TransactionExecuted: ", to.toString(), value.toString(), data.toString());
        });

        // Execute the transaction on the proxy contract
        console.log("txData.to: ", txData.to);
        console.log("txData.value: ", txData.value);
        console.log("txData.data: ", txData.data);
        console.log("txData.nonce: ", txData.nonce);
        console.log("computedSignature: ", computedSignature);

        const txExecution = await contract.executeTransaction(
            txData.to,
            txData.value,
            txData.data,
            txData.nonce,
            computedSignature
        );
        console.log('txExecution: ', txExecution);

        const receiptExecution = await txExecution.wait(); // Wait for the transaction to be mined
        console.log('receiptExecution: ', receiptExecution);

        // Check that the nonce was correctly incremented
        expect(await contract.nonces(txExecution.from)).to.equal(1);
    });
});
