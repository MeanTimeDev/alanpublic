// Require Web3 Module
const Web3 = require('web3');
const BigNumber = require('bignumber.js');
const bitGoUTXO = require('bitgo-utxo-lib');
const fs = require('fs');
const homedir = require('os').homedir();

/*** variable to be put in veth.conf */
// Show web3 where it needs to look for the Ethereum node

const verusBridgeAddress = "0x035AEC167Cc97dCEF285dAd39953fd80D439D027";
const verusBridgeAbi = require('./VerusBridgeAbi.json');
const verusBridgeStartBlock = 	8578897;
 
const verusNotarizerAddress = "0xe2aA88A01F37fFB54884D26f77888d3C0DEA81A4";
const verusNotarizerAbi = require('./VerusNotarizerAbi.json');

const ethVerusUint160 = "000000000000000000000000000000000000000";
const testnet = true;
const privateKey = !!!eth private key!!!;
const ETHSystemID = '000000000000000000000000000000000000000';
const VerusSystemID = 'iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq'; //vrsctest id
//let VETHCurrencyID = '000000000000000000000000000000000000000';
const VETHCurrencyID = 'iCtawpxUiCc2sEupt7Z4u8SDAncGZpgSKm'
const ethNode = !!!rinkeby node!!!;

//constaants for converting uint160 to iaddress
const IAddress = 102;

const port = 8000;

/*** end of variable for veth.conf */

const web3 = new Web3(new Web3.providers.WebsocketProvider(ethNode))
const verusBridge = new web3.eth.Contract(verusBridgeAbi, verusBridgeAddress);
const verusNotarizer = new web3.eth.Contract(verusNotarizerAbi, verusNotarizerAddress);

/* variables to be set in another file */
//load the the configuration file if it doesnt exist create it WIP
//if()
console.log(homedir);
loadConfFile = () => {
    let walletdirectory = "/";
    
    if(process.platform == 'darwin'){
        walletdirectory /= "Library/Application Support/Komodo/pbaas/";
    } else if(process.platform == 'win32') {
        walletdirectory /= homedir;
        walletdirectory /= "%AppData%\Roaming\Komodo\pbaas\\";
    } else {
        //linux
        walletdirectory /= ".komodo/";
    }
    //check if the file exists
    let data = fs.readFileSync(walletdirectory + 'veth.conf')
    console.log(data);
}

convertVerusAddressToEthAddress = (verusAddress) => {
    return "0x"+ bitGoUTXO.address.fromBase58Check(verusAddress).hash.toString('hex');
}


let VerusSystemAddress = convertVerusAddressToEthAddress(VerusSystemID);
let VETHCurrencyAddress = convertVerusAddressToEthAddress(VETHCurrencyID);

/*
console.log("Veth:",VETHCurrencyAddress);
console.log("Verus:",VerusSystemAddress);

console.log("notaries");
console.log(bitGoUTXO.address.fromBase58Check("iAwycBuMcPJii45bKNTEfSnD9W9iXMiKGg").hash.toIn);
console.log("0x",bitGoUTXO.address.fromBase58Check("iAwycBuMcPJii45bKNTEfSnD9W9iXMiKGg").hash.toString('hex'));
console.log("0x",bitGoUTXO.address.fromBase58Check("iKjrTCwoPFRk44fAi2nYNbPG16ZUQjv1NB").hash.toString('hex'));
console.log("0x",bitGoUTXO.address.fromBase58Check("iChhvvuUPn7xh41tW91Aq29ah9FNPRufnJ").hash.toString('hex'));*/

let maxGas = 6000000;

//setup account and put it in the wallet
let account = web3.eth.accounts.privateKeyToAccount(privateKey);
web3.eth.accounts.wallet.add(account);

/**
 * split the full 65 byte array into 
*/
splitSignature = (fullSig) => {
    let vVal = fullSig.substr(0,64);
    let rVal = fullSig.substr(64,64);
    let sVal = fullSig.substr(128,2);
    return {v:vVal,rVal,sVal};
}

splitSignatures = (fullSigs) => {
    let vs = [];
    let rs =[];
    let ss = [];
    for(let i = 0;i<signatures.length;i++){
        let splitSig = splitSignature(signatures[i]);
        vs.push(splitSig.v);
        rs.push(splitSig.r);
        ss.push(splitSig.s);
    }
    return {vsVals:vs,rsVals:rs,ssVals:ss};
}

//processing functions

processPartialTransactionProof = (PTProof) => {
    //first 10 bytes is the number in the array afterwards each 32 bytes is a proof
    let returnArray = [];
    if(typeof PTProof == 'string'){
        if(PTProof.length <= 10) return returnArray;
        //breakdown the 
        while(PTProof.length > 0){
            let proofElement = '0x' + PTProof.substr(0,63);
            returnArray.push(proofElement);
            PTProof = PTProof.substr(64);
        }
        return returnArray;
    } else return false;
}


convertToRAddress = (RAddress) => {
    return "0x" + bitGoUTXO.address.fromBase58Check(RAddress).hash.toString('hex');
 } 

convertToUint256 = (inputNumber) => {
    return new BigNumber(inputNumber * 10e+18);
}

convertToInt64 = (inputNumber) => {
    let coin = 100000000;
    return inputNumber * coin;
}

addBytesIndicator = (input) => {
    return '0x' + input;
}

convertToCurrencyValues = (input) => {
    let keys = Object.keys(input);
    let values = Object.values(input);
    let ccurrency = [];
    for(let i = 0;i < input.length;i++){
        ccurrency.push({currency: keys[i],amount: values[i]});
    }
    return ccurrency;
}

increaseHexByAmount = (hex,amount) => {
    let x = new BigNumber(hex);
    let sum = x.plus(amount);
    let result = '0x' + sum.toString(16);
    return result;
}

processImports = (imports) => {
    imports.forEach((reserveTransferImport) => {
        if(reserveTransferImport.txid != 'undefined') reserveTransferImport.txid = addBytesIndicator(reserveTransferImport.txid);
        if(reserveTransferImport.exportinfo.sourcesystemid != 'undefined') reserveTransferImport.exportinfo.sourcesystemid = processRAddress(reserveTransferImport.exportinfo.sourcesystemid);
        if(reserveTransferImport.exportinfo.destinationsystemid != 'undefined') reserveTransferImport.exportinfo.destinationsystemid = processRAddress(reserveTransferImport.exportinfo.destinationsystemid);
        if(reserveTransferImport.exportinfo.destinationcurrencyid != 'undefined') reserveTransferImport.exportinfo.destinationcurrencyid = processRAddress(reserveTransferImport.exportinfo.destinationcurrencyid);
        //convert totalamounts
        if(reserveTransferImport.exportinfo.totalamounts !='undefined') {
            //convert this to an array so we can process it 
            reserveTransferImport.exportinfo.totalamounts = convertToCurrencyValues(reserveTransferImport.exportinfo.totalamounts);
        }
        //convert totalFees
        if(reserveTransferImport.exportinfo.totalfees !='undefined') {
            //convert this to an array so we can process it 
            reserveTransferImport.exportinfo.totalfees = convertToCurrencyValues(reserveTransferImport.exportinfo.totalfees);
        }
        
        //do we need to process each of the totalamounts and total fees
        //for the transactions to then do the 
        //loop through the transfers and convert the address
        //deserialize the partial transaction proof into an array to make it happy
        if(reserveTransferImport.partialtransactionproof != 'undefined') reserveTransferImport.partialtransactionproof = processPartialTransactionProof(reserveTransferImport.partialtransactionproof);

        reserveTransferImport.transfers.forEach(element => {
            if(element.destination.address != 'undefined') element.destination.address = processRAddress(element.destination.address);
        });
    })
    console.log(imports);
    return imports;
    
}

//ethProof serializer

/*
let proof = {
    "accountProof": [
        "0xf90211a01b577ccee4a1dd64832aeca2a2cfc065bbd72f0f8d492d77a2494135b947c397a074f8cfa9940ba4ab9b0a82bfdf95c53e5617d787a60151af17ef7462c87fdb5ca0d71907c76fc3e4a0d8536158c1e12f48761b6564fd76ec3e35afe7ab9d82887fa0ba5a0e0372495426586437b8fb8c1872d320a61221341dadee9133492c213677a0762cf7df6def3c505252a8662f6f2435c8ae14f2e453a5476edc2c8b8a1174daa095aea6eb8bd14ed0e83f7a04159615bf291453a166165393a52e55dab9a1d536a0386bde5f15be36f4419e0f3b81f1d70e76f25af31dbd1fcbe06f31952f14010ea0be51ee911f247555c97cce71ab313071192413acf02197e069c36c338ea8e151a0d0997af58e035f3284452f3e5af21c6a17c862ccce9e06a1efe42f24b37ef300a04770bda6ed17ac5740b34d3e1178026cb791c750e3ad8b538f32d4248a80dc16a08bc83f448d0b7fa333859cc293172b31e45dabd9b81032a817b4b5778ecf8861a0e5b0cd3f50ad8e3c878b0183197724d2deab7d051da22fbd741cd2940f4aa8a0a0a8d58f70f66a619021078b557c95301b3ebfe4daf95c65e0d06dd39c02c006c1a0249026f95b19f9c77cdf8f12120242f607aa7901269230a03c193640faff1ef0a04443160abaced9f6ac74c462f3cf7795d2ca3fbca105da6440f19aaa16f082d8a07287b94f784794fb6d93816f43b144c1b47d642c9f63bbeb92e39382515b7d7c80",
        "0xf90211a097b0a34b5afbd3739a23f691d5ba92b0a09fd5ce527db990bfb008ac274e3ecfa044083182720f2ea42bde5546a94215163810f453f1bbf6ca9d5d0429f5d5e933a07151cf44fff42a3d72931e9e12c58b6fc62c09d12fa9c98dea017fb2bd115883a0ad7c31a9b45f0ed7fe4415defe5ee879b5223396a248feed0e48e890999a0732a05fb777adaa0d3d5527de4940b67e047047fef18d6d614cf10439a908b1e8fe50a09128120bba15a1f25dad96b3e3feea755bb977ea7edc065f82657cf253bfe33ba0d4e5052a0f41a6c3c5d91fa499fc2c3af1949d180c441b2d04266c0d29577358a0be03bbeaef5c69ccccbf33b8cecae0a7d76530d578601ba4e0ea573c52411a22a00a16b603b49c58104b02b151d1eaa87449b5b98abf6e7603f957826b63f1a148a069427169facd849d9f44c771e8f41d320a663b664042bb87c801327fedf43963a0cfd9130319b1505fcd5bf94e07507907b6625c45c54ae6f9f6a2bd82169171a8a064301f2725786ab78bddcf9e7e351a80b0e81326e281650f78ead6d36a41d9afa015443ef5471c21524570e14d086961e2dc21146381530d1328e709d55c3b66cca0d1ee30c66acbef72971b4db5f0bcdf8fb2ceec4054d80c0c688540f35a79fa7ea08cffac44d19a40e050ac70fd77bb8579c4544b9b4b11345a86631b440b44cdeea0cd260b8594a8819c95773a048df275c97f8e6d47da67af653d1670a31d2ff4d880",
        "0xf90211a0c90c238f21838d92d2ebcb3fd5cca7f047ae85b88cc942369fdd13c2bb48d305a0ccf42a31f238d86cd294fb75e73e59465cc81bdb5c3fd86fc1bd60d00602293aa05bdb9d2336cd01b26fe5a8078de3624da5f662e2324e6db15556bb20787a594ba08e651417f0f382b8b551269548ce5fb133aba592bd37f3425ef82c2112deab15a065595ffb5e10846ca5dcb86a768ca9c2a889c4918b2a4ebbe0329be6b9db16a7a07e395b60b9c5c87cca7de438b86edb4fcecac1474c9656b7705c4571c59ad924a00e198278c6d3c41e152210cf3d5691209f94bcadfbd8ff70fb158ce89e5eff91a0780d97e784f73a9efdfcc4f568dfe5baa10a45a7165b6ea7b8a59d2283ec8cb6a0ac53d31d7ad4e0e83adfa80605e8947ce875da6d1edd2cde437214ace7595831a02fff4b9e51d8dc9b8f5297299b57ce9df70b0737d25ee4c3454b39017429538fa0c1ad4678e876bd6cb08675fb47530261efa49a6a7919c792a9a4d55c3a3e9e09a000948a2c01929b10bde5eb94fa60d6c54a325930e7f0a6948ba50102bdef4f60a08de708b6f9ee63ecc27a9baea0c02ed05b63fe22d17dd6cb5f6cdc2481e95706a029eab1646ce52352b187745e057f12d32aea92fe8fd59fa8f13068b232ffaa19a0703b4ecb7385fcb60a838a4cbc8ff4ed7067fd45a334ee50d249fed9cafb2b09a0205792e1e5b624b2e5f8455d0bf257aa01262a3af194eb4a7996e50b246ff30d80",
        "0xf90211a04100fac8b141d274d8ead905fd8f1a7a275e4db1dc08b0b3c33b4a67492995a7a08c0e7b67db3beb7f1a052484b8f6a62fa961045815def3610451af2a6806df06a0564568ce56f05f8ffbf8f86c220d1f4ebf868c2faa2b04b47b5469b1530234a4a03771e894b9de5612ba61d433e404fb1c4a4061a59d1727929473979af6a05164a007e18427226523fdf375765f06b388d06b26bbe10018434ddfc52a88335e5ccaa0535c5ce20f8d4b17807ccd468d492b4fb0b4042864fc9852a4e73ef793be0afca0f6298fbf41561bd0ebfecb629ccae84db6eedb95d2c67983ed9ccd1ee49a3167a0ed02ab0285640c418be50905f28c11e25eb0566da200c7ea64d6c4d7f4fc10e9a02e4052393dc39cf8a23821cfb8431d27b9887bd5c1246d323428fac6532cb93fa01265f2c466206247c732f6caedd2b7f23ec7d9b480db07664e61738a40d4f520a064eb2c771d683206e8c9f3183d60ef7447750600d0cdd54259192b784432f61ba0a685368bf7044b60481411042c6dd494920f45b6bdbe8b61911f9fee70b4df6da026c208abeec2c87c2f4e67478f3cf67d6779a89a70fc2f4b8242fe0149abd721a0ebb922720d17989f9601a227abadfefd0b2f492389f9a0db0eb967d876a66495a0160f6b3469da708cab9ca8c43b620fca115f42e8f11d4b5e46d3ce6133a60cc6a00df6e108a87e74c2a65abe5b507f48abf792f0efb6baabbf0b0fb2bc197347d480",
        "0xf90211a0378fe5114c03ca74d298cac358ddc16bf8d490a316a3ac2ee63b0f4d07e0426fa04c8e3d9cbcc2cc47945d0631e5066d3230e89c92be2c605059f6ac00e5c3a6b8a086b36f8b3884217dd7206dc848cf2d5cb930a695cfa4ae34287149168eacf881a06e9424d2cc14950023c77a2512074cb5857d29674f0c6c4100528d7e56328af1a089d4f1efc4c75f6f7104cd1c8d76ce12d1a54ba4797f817b247ce3a51ec5dccba0c6c4927f666ea6d3e7a2e781ad7879cbd101183878e1b37fb43713f7ce98b112a09c44a917c4196b799f3c721dd21dc0ed8de455a81f3e2ccfbfff1870d298c94ea021fdbc8e3f3139260428f7bf2e52e7b4692b6b2997b4bdc7949d7990b06641eaa0df6c7e40fece0404399dafe3b9a792459e3119dc976587ffcc2afad26bf2ded6a0cf0e90caaf9475fca1f78fe74a6507cd82ef0488c08caa6103403abc1cd0820aa0084c8f228df5e0a9177965ac05e202ba9d370a655c6a8fac828ebc202eef2eeba06ca25153e590da0b54774c7d734c311db3aaad8c428e1754933f7cd8fc976725a00073b49c4f85dfb7dd212db5f0cec0b2fdb64a3250e5be77cd8f3358a124c3eba01ac17140c0eb0d3ca8cc980b688d04db87cf155b4eef1f37afbd5e0151e957a1a0450471e0c35d76e20434d8f128ad2f4935d09c4f0eed5f92bf771dd95e326922a0b7af52b1ed80416764f3ab460db7081fa9f5f839a7c50ad90aee0462ac5b87ae80",
        "0xf8b18080808080a02406bbdf630c1f99fcb1ade1af21eac6564ce26be8c7389b0aa8c55df4005841a0aa24a8bbb3eecb24cb540316ec51a0deb4a431926a949178c6707dee0fb9e5eb8080a0a9c1330f366e8986080da18870a6988933c83505d851bd6b7278857b3c7f04228080a05bc638d492a4d54efb40a4157a27722498146e11af01d35fa7df60e34776750280a092bd6e06fb5051da5a9a2e1abf64da1d99feb31009bcf2a599b458e8426b8fde8080",
        "0xf87180808080a05f137b10ddfdc97fc55101b889a39f171fdb8db31b492415a0565cfa8f6b02e6a008ef0f84cfcdcf8fa045b126debef00c19e31f6bc033302f771699f535fef3378080808080808080a02463b48e137439cb6165f07056127fc006faddec9a965a9943a12f654dc068748080",
        "0xf86d9d340a0bcd45240574622e0b640f891f286775324b6910c0fb1800da7207b84df84b018702d79883d20000a039397610107e9a7e835fc03ca6626243b04b5042b16dd0c2afac8e8611bd8ebfa08531e2f61103eca2ac1383411a0972f36b33a366006977f1c424f1b55176a155"
    ],
    "address": "0x2f9d2348863F42De47b60674b68a3202375569D0",
    "balance": "800000000000000",
    "codeHash": "0x8531e2f61103eca2ac1383411a0972f36b33a366006977f1c424f1b55176a155",    
    "nonce": "1",
    "storageHash": "0x39397610107e9a7e835fc03ca6626243b04b5042b16dd0c2afac8e8611bd8ebf",
    "storageProof": [
        {
            "key": "0x175b7a638427703f0dbe7bb9bbf987a2551717b34e79f33b5b1008d1fa01dbc",
            "proof": [
                "0xf90211a0f16eea6e5da747c088119e3750d2546b66051913dd05e724d15d82c3bb9944ada062d395f9a3434ed977c3e9cb92070927404764a420556b88d9b97962f315b445a07623163dcec7b6dbed4f942e072d0c9386f46fb5c9a8ec5b8f43502bc35901c0a08386a6c67aeeaf6c56716bd2fce377b089669bf7cbc1dd11fa67e82e0b740d23a043da2c02ba1ec7f58a19ba9d7e5c07126ba82efe126bec35048ee11e0cfdf5f0a05a925452e0420e9c287faa4895e841236cb57d5be96e2e30569c05132fd109ada0d3bfe903cfbe4d476bc7b2b349c1463533b50f86d538ac4d2488237b5437aa27a09627e7da8552370f5b294a01db4680cfbb9713b6c86c791888020f191e763970a09d2b3a9740accdc96571b8070a9e701143c9ba422bec8e4dc5f92704e85ae7d2a0a076183c477494770c45bdea351f6dc8699efdebf773dc317c7a6612fae86faea0b47c72faf39b9d3d106b6c423ec4ae5cbd23adeaee61e0686e3cecd278e5c867a066d7388134268c9fa1c4451d0eab77c1145cb629171f70d3afe765a5be77885fa004ec0d4f1749d2e9215ee53bc87095bb322999ab1a16258830f1ebffe5f1d407a0a1bcc6cfc262eead7c95c80c2ce029df9c5e9464fe47ebbccedb98cdd1617cdfa0b00033f9158306fa0cabb3e48306a642e792d869a48b0a2f34a1616e7f9b4f9ba02c5bd5a5807fd20d4f792e78cbc24e45f99e555a4b731dab1f32aa3a1ec95c8480",
                "0xf851a0661489f0d94e1d58c0a25d54dfe603e1fd9f3fc6df392de29fe9fa15500fbdab808080a0bb05024c9c908ff608776a694bb5e7eabdf7e73270881d89704914799a319b6c808080808080808080808080",
                "0xf8518080808080a07f7fb2c542b8f5de1d2bd1f505ecb06f355552eaa6398002f2f2319dd7932eb580808080a0e6665840220c60fc2b769cf47011322b6708319aa922df2c575b6bda7e8685e3808080808080",
                "0xf8429f3bea1508c7557b93b3e219e777ce8530b60f9f8452ef1c627dbc62b53708fca1a0f99879ff83a66416b97b910c86db48d8d3b5ef067d632e806116caf136a9f811"
            ],
            "value": "0xf99879ff83a66416b97b910c86db48d8d3b5ef067d632e806116caf136a9f811"
        }
    ]
};*/

writeVarInt = (newNumber) => {
    console.log(newNumber);
    //let tmp = Array(Math.floor((sizeofInt(newNumber)*8+6)/7));
    let tmp = [];
    let len = 0;
    while(true){
        tmp[len] = (newNumber & 0x7f) | (len ? 0x80 : 0x00);
        if(newNumber <= 0x7f) break;
        newNumber = (newNumber >> 7 ) -1;
        len++;
    }
    //reverse the array return it as a buffer
    tmp = tmp.reverse();
    return Buffer.from(tmp);
}

readVarInt = (data) => {
    let n = 0;
    let is = Buffer.from(data,'hex');
    let pos = 0;
    while(true) {
        let chData = is.readUInt8(pos); //single char
        pos++;
        n = (n << 7) | (chData & 0x7F);
        if (chData & 0x80)
            n++;
        else
            return n;
    }
}

writeCompactSize = (newNumber) => {
    let outBuffer = Buffer.alloc(1);
    if (newNumber < 253)
    {   
        outBuffer.writeUInt8(newNumber);
    }
    else if (newNumber <= 0xFFFF)
    {   
        outBuffer.writeUInt8(253);
        let secondBuffer = Buffer.alloc(2);
        secondBuffer.writeUInt16LE(newNumber);
        outBuffer = Buffer.concat([outBuffer,secondBuffer]);
    }
    else if (newNumber <= 0xFFFFFFFF)
    {   
        outBuffer.writeUInt8(254);
        let secondBuffer = Buffer.alloc(4);
        secondBuffer.writeUInt32LE(newNumber);        
        outBuffer = Buffer.concat([outBuffer,secondBuffer]);
    }
    else
    {
        outBuffer.writeUInt8(255);
        let secondBuffer = Buffer.alloc(8);
        secondBuffer.writeUInt32LE(newNumber);        
        outBuffer = Buffer.concat([outBuffer,secondBuffer]);
    }
    return outBuffer;
}

removeHexLeader = (hexString) => {
    if(hexString.substr(0,2) == '0x') return hexString.substr(2);
    else return hexString;
}

uint160ToVAddress = (number,version) => {
    let ashex = BigInt(number).toString(16);
    return(bitGoUTXO.address.toBase58Check(Buffer.from(ashex,'hex'),version));
}

ethAddressToVAddress = (ethAddress,version) => {
    return(bitGoUTXO.address.toBase58Check(Buffer.from(removeHexLeader(ethAddress),'hex'),version));
}

writeUInt160LE = (uint160le) => {
    let output = Buffer.alloc(20);
    output.write(String(uint160le));
    return output;
}

writeUInt256LE = (uint256le) => {
    //remove the 0x 
    if(uint256le.substr(0,2) == '0x') uint256le = uint256le.substr(2);
    let output = Buffer.from(uint256le,'hex');
    return output;
}

serializeCCurrencyValueMap = (ccvm) => {
    let encodedOutput = writeCompactSize(ccvm.length);
    //loop through the array
    for(let i = 0; i < ccvm.length; i++){
        console.log("ccvm:",ccvm[i]);
        encodedOutput = Buffer.concat([encodedOutput,writeUInt(ccvm[i].currency,160)]);
        encodedOutput = Buffer.concat([encodedOutput,writeUInt(ccvm[i].amount,64)]);
    }
    return encodedOutput
}

serializeCCurrencyValueMapArray = (ccvmarray) => {
    let encodedOutput = writeCompactSize(ccvmarray.length);
    for (var key in ccvmarray) {
        encodedOutput = Buffer.concat([encodedOutput,writeUInt(key,160)]);
        encodedOutput = Buffer.concat([encodedOutput,writeUInt(ccvmarray[key],64)]);
    }
    return encodedOutput;
}

serializeCTransferDestination = (ctd) => {
    let encodedOutput = writeUInt(ctd.destinationtype,32);
    encodedOutput = writeUInt(ctd.destinationaddress,160);
    return encodedOutput;
}

writeUInt = (uint,uintType) => {
    let outBuffer = null;
    switch (uintType){
        case 16 :
            outBuffer = Buffer.alloc(2);
            outBuffer.writeUInt16LE(uint);
            //writeUInt16LE(uint);
            break;
        case 32 :
            outBuffer = Buffer.alloc(4);
            outBuffer.writeUInt32LE(uint);
            break;
        case 64 :
            outBuffer = Buffer.alloc(8);
            outBuffer.writeBigInt64LE(BigInt(uint));
            break;
        case 160 :
            outBuffer = writeUInt160LE(uint);
            break;
        case 256 :
            outBuffer = writeUInt256LE(uint);
            break;
        default:
            outBuffer = Buffer.alloc(1);
            outBuffer.writeUInt8(uint);          
    }
    return outBuffer;
}

serializeCrossChainExport = (cce) => {

    let encodedOutput = writeUInt(cce.version);
    encodedOutput = Buffer.concat([encodedOutput,writeUInt(cce.flags,16)]);
    encodedOutput = Buffer.concat([encodedOutput,writeVarInt(cce.sourceheightstart)]);
    encodedOutput = Buffer.concat([encodedOutput,writeVarInt(cce.sourceheightend)]);
    encodedOutput = Buffer.concat([encodedOutput,writeUInt(cce.destsystemid,160)]);
    encodedOutput = Buffer.concat([encodedOutput,writeUInt(cce.destcurrencyid,160)]);
    encodedOutput = Buffer.concat([encodedOutput,writeUInt(cce.numinputs,32)]);
    //totalamounts CCurrencyValueMap
    encodedOutput = Buffer.concat([encodedOutput,serializeCCurrencyValueMap(cce.totalamounts)]);
    //totalfees CCurrencyValueMap
    encodedOutput = Buffer.concat([encodedOutput,serializeCCurrencyValueMap(cce.totalfees)]);
    //hashtransfers uint256
    encodedOutput = Buffer.concat([encodedOutput,writeUInt(cce.hashtransfers,256)]);
    //totalburned CCurrencyValueMap
    encodedOutput = Buffer.concat([encodedOutput,serializeCCurrencyValueMap(cce.totalburned)]);
    encodedOutput = Buffer.concat([encodedOutput,writeUInt(cce.rewardaddress,160)]);
    encodedOutput = Buffer.concat([encodedOutput,writeUInt(cce.firstinput,32)]);
    return encodedOutput;
}

serializeCReserveTransfers = (crts) => {

    let encodedOutput = writeCompactSize(crts.length);
    for(let i = 0;i < crts.length; i++){
        encodedOutput = Buffer.concat([encodedOutput,writeVarInt(crts[i].version)]);
        encodedOutput = Buffer.concat([encodedOutput,serializeCCurrencyValueMap(crts[i].currencyvalues)]);
        encodedOutput = Buffer.concat([encodedOutput,writeVarInt(crts[i].flags)]);
        encodedOutput = Buffer.concat([encodedOutput,writeUInt(crts[i].feecurrencyid,160)]);
        encodedOutput = Buffer.concat([encodedOutput,writeUInt(crts[i].fees,256)]);
        encodedOutput = Buffer.concat([encodedOutput,serializeCTransferDestination(crts[i].destination)]);
        encodedOutput = Buffer.concat([encodedOutput,writeUInt(crts[i].destinationcurrencyid,160)]);
        encodedOutput = Buffer.concat([encodedOutput,writeUInt(crts[i].secondreserveid,160)]);
        encodedOutput = Buffer.concat([encodedOutput,writeUInt(crts[i].destinationsystemid,160)]);
    }
    return encodedOutput;
}

//takes in an array of proof strings and serializes
serializeEthProof = (proofArray) => {
    if(proofArray === undefined) return null;
    let encodedOutput = writeVarInt(proofArray.length);
    //loop through the array and add each string length and the sstring
    //serialize account proof
    for(let i = 0;i < proofArray.length; i++){
        //remove the 0x at the start of the string
        let proofElement = removeHexLeader(proofArray[i]);
        encodedOutput = Buffer.concat([encodedOutput,writeCompactSize(proofElement.length/2)]);
        encodedOutput = Buffer.concat([encodedOutput,Buffer.from(proofElement,'hex')]);
    }
    return encodedOutput;
}

serializeEthStorageProof = (storageProof) => {
    let key = removeHexLeader(storageProof.key);
    if(key.length % 2 != 0) key = '0'.concat(key);
    let encodedOutput = Buffer.from(key,'hex');
    encodedOutput = Buffer.concat([encodedOutput,serializeEthProof(storageProof.proof)]);
    let valueBuffer = Buffer.from(removeHexLeader(storageProof.value),'hex');
    encodedOutput = Buffer.concat([encodedOutput,valueBuffer]);
    return encodedOutput;
}

serializeEthFullProof = (ethProof) => {
    let encodedOutput = Buffer.alloc(1);
    let version = 1;
    encodedOutput.writeUInt8(version);


    let type = 3; //type eth
    let typeBuffer = Buffer.alloc(1);
    typeBuffer.writeUInt8(type);
    encodedOutput = Buffer.concat([encodedOutput,typeBuffer]);
    //write accountProof length
    //proof size as an int 32
    let sizeBuffer = Buffer.alloc(4);
    sizeBuffer.writeUInt32LE(1);
    encodedOutput = Buffer.concat([encodedOutput,sizeBuffer]);

    let branchTypeBuffer = Buffer.alloc(1);
    branchTypeBuffer.writeUInt8(4); //eth branch type
    encodedOutput = Buffer.concat([encodedOutput,branchTypeBuffer]);
    //merkle branch base
    encodedOutput = Buffer.concat([encodedOutput,branchTypeBuffer]);

    //serialize account proof
    encodedOutput = Buffer.concat([encodedOutput,serializeEthProof(ethProof.accountProof)]);
    //serialize address bytes 20
    encodedOutput = Buffer.concat([encodedOutput,Buffer.from(removeHexLeader(ethProof.address),'hex')]);
    let balanceBuffer = Buffer.alloc(8);
    balanceBuffer.writeBigUInt64LE(BigInt(ethProof.balance));
    
    encodedOutput = Buffer.concat([encodedOutput,balanceBuffer]);
    //serialize codehash bytes 32
    encodedOutput = Buffer.concat([encodedOutput,Buffer.from(removeHexLeader(ethProof.codeHash),'hex')]);
    //serialize nonce as uint32
    
    encodedOutput = Buffer.concat([encodedOutput,writeVarInt(ethProof.nonce)]);
    //serialize storageHash bytes 32
    encodedOutput = Buffer.concat([encodedOutput,Buffer.from(removeHexLeader(ethProof.storageHash),'hex')]);
    
    //loop through storage proofs
    for(let i = 0;i < ethProof.storageProof.length; i++){
        encodedOutput = Buffer.concat([encodedOutput,serializeEthStorageProof(ethProof.storageProof[i])]);
    }
    //append 12 0s to the end of the buffer to override the component part of the Proof
    encodedOutput = Buffer.concat([encodedOutput,Buffer.from('000000000000','hex')]);
    return encodedOutput;
}


getBlock = async (input) => {
    try{
        let block = await web3.eth.getBlock(input.blockHeight);
        return block;
    } catch(error){
        return {status:false,error:error};
    }
    
}

/** get Proof for **/
getProof = async (eIndex,blockHeight) => {
    let index = "0x000000000000000000000000000000000000000000000000000000000000000B"; 
    let key = web3.utils.sha3(index,{"encoding":"hex"});
    if(eIndex > 0){
        key = increaseHexByAmount(key,eIndex);
    }
    try{
        //let storedValue = await web3.eth.getStorageAt(verusBridgeAddress,key); 
        let proof = await web3.eth.getProof(verusBridgeAddress,[key],blockHeight);
        return proof;
    } catch(error){
        console.log("error:",error);
        return {status:false,error:error};
    }
}

// create the component parts for the proof

createComponents = (transfers,hash,blockHeight) => {

    let cce = createCrossChainExport(transfers,hash,blockHeight);
    //Var Int Components size as this can only 
    let encodedOutput = writeCompactSize(1);
    //eltype
    encodedOutput = Buffer.concat([encodedOutput,writeUInt(7,16)]);
    //elIdx
    encodedOutput = Buffer.concat([encodedOutput,writeUInt(0,16)]);
    //elVchObj
    let exportKey = "f2b2f628b4a942de8712bc3f9d5459e577332c2c";
    let serialized = Buffer.from(exportKey,'hex');
    let version = 1;
    serialized = Buffer.concat([serialized,writeUInt(version,1)]);
    let twoDVectorSize = 1;
    serialized = Buffer.concat([serialized,writeUInt(twoDVectorSize,1)]);
    serialized = Buffer.concat([serialized,serializeCrossChainExport(cce)]);
    serialized = Buffer.concat([serialized,serializeCReserveTransfers(transfers)]);
    
    encodedOutput = Buffer.concat([encodedOutput,writeCompactSize(serialized.length)]);
    encodedOutput = Buffer.concat([encodedOutput,serialized]);
    return encodedOutput;

}
//create an outbound trans
createOutboundTransfers = (transfers) => {
    let outTransfers = [];
    for(let i = 0; i< transfers.length; i++){
        let transfer = transfers[i];
        let outTransfer = {};
        outTransfer.version = 1;
        outTransfer.currencyvalues = transfer.currencyvalues;
        outTransfer.flags = transfer.flags;
        outTransfer.crosssystem = true;
        outTransfer.exportto = uint160toVaddress(ETHSystemID,IAddress);
        outTransfer.convert = true;
        outTransfer.feecurrencyid = uint160ToVAddress(transfer.feecurrencyid,IAddress);
        outTransfer.fees = transfer.fees;
        outTransfer.destinationcurrencyid = uint160toVaddress(transfer.destCurrencyID,IAddress);
        outTransfer.destination = {
            "type" : transfer.destination.destinationtype,
            "address" : transfer.destination.destinationaddress
        }
        outTransfers.push(outTransfer);
    }
    return outTransfers;
}

createCrossChainExport = (transfers,hash,blockHeight) => {
    let cce = {};
    cce.version = 1;
    cce.flags = 3;
    cce.sourceheightstart = blockHeight;
    cce.sourceheightend = blockHeight + 1;
    cce.sourcesystemid = ETHSystemID;
    cce.destinationsystemid = VerusSystemID;
    cce.destinationcurrencyid = VETHCurrencyID;
    cce.numinputs = transfers.length;    
    cce.totalamounts = [];
    let totalamounts = [];
    cce.totalfees = [];
    let totalfees = [];
    for(let i = 0; i < transfers.length; i++){
        //sum up all the currencies
        if(totalamounts.indexOf(uint160toVaddress((transfers[i].currencyvalues.currency))) >= 0) totalamounts[uint160toVaddress(transfers[i].currencyvalues.currency)] += transfers[i].currencyvalues.amount;
        else totalamounts[transfers[i].currencyvalues.currency] = transfers[i].currencyvalues.amount;
        if(totalfees.indexOf(uint160toVaddress(transfers[i].feecurrencyid,IAddress)) >= 0) totalfees[uint160toVaddress(transfers[i].feecurrencyid,IAddress)] += transfers[i].fees;
        else totalfees[uint160toVaddress(transfers[i].feecurrencyid)] = transfers[i].fees;
    }
    for (var key in totalamounts) {
        cce.totalamounts.push({"currency":key,"amount":totalamounts[key]});
    }
    for (var key in totalfees) {
        cce.totalfees.push({"currency":key,"amount":totalfees[key]});
    }
    cce.hashtransfers = hash; //hash the transfers
    cce.totalburned = [{"currency":0,"amount":0}];
    cce.rewardaddress = uint160toVaddress(0x0000000000000000000000000000000000000002);
    cce.firstinput = 0;
    return cce;
}

/** core functions */

exports.getInfo = async (input) => {
    //getinfo is just tested to see that its not null therefore we can just return the version
    //check that we can connect to Ethereum if not return null to kill the connection
    try{
        let info = await verusBridge.methods.getinfo().call();
        //clear out the unnecessary array elements
        //info = Object.fromEntries(info);
        //complete tiptime with the time of a block
       //let test = convertWeb3Response(info);
        let returnObject = {
            "version" : info.version,
            "name" : info.name,
            "VRSCversion" : info.VRSCversion,
            "blocks" : info.blocks,
            "tiptime" : info.tiptime,
            "testnet" : info.testnet
        }
        return {"result":returnObject};
    } catch(error){
        return {status:false,error:error};
    }
}

exports.getCurrency = async (input) => {

    try{
        let currency = input[0];
        //convert i address to an eth address
        
        let info = await verusBridge.methods.getcurrency(convertVerusAddressToEthAddress(currency)).call();
        //complete tiptime with the time of a block
        //convert the CTransferDestination
        //convert notary adddresses
        let notaries = [];
        for(let i = 0; i < info.notaries.length; i++){
            notaries[i] = ethAddressToVAddress(info.notaries[i],IAddress);
        }

        let nativecurrencyid = [];
        let returnObject = {
            "version" : info.version,
            "name": info.name,
            //"name": "vETH",
            "currencyid": uint160ToVAddress(info.currencyid,IAddress),
            "parent": uint160ToVAddress(info.parent,IAddress),
            "systemid": uint160ToVAddress(info.systemid,IAddress),
            "notarizationprotocol": info.notarizationprotocol,
            "proofprotocol": info.proofprotocol,
            "nativecurrencyid" : {"destinationaddress": '0x' + BigInt(info.nativecurrencyid.destinationaddress,IAddress).toString(16),"destinationtype": info.nativecurrencyid.destinationtype},
            //"nativecurrencyid" : {"address": info.nativecurrencyid.destinationaddress,"type": info.nativecurrencyid.destinationtype},
            "launchsystemid": uint160ToVAddress(info.launchsystemid,IAddress),
            "startblock": info.startblock,
            "endblock": info.endblock,
            "initialsupply": info.initialsupply,
            "prelaunchcarveout": info.prelaunchcarveout,
            "gatewayid": uint160ToVAddress(info.gatewayid,IAddress),
            "notaries": notaries,
            "minnotariesconfirm" : info.minnotariesconfirm

        };
        console.log("getCurrency Return", returnObject);
        return {"result": returnObject};
    }
    catch(error){
        return {status:false,error:error};
    }
}


/*
"\nArguments\n"
"\"chainname\"                      (string, required)  name/ID of the currency to look for. no parameter returns current chain\n"
"\"heightstart\"                    (int, optional)     default=0 only return exports at or above this height\n"
"\"heightend\"                      (int, optional)     dedfault=maxheight only return exports below or at this height\n"

*/


exports.getExports = async (input) => {
    
    let output = [];
    let chainname = input[0];
    let heightstart = input[1];
    let heightend = input[2];

    try{
        //input chainname should always be VETH
        if(chainname != "VETH") return [];
        if(heightstart > 0 && heightstart < verusBridgeStartBlock) return [];
        //if undefined default to the last block available - 20 and last block available (this might break the node as too many queries)
        if(heightend == undefined) heightend = await web3.eth.getBlockNumber();
        if(heightstart == undefined) heightstart = heightend;
        
        //end block is after startblock
        if(heightstart > 0 && heightend > 0 && heightend < heightstart) return [];
        let exportSets = await verusBridge.methods.getReadyExportsByRange(heightstart,heightend).call();
        
        for(let i = 0;i < exportSets.length; i++){
            //loop through and add in the proofs for each export set and the additional fields
            let exportSet = exportSets[i];
            let outputSet = {};
            outputSet.height = exportSet.blockHeight;
            outputSet.txid = ""; //this is not required for the proof
            outputSet.txoutnum = exportSet.position;
            outputSet.exportinfo = {};

            outputSet.exportinfo.version = 0x80000000;
            outputSet.exportinfo.flags = 3; //What does the flags need to be set to
            outputSet.exportinfo.sourceheightstart = exportSet.blockHeight;
            outputSet.exportinfo.sourceheightend = exportSet.blockHeight;
            outputSet.exportinfo.sourcesystemid = uint160ToVAddress(ETHSystemID,IAddress);
            outputSet.exportinfo.destinationsystemid = uint160ToVAddress(VerusSystemID,IAddress);
            outputSet.exportinfo.destinationcurrencyid = uint160ToVAddress(VerusSystemID,IAddress);
            outputSet.exportinfo.numinputs = exportSet.transfers.length;
            //calculate the totalamounts by summing the CCurrencyValues
            let totalamounts = {};
            let totalfees = {};
            for(let y = 0;y < exportSet.transfers.length;y++){
                let transfer = exportSet.transfers[y];
                console.log("transfer:",transfer);
                if(totalamounts[uint160toVaddress(transfer.currencyvalues.currency,IAddress)]!== undefined){
                    totalamounts[uint160toVaddress(transfer.currencyvalues.currency,IAddress)] += transfer.currencyvalues.amount;
                } else {
                    totalamounts[uint160toVaddress(transfer.currencyvalues.currency,IAddress)] = transfer.currencyvalues.amount;
                }
                if(totalfees[transfer.feecurrencyid]!== undefined){
                    totalfees[transfer.feecurrencyid] += transfer.fees;
                } else {
                    totalfees[transfer.feecurrencyid] = transfer.fees;
                }
            }
            outputSet.exportinfo.totalamounts = totalamounts;
            outputSet.exportinfo.totalfees = totalfees;
            outputSet.exportinfo.hashtransfers = outputSet.exportHash;
            outputSet.exportinfo.totalburned = "";
            outputSet.exportinfo.rewardaddress = "";
            outputSet.exportinfo.firstinput = 0;
            //get teh 
            outputSet.partialtransactionproof = await getProof(exportSet.position,exportSet.blockHeight);
            //serialize the proof
            outputSet.partialtransactionproof = serializeEthFullProof(outputSet.partialtransactionproof).toString('hex');
            outputSet.components = createComponents(exportSet.transfers,exportSet.exportHash,exportSet.blockHeight);
            //build transfer list
            //get the transactions at the index
            outputSet.transfers = createOutboundTransfers(exportSet.transfers);
            //loop through the 
            output.push(outputSet);
        }
        

        return {"result":output};
    }catch(error){
        console.log("input:",input);
        return {status: false,error: error};
    }
}
/*"getbestproofroot '{\"proofroots\":[\"version\":n,\"type\":n,\"systemid\":\"currencyidorname\",\"height\":n,\n"
            "                   \"stateroot\":\"hex\",\"blockhash\":\"hex\",\"power\":\"hex\"],\"lastconfirmed\":n}'\n"
            "\nDetermines and returns the index of the best (most recent, valid, qualified) proof root in the list of proof roots,\n"
            "and the most recent, valid proof root.\n"
"\nArguments\n"
"{\n"
"  \"proofroots\":                  (array, required/may be empty) ordered array of proof roots, indexed on return\n"
"  [\n"
"    {\n"
"      \"version\":n                (int, required) version of this proof root data structure\n"
"      \"type\":n                   (int, required) type of proof root (chain or system specific)\n"
"      \"systemid\":\"hexstr\"      (hexstr, required) system the proof root is for\n"
"      \"height\":n                 (uint32_t, required) height of this proof root\n"
"      \"stateroot\":\"hexstr\"     (hexstr, required) Merkle or merkle-style tree root for the specified block/sequence\n"
"      \"blockhash\":\"hexstr\"     (hexstr, required) hash identifier for the specified block/sequence\n"
"      \"power\":\"hexstr\"         (hexstr, required) work, stake, or combination of the two for most-work/most-power rule\n"
"    }\n"
"  .\n"
"  .\n"
"  .\n"
"  ]\n"
"  \"currencies\":[\"id1\"]         (array, optional) currencies to query for currency states\n"
"  \"lastconfirmed\":n              (int, required) index into the proof root array indicating the last confirmed root"
"}\n"

"\nResult:\n"
"\"bestindex\"                      (int) index of best proof root not confirmed that is provided, confirmed index, or -1"
"\"latestproofroot\"                (object) latest valid proof root of chain"
"\"currencystates\"                 (int) currency states of target currency and published bridges"
*/
exports.getBestProofRoot = async (input) => {
    //loop through the proofroots and check each one
    console.log(input);
    let proofroots = input[0];
    let bestIndex = 0;
    let goodroots = [];
    block = await web3.eth.getBlock("latest");
    if(input.length){
        for(let i=0; i < proofroots.length; i++){
            if(checkProofRoot(proofroots[i].height,proofroots[i].height.stateroot,proofroots[i].blockhash)){
                goodroots.push(i);
                if(proofroots[bestIndex].height < proofroots[i].height) bestIndex = i;
            }
        }
    }
    let CProofRoot = {};
    CProofRoot.version = 1;
    CProofRoot.type = 2;
    CProofRoot.systemid = VerusSystemID;
    CProofRoot.height = block.number;
    CProofRoot.stateroot = block.stateRoot;
    CProofRoot.blockhash = block.hash;
    CProofRoot.power = 0;
    return {bestIndex,CProofRoot};
}

checkProofRoot = async (height,stateroot,blockhash) => {
    let block = await getBlock(height);
    if(block.stateRoot == stateroot && blockhash == hash) return true;
    else return false;
}

//return the data required for a notarisation to be made
exports.getNotarizationData = async () => {

    //create a CProofRoot from the block data
    let block;
    try{
        block = await web3.eth.getBlock("latest");
    }catch(error){
        return {status: false,error: error};
    }
    let Notarization = {};
    Notarization.version  = 1;
    //possibly check the contract exists?
    Notarization.launchconfirmed = true;
    Notarization.launchcomplete = true;
    Notarization.mirror = true;
    //proposer should be set to something else this is just sample data
    Notarization.proposer = {
        "type" : 4,
        "address" : "iPveXFAHwModR7LrvgzxxHvdkKH84evYvT"
    };
    Notarization.currencyid = ETHSystemID;
    Notarization.notarizationheight = block.number;
    Notarization.currencystate = {};
    Notarization.currencystate[ETHSystemID] = {
        "flags" : 0,
        "version" : 1,
        "launchcurrencies" : [{
            "currencyid": 0,
            "weight": 0.00000000,
            "reserves": 1.00000000,
            "priceinreserve": 1.00000000
        }],
        "initialsupply": 0.00000000,
        "emitted": 0.00000000,
        "supply": 0.00000000,
        "currencies": {},
        "primarycurrencyfees": 0.00000000,
        "primarycurrencyconversionfees": 0.00000000,
        "primarycurrencyout": 0.00000000,
        "preconvertedout": 0.00000000
    };
    Notarization.currencystate[ETHSystemID].currencyid = ETHSystemID;
    Notarization.currencystate[ETHSystemID].currencies[ETHSystemID] = {
        "reservein": 0.00000000,
        "primarycurrencyin": 0.00000000,
        "reserveout": 0.00000000,
        "lastconversionprice": 1.00000000,
        "viaconversionprice": 0.00000000,
        "fees": 0.00000000,
        "conversionfees": 0.00000000,
        "priorweights": 0.00000000
    };
    Notarization.currencystate[ETHSystemID].launchcurrencies[0].currencyid = ETHSystemID;
    Notarization.prevnotarizationtxid = "0";
    Notarization.prevnotarizationout = 0;
    Notarization.prevheight = 0;
    
    Notarization.currencystates = [{
        ETHSystemID : {
          "flags": 0,
          "version": 1,
          "currencyid": ETHSystemID ,
          "launchcurrencies": [
            {
              "currencyid": ETHSystemID ,
              "weight": 0.00000000,
              "reserves": 1.00000000,
              "priceinreserve": 1.00000000
            }
          ],
          "initialsupply": 0.00000000,
          "emitted": 0.00000000,
          "supply": 0.00000000,
          "currencies": {
            ETHSystemID : {
              "reservein": 0.00000000,
              "primarycurrencyin": 0.00000000,
              "reserveout": 0.00000000,
              "lastconversionprice": 1.00000000,
              "viaconversionprice": 0.00000000,
              "fees": 0.00000000,
              "conversionfees": 0.00000000,
              "priorweights": 0.00000000
            }
          },
          "primarycurrencyfees": 0.00000000,
          "primarycurrencyconversionfees": 0.00000000,
          "primarycurrencyout": 0.00000000,
          "preconvertedout": 0.00000000
        }
      }];

      let CProofRoot = {};
      CProofRoot.version = 1;
      CProofRoot.type = 2;
      CProofRoot.systemID = ETHSystemID;
      CProofRoot.rootHeight = block.number;
      CProofRoot.stateRoot = block.stateRoot;
      CProofRoot.blockHash = block.hash;
      CProofRoot.compactPower = 0; //not required for an eth proof to my knowledge

      Notarization.proofroots = CProofRoot;
      Notarization.nodes = [];
      Notarization.forks = [[0]];
      Notarization.lastconfirmedheight = 0;
      Notarization.lastconfirmed = 0;
      Notarization.betchain = 0;

      return {"result":Notarization};
}

/** send transactions to ETH 
 * CTransferArray, an array of CTransfer
 * CTransferSet is a CTransferSet
 * proof is an array of bytes32
 * blockheight uint32
 * hashIndex uint32
*/

exports.submitImports = async (CTransferArray) => {
    //need to convert all the base64 encoded addresses back to uint160s to be correcly passed into solidity 
    //checks to 
    try {
        //convert all address to uint160
        //CTransferArray = processImports(CTransferArray);
        let result = await verusBridge.methods.submitImports(CTransferArray).send({from: account.address,gas: maxGas});
        console.log("Result:",result);
        return {status: true};
    } catch(error){
        return {status: false,error: error};
    }
}


exports.submitAcceptedNotarization = async (pBaasNotarization,pBassNotarizationHash,signatures) => {
    let splitSigs = splitSignatures(signatures);
    try{
        let setDataResult = await verusNotarizer.methods.setLatestData(pBaasNotarization,pBassNotarizationHash,splitSigs.vs,splitSigs.rs,splitSigs.ss);
    } catch(error){
        console.log("error:",error);
    }
}
/*
exports.confirmNotarization = async (pBaasNotarizationArray) => {
    //loop through the array and return the most recent valid notarization
    let mostRecentValidIndex = null;
    for(let i = 0;i< pBaasNotarizationArray.length; i++){
        if(pBaasNotarizationArray[i].notarizationHeight > pBaasNotarizationArray[mostRecentValidIndex].notarizationHeight){
            let block = await web3.eth.getBlock(pBaasNotarizationArray[i].notarizationHeight);
            //THIS PART MAY NEED REVISITING WHEN WE GET DATA ASSUMING WE RECEIVE A KEYED 
            //ARRAY REPRESENTATION OF THE currencystate
            if(block.stateRoot == pBaasNotarizationArray[i].proofRoots[ethVerusUint160]) {
                mostRecentValidIndex = i;
            }
        }
    }
    if(mostRecentValidIndex == null) return false;
    else return mostRecentValidIndex;
}*/

//return the data required for a notarisation to be made
exports.getLastImportFrom = async () => {

    //create a CProofRoot from the block data
    let block;
    try{
        block = await web3.eth.getBlock("latest");
    }catch(error){
        return {status: false,error: error};
    }

    let lastimport = {};

    lastimport.version = 1;
    lastimport.flags = 68;
    lastimport.sourcesystemid = VETHCurrencyID;
    lastimport.importcurrencyid = VETHCurrencyID;
    lastimport.valuein = {};
    lastimport.tokensout = {};
    lastimport.numoutputs = {};
    lastimport.hashtransfers = {};
    lastimport.exporttxid = {};
    lastimport.exporttxout = {};
    

    let lastconfirmednotarization = {};

    lastconfirmednotarization.version  = 1;
    //possibly check the contract exists?
    lastconfirmednotarization.launchconfirmed = true;
    lastconfirmednotarization.launchcomplete = true;
    lastconfirmednotarization.mirror = true;
    //proposer should be set to something else this is just sample data
    lastconfirmednotarization.proposer = {
        "type" : 4,
        "address" : "iPveXFAHwModR7LrvgzxxHvdkKH84evYvT"
    };
    lastconfirmednotarization.currencyid = ETHSystemID;
    lastconfirmednotarization.notarizationheight = block.number;
    lastconfirmednotarization.currencystate = {};
    lastconfirmednotarization.currencystate[ETHSystemID] = {
        "flags" : 0,
        "version" : 1,
        "launchcurrencies" : [{
            "currencyid": 0,
            "weight": 0.00000000,
            "reserves": 1.00000000,
            "priceinreserve": 1.00000000
        }],
        "initialsupply": 0.00000000,
        "emitted": 0.00000000,
        "supply": 0.00000000,
        "currencies": {},
        "primarycurrencyfees": 0.00000000,
        "primarycurrencyconversionfees": 0.00000000,
        "primarycurrencyout": 0.00000000,
        "preconvertedout": 0.00000000
    };
    lastconfirmednotarization.currencystate[ETHSystemID].currencyid = ETHSystemID;
    lastconfirmednotarization.currencystate[ETHSystemID].currencies[ETHSystemID] = {
        "reservein": 0.00000000,
        "primarycurrencyin": 0.00000000,
        "reserveout": 0.00000000,
        "lastconversionprice": 1.00000000,
        "viaconversionprice": 0.00000000,
        "fees": 0.00000000,
        "conversionfees": 0.00000000,
        "priorweights": 0.00000000
    };
    lastconfirmednotarization.currencystate[ETHSystemID].launchcurrencies[0].currencyid = ETHSystemID;
    lastconfirmednotarization.prevnotarizationtxid = "0";
    lastconfirmednotarization.prevnotarizationout = 0;
    lastconfirmednotarization.prevheight = 0;
    
    lastconfirmednotarization.currencystates = [{
        ETHSystemID : {
          "flags": 0,
          "version": 1,
          "currencyid": ETHSystemID ,
          "launchcurrencies": [
            {
              "currencyid": ETHSystemID ,
              "weight": 0.00000000,
              "reserves": 1.00000000,
              "priceinreserve": 1.00000000
            }
          ],
          "initialsupply": 0.00000000,
          "emitted": 0.00000000,
          "supply": 0.00000000,
          "currencies": {
            ETHSystemID : {
              "reservein": 0.00000000,
              "primarycurrencyin": 0.00000000,
              "reserveout": 0.00000000,
              "lastconversionprice": 1.00000000,
              "viaconversionprice": 0.00000000,
              "fees": 0.00000000,
              "conversionfees": 0.00000000,
              "priorweights": 0.00000000
            }
          },
          "primarycurrencyfees": 0.00000000,
          "primarycurrencyconversionfees": 0.00000000,
          "primarycurrencyout": 0.00000000,
          "preconvertedout": 0.00000000
        }
      }];

      let CProofRoot = {};
      CProofRoot.version = 1;
      CProofRoot.type = 2;
      CProofRoot.systemid = VerusSystemID;
      CProofRoot.height = block.number;
      CProofRoot.stateroot = block.stateRoot;
      CProofRoot.blockhash = block.hash;
      CProofRoot.power = 0; //not required for an eth proof to my knowledge

      lastconfirmednotarization.proofroots = [];
      lastconfirmednotarization.proofroots[0] = CProofRoot;
      lastconfirmednotarization.nodes = [];
      lastconfirmednotarization.forks = [[0]];
      lastconfirmednotarization.lastconfirmedheight = 0;
      lastconfirmednotarization.lastconfirmed = 0;
      lastconfirmednotarization.betchain = 0;

    let lastconfirmedutxo = {
        "txid": "16736c05a8a28201a3680a4cc0bb7f1d8ac2ca878c358bcde52501328722ebb1",
        "voutnum": 0
        }

        console.log("getCurrency Return", {lastimport,lastconfirmednotarization,lastconfirmedutxo });

      return {"result":{lastimport,lastconfirmednotarization,lastconfirmedutxo }};
}
