# Alan

Alan is a node js application passing transactions between Verus and Ethereum blockchains.

To install Alan complete the following steps:

In ethinteractor.js set 
const privatekey to the address of an ethereum wallet on the rinkeby chain with sufficient funds, to provide gas for calls to the rinkeby blockchain.
const ethNode to a websocket address for an Ethereum node on Rinkeby.

(this will change to be in the veth.conf file)

Once set run the following commands:

npm install
node httpserver.js

This will result in the service running on port 8000 it can be queried using the following examples:
 curl  --data-binary '{"jsonrpc":"1.0","id":"curltext","method":"getinfo","params":[]}' -H 'content-type:text/plain;' http://127.0.0.1:8000

curl  --data-binary '{"jsonrpc":"1.0","id":"curltext","method":"getcurrency","params":["iCtawpxUiCc2sEupt7Z4u8SDAncGZpgSKm"]}' -H 'content-type:text/plain;' http://127.0.0.1:8000

