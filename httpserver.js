let http = require('http');
let url = require('url');
let ethInteractor = require('./ethInteractor.js');


function processPost(request, response, callback) {
    var queryData = "";
    if(typeof callback !== 'function') return null;
    console.log("incoming connection");

    if(request.method == 'POST') {
        request.on('data', function(data) {
            queryData += data;
            if(queryData.length > 1e6) {
                queryData = "";
                response.writeHead(413, {'Content-Type': 'text/plain'}).end();
                request.connection.destroy();
            }
        });

        request.on('end', function() {
            //request.post = querystring.parse(queryData);
            request.post = queryData;
            callback();
        });

    } else {
        response.writeHead(405, {'Content-Type': 'text/plain'});
        response.end();
    }
}

http.createServer((request, response) => {
    if(request.method == 'POST') {
        processPost(request, response, function() {
            //handle the post request based upon the url
            //let parsedUrl = url.parse(request.url);
            //trim the leading slash
            
            if(request.post){
                    
                let postData = JSON.parse(request.post);
                let command = postData.method;
                console.log("command:",command);
                switch(command) {

                    case 'submitimports' : 
                    //postdata is an array of imports loop through the array of imports
                    ethInteractor.submitImports(postData.params).then((returnData) => {
                        response.write(JSON.stringify(returnData));
                        response.end();
                    });                                        
                    break;   

                    case 'getexports' : ethInteractor.getExports(postData.params).then((returnData) => {
                        response.write(JSON.stringify(returnData));
                        response.end();
                    });
                    break;

                    case 'getinfo' : ethInteractor.getInfo().then((returnData) => {
                        response.write(JSON.stringify(returnData));
                        response.end();
                    });
                    break;

                    case 'getcurrency' : ethInteractor.getCurrency(postData.params).then((returnData) => {
                        response.write(JSON.stringify(returnData));
                        response.end();
                    });
                    break;

                    case 'submitacceptednotarization' : ethInteractor.submitAcceptedNotarization(postData.params.pBaasNotarization,postData.params.pBaasNotarizationHash,postData.params.signatures).then((returnData) => {
                        response.write(JSON.stringify(returnData));
                        response.end();
                    });
                    break;

                    case 'getnotarizationdata' : ethInteractor.getNotarizationData().then((returnData) => {
                        response.write(JSON.stringify(returnData));
                        response.end();
                    });
                    break;   

                    case 'getbestproofroot' : ethInteractor.getBestProofRoot(postData.params).then((returnData) => {
                        response.write(JSON.stringify(returnData));
                        response.end();
                    });
                    break;   

                    case 'getlastimportfrom' : ethInteractor.getLastImportFrom().then((returnData) => {
                        response.write(JSON.stringify(returnData));
                        response.end();
                    });
                    break;   

                    default:
                        console.log("invalid command: " + command);
                        response.writeHead(404,"Invalid Command",{'Content-Type': 'application/json'});
                        response.end();
                }
            }
            response.writeHead(200, "OK", {'Content-Type': 'application/json'});
            
        });
    } else {
        response.writeHead(200, "OK", {'Content-Type': 'application/json'});
        response.end();
    }

}).listen(8000);
