let testInt = Number("589588163014388130691800328414111854848014617344").toString(16);

uint160ToVAddress = (number,version) => {
    let ashex = Number(number).toString(16);
    return(bitGoUTXO.address.toBase58Check(Buffer.from(ashex,'hex'),version));
}

