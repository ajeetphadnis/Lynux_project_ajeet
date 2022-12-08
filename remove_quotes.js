var subjAttrs = [{
    name: 'commonName',
    value: ''
  }, {
    name: 'countryName',
    value: ''
  }, {
    shortName: 'ST',
  }, {
    name: 'localityName',
    value:  ''                    //newuser.orgName
  }, {
    name: 'organizationName',
    value: ''                     //newuser.orgName
  }, {
    shortName: 'OU',
    value:  ''                   //newuser.nameIdentifier
  }];
  var jwtStr = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpZCI6IjAwREQwMDAwMDAwRjdMNSIsImlzcyI6ImNvbS51dGVzLmludGVybWVkaWF0ZV9jYS1kb21haW4iLCJzdWIiOiIwMEREMDAwMDAwMEY3TDUiLCJhdWQiOiJjb20udXRlcy5pbnRlcm1lZGlhdGVfY2EtZG9tYWluIiwianRpIjoiMTIwLTUxLTIxNi0xMDYtMjQ0LTc0LTE3OC01Mi02MS0xMzkiLCJleHAiOjEyNDUyNjQ2MTAsIm5iZiI6MTI0NTI2NDMxMCwiaWF0IjoxNjYzNjM3NTY5fQ.";
  var data = {"attributes":[{"type":"2.5.4.3","value":"HydroASA","valueTagClass":19,"name":"commonName","shortName":"CN"},{"type":"2.5.4.6","value":"NO","valueTagClass":19,"name":"countryName","shortName":"C"},{"type":"2.5.4.8","value":"HydroASA","valueTagClass":19,"name":"stateOrProvinceName","shortName":"ST"},{"type":"2.5.4.7","value":"Oslo","valueTagClass":19,"name":"localityName","shortName":"L"},{"type":"2.5.4.10","value":"HydroInc","valueTagClass":19,"name":"organizationName","shortName":"O"},{"type":"2.5.4.11","value":"HydroInc","valueTagClass":19,"name":"organizationalUnitName","shortName":"OU"}],"hash":"5363590dd8cb9eb4cc1a317e5bd1f895db41cdee"};
  var valid = {"notBefore":"2022-09-14T15:25:39.000Z","notAfter":"2022-09-15T15:25:39.000Z"};
function removeQuotes() {
    var quotesStr = '"this is a single quote string"';
    //var noquotesStr = quotesStr.replaceAll("^\"|\"$", "");
    var noquotesStr = quotesStr.replaceAll("\"", "");

    console.log(noquotesStr);
}

function convertStr2Date( dtStr) {
    //const event = new Date('14 Jun 2017 00:00:00 PDT');
    const event = new Date(dtStr);
    console.log(event.toUTCString());
    // expected output: Wed, 14 Jun 2017 07:00:00 GMT
}

function convertStr2Seconds(dtStr) {
    const date = new Date(dtStr);
    const seconds = Math.floor(date.getTime() / 1000);
    console.log(seconds); // 👉️ 1650954924
}


function fillArr(subj) {
    if (data.attributes[0].name === 'commonName') {
        //subjAttrs[0].value = data.attributes[0].value;
        //console.log(data.attributes[0].name);
        valid = valid.notBefore+'*'+valid.notAfter;
        console.log(valid);
    }
}

function parseJwt (token, mode) {
  var header = JSON.parse(Buffer.from(token.split('.')[0], 'base64').toString());
  var payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
  //var payload = JSON.parse(Buffer.from(token.split('.')[2], 'base64').toString());
  if (mode == 1) {
    return header.alg+"*"+header.typ;
  } else if (mode == 2) {
    return payload;
  }
}



function getUserDomain(mailAddress) {
  var mailContent = mailAddress.split('@');
  console.log("User name:  " + mailContent[0] +  "      " + mailContent[1]);
  return (mailContent[0]+'*'+mailContent[1])
}

function convertUnixTS2Date(unixStr) {
  const dtf = new Date(unixStr);
  return dtf;
}


//app.listen(3001, () => console.log('Your app listening on port 3000'));

//var ran = getRandomHex(16);
//var ran = parseJwt(jwtStr, 1);
//  1705558908     1405558878
var ran = convertUnixTS2Date(1705558908);
//var ran = getUserDomain('test@example.com');
console.log(ran);

     
//var nbfv = '2014-07-17T01:01:18Z';
//var nafv = '2024-01-18T06:21:48Z';
//convertStr2Date(nbfv);
//convertStr2Seconds(nbfv);
//fillArr(data);