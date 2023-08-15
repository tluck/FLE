// Simple Client-Side Field Level Encryption example for Node.js - Encrypted insert (Step 2)
// Requires key vault setup (Step 1)

// To install:
//  Make sure the mongocryptd binary is on a default path (from the Enterprise server package on MongoDB Downloads)
//  If it's not, you will encounter this: Error: connect ECONNREFUSED 127.0.0.1:27020
//
//  npm install mongodb mongodb-client-encryption --save
//  node create_data.js

const { getCredentials } = require("./credentials");
var credentials = getCredentials();
const URI = credentials.MONGODB_URI;

const assert = require('assert');
const mongodb = require('mongodb');
const { ClientEncryption } = require('mongodb-client-encryption');
const { MongoClient } = mongodb;

const dbName                 = 'CSFLE';
const dataCollectionName     = 'people';
const keyVaultdbName         = 'encryption';
const keyVaultCollectionName = '__keyVault';
const dataNamespace          = `${dbName}.${dataCollectionName}`;
const keyVaultNamespace      = `${keyVaultdbName}.${keyVaultCollectionName}`;

const PRETTY_PRINT = 2;

// Only needed if using local master key for testing, or wrapping a custom key/secrets REST service call
// See: Quickstart Guide for generating a local key in Base64 format
//const LOCAL_MASTER_KEY   =  'f6pv747dKhOer4xvdg/V5ga6RTISh3N0xgpFcn3fSDQUDfpi8cOsGwv57A3mGhzkJc9lhKGIZ7IQ0aWS1OM/nstjBASiBWCuaFZXQNG8DMVX+/YFJIKIleTsM344Hbxz';
const fs = require("fs");
const provider = "local";
const path = "./master-key.txt";
// WARNING: Do not use a local key file in a production application
const localKey = fs.readFileSync(path);
const kmsProviders = {
  local: {
    key: localKey,
  },
};

const extraOptions = {
  cryptSharedLibPath: credentials["SHARED_LIB_PATH"]
};

const AEAD_DETERM = 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic';
const AEAD_RANDOM = 'AEAD_AES_256_CBC_HMAC_SHA_512-Random';

(async () => {

  console.log(`Connecting to "${URI}"...`);
  var client = new MongoClient(URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
  });
  await client.connect();
  console.log("\nConnected.\n");

  console.log("Fetching Ids ...");
  var keyName1 =  `ssn.${dataCollectionName}.${dbName}`
  var key1 =
  await client
    .db(keyVaultdbName)
    .collection(keyVaultCollectionName)
    .findOne({ 'keyAltNames': keyName1 })
    .catch((err) => { console.error(err.stack) });

  var keyName2 =  `dob.${dataCollectionName}.${dbName}`
  var key2 =
  await client
    .db(keyVaultdbName)
    .collection(keyVaultCollectionName)
    .findOne({ 'keyAltNames': keyName2 })
    .catch((err) => { console.error(err.stack) });
  
  var keyName3 =  `object_data.${dataCollectionName}.${dbName}`
  var key3 =
  await client
    .db(keyVaultdbName)
    .collection(keyVaultCollectionName)
    .findOne({ 'keyAltNames': keyName3 })
    .catch((err) => { console.error(err.stack) });

  var keyName4 =  `array_data.${dataCollectionName}.${dbName}`
  var key4 =
  await client
    .db(keyVaultdbName)
    .collection(keyVaultCollectionName)
    .findOne({ 'keyAltNames': keyName4 })
    .catch((err) => { console.error(err.stack) });
    
  var keyName5 =  `mobile.${dataCollectionName}.${dbName}`
  var key5 =
  await client
      .db(keyVaultdbName)
      .collection(keyVaultCollectionName)
      .findOne({ 'keyAltNames': keyName5 })
      .catch((err) => { console.error(err.stack) });

  console.log("\n_id value for 'key1' _id: ");
  console.log( key1._id );
  console.log("\n_id value for 'key2' _id: ");
  console.log( key2._id );
  console.log("\n_id value for 'key3' _id: ");
  console.log( key3._id );
  console.log("\n_id value for 'key3' _id: ");
  console.log( key4._id );
  console.log("\n_id value for 'key3' _id: ");
  console.log( key5._id );

  const peopleSchema = {
    [dataNamespace]: {
      bsonType: 'object',
      properties: {
        "ssn": {
          encrypt: {
            bsonType: 'string',
            algorithm: AEAD_DETERM,
            keyId: [ key1._id  ]
          }
        },
        "dob": {
          encrypt: {
            bsonType: 'date',
            algorithm: AEAD_DETERM,
            keyId: [ key2._id  ]
          }
        },
        "object_data": {
          encrypt: {
            bsonType: 'object',
            algorithm: AEAD_RANDOM,
            keyId: [ key3._id  ]
          }
        },
        "array_data": {
          encrypt: {
            bsonType: 'array',
            algorithm: AEAD_RANDOM,
            keyId: [ key4._id  ]
          }
        },
        "contacts":{
          bsonType: 'object',
          properties: {
          "mobile": {
            encrypt: {
            bsonType: 'string',
            algorithm: AEAD_RANDOM,
            keyId: [ key5._id ]
          }}}
        }
      }
    }
  };
  

  console.log("\npeopleSchema: ");
  //console.log( peopleSchema );
  console.log( JSON.stringify(peopleSchema, null, PRETTY_PRINT) );

  console.log("\nClosing client connection...")
  await client.close();

  // NOTE: Instead of dynamically querying for key1 Id each connection, consider
  // saving fixed keyId Object IDs in json schema definition
  
  console.log("\nOpening encrypted client connection...")

  client = new MongoClient(URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    monitorCommands: true,
    autoEncryption: { keyVaultNamespace, kmsProviders, schemaMap: peopleSchema, extraOptions }
  });
  await client.connect();
  console.log('Connected.');

  console.log("\nDropping people collection if present...")
  await client.db(dbName).collection(dataCollectionName).drop().catch(() => {});

  console.log("\nAttempting to insert a document using transparent encryption...");

  var doc = {
    'name': 'Taylor',
    'ssn': '555-55-5555',
    'dob': new Date('1989-12-13'),
    'object_data': {record:1, num: 12345678},
    'array_data':[{foo:1, bar:2}, "secret"],
    'unenc_data':[{foo:1, bar:2}, "notsecret"],
    'contacts': {
       'address1': '123 Main St',
       'city':     'New York',
       'state':    'NY',
       'postal':   '10281',
       'mobile':   '212-867-5309'
    }
};

await client
  .db(dbName)
  .collection(dataCollectionName)
  .insertOne(doc)
  .catch((err) => { console.error(err.stack) });

  var doc = {
    'name': 'Thomas',
    'ssn': '290-66-1234',
    'dob': new Date('1960-11-06'),
    'object_data': {record:1, num: 87654321},
    'array_data':[{foo:2, bar:3}, "secret2"],
    'unenc_data':[{foo:2, bar:3}, "notsecret2"],
    'contacts': {
       'address1': '6293 Girvin Dr',
       'city':     'Oakland',
       'state':    'CA',
       'postal':   '94611',
       'mobile':   '919-360-4368'
    }
  };
 
await client
   .db(dbName)
   .collection(dataCollectionName)
   .insertOne(doc)
   .catch((err) => { console.error(err.stack) });

console.log("\n2 Documents inserted.");

var db = client.db( dbName );
//console.log( db );
await db.command( 
  { collMod: dataCollectionName,
    validator: {
      $jsonSchema: {
          "bsonType": "object",
          "properties": {
            "ssn": {
                "encrypt": {
                  "bsonType": "string",
                  "algorithm": AEAD_DETERM,
                  "keyId": [ key1._id ]
                }
            },
            "dob": {
              "encrypt": {
                "bsonType": "date",
                "algorithm": AEAD_DETERM,
                "keyId": [ key2._id ]
              }
            },
            "object_data": {
              "encrypt": {
                "bsonType": "object",
                "algorithm": AEAD_RANDOM,
                "keyId": [ key3._id ]
              }
            },
            "array_data": {
              "encrypt": {
                "bsonType": "array",
                "algorithm": AEAD_RANDOM,
                "keyId": [ key4._id ]
              }
            },
            "contacts": {
              "bsonType" : "object",
              "properties" : {
                "mobile": {
                  "encrypt": {
                    "bsonType": "string",
                    "algorithm": AEAD_RANDOM,
                    "keyId": [ key5._id ]
                  }
                }
              }
            }
          }
      }
    }
  });

  console.log("\nAdding server-side schema validation\n");


console.log("\nFetching an encrypted document via ssn - an encrypted field ... \n");

await client
  .db(dbName)
  .collection(dataCollectionName)
  .findOne({ ssn: '290-66-1234', })
  .catch((err) => { console.error(err.stack) });

console.log( doc );

console.log("\nClosing encrypted connection...\n");
await client.close();

console.log(`Opening unencrypted connection to "${URI}"...`);
var client = new MongoClient(URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
  });
await client.connect();
console.log('Connected.');

console.log("\nFetching an encrypted document via medRecNum - a non-encyrypted field (expect to see ciphertext)... \n");

var doc =
await client
  .db(dbName)
  .collection(dataCollectionName)
  .findOne({ 'name' : "Thomas" })
  .catch((err) => { console.error(err.stack) });

console.log( doc );

console.log("\nClosing unencrypted connection...")
await client.close();

console.log("\nTest complete. \n");

})().catch( err => console.error(err.stack) );
