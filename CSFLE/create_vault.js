// Simple Client-Side Field Level Encryption example for Node.js - Key setup (Step 1)


// To install:
//  Make sure the mongocryptd binary is on a default path (from the Enterprise server package on MongoDB Downloads)
//  If it's not, you will encounter this: Error: connect ECONNREFUSED 127.0.0.1:27020

//  npm install mongodb mongodb-client-encryption --save
//  node create_vault.js

//'use strict';
const { getCredentials } = require("./credentials");
var credentials = getCredentials();
const URI = credentials.MONGODB_URI;

const assert = require('assert');
const mongodb = require('mongodb');
const { ClientEncryption } = require('mongodb-client-encryption');
const { MongoClient } = mongodb;

const dbName                 = 'CSFLE';
const dataCollectionName     = 'people';
const keyVaultDB             = 'encryption';
const keyVaultCollection     = '__keyVault';
// const dataNamespace          = `${dbName}.${dataCollectionName}`;
const keyVaultNamespace      = `${keyVaultDB}.${keyVaultCollection}`;
const regex                  = { "keyAltNames": { $regex: /people.CSFLE/ }};

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
  const client = new MongoClient(URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
  });
  await client.connect();
  console.log('Connected.');

  const encryption = new ClientEncryption(client, {
    'kmsProviders': kmsProviders,
    'extraOptions': extraOptions,
    'keyVaultNamespace': keyVaultNamespace,
   //mongocryptdBypassSpawn: true,
   });

//console.log("\nDropping keyVaultCollection if present...")
//await client.db(keyVaultDB).collection(keyVaultCollection).drop().catch(() => {});
const keyVaultClient = client.db(keyVaultDB).collection(keyVaultCollection);
  console.log( "\nRemoving old keys from keyVault in",keyVaultNamespace,"matching",regex);
  await keyVaultClient.deleteMany( regex );

  await keyVaultClient.createIndex(
    { keyAltNames: 1 },
    {
      unique: true,
      partialFilterExpression: { keyAltNames: { $exists: true } },
    }
  );
  // end-create-index

  console.log("\nCreating data keys...");

  var keyName =  `ssn.${dataCollectionName}.${dbName}`
  const key1 =
  await encryption
    .createDataKey('local', { keyAltNames: [keyName] })
    .catch((err) => { console.error(err.stack) });
  
  var keyName =  `dob.${dataCollectionName}.${dbName}`
  const key2 =
  await encryption
    .createDataKey('local', { keyAltNames: [keyName] })
    .catch((err) => { console.error(err.stack) });

  keyName =  `mobile.${dataCollectionName}.${dbName}`
  const key3 =
  await encryption
    .createDataKey('local', { keyAltNames: [keyName] })
    .catch((err) => { console.error(err.stack) });

  keyName =  `object_data.${dataCollectionName}.${dbName}`
  const key4 =
  await encryption
    .createDataKey('local', { keyAltNames: [keyName] })
    .catch((err) => { console.error(err.stack) });

  keyName =  `array_data.${dataCollectionName}.${dbName}`
  const key5 =
  await encryption
    .createDataKey('local', { keyAltNames: [keyName] })
    .catch((err) => { console.error(err.stack) });

  console.log("Data keys created. keyId/UUID:");
  console.log({ key1 });
  console.log({ key2 });
  console.log({ key3 });
  console.log({ key4 });
  console.log({ key5 });

  await client.close();
  console.log("\nSetup complete. \n");

})().catch( err => console.error(err.stack) );
