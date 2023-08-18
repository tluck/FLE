/*
   Simple Node.js copy/pasteable Queryable Encryption example for serverless, Atlas, and local development
    node:    Install Node LTS version following docs: https://nodejs.org/en/download from installer.
             mkdir ~/.npm-global
             mkdir ~/lib 2>/dev/null
             npm config set prefix '~/.npm-global'
             npm install npm -g

    install: curl -LO https://downloads.mongodb.com/osx/mongo_crypt_shared_v1-macos-arm64-enterprise-7.0.0-rc0.tgz
             curl -LO https://downloads.mongodb.com/osx/mongo_crypt_shared_v1-macos-x86_64-enterprise-7.0.0-rc0.tgz
             tar -C ~/lib --strip-components 1 -zxf ./mongo_crypt_shared*.tgz lib/mongo_crypt_v1.dylib
             npm init -y
             npm install mongodb mongodb-client-encryption

    useage:  node helloWorld.js
    
*/

const { getCredentials } = require("./credentials");
credentials = getCredentials();
const uri = credentials.MONGODB_URI;
//const uri = 'mongodb://<user>:<password>@localhost:27018/';

const { MongoClient } = require("mongodb");
const { ClientEncryption } = require("mongodb-client-encryption");

// This MUST match your hardware & platform architecture (e.g. macOS M1/M2 ARM64 vs Intel; Ubuntu .so file, etc)
//const cryptSharedLibPath = require('os').homedir() + '/lib/mongo_crypt_v1.dylib';
//const cryptSharedLibPath = '/opt/mongo/mongo_crypt_shared_v1-macos-x86_64-enterprise/lib/mongo_crypt_v1.dylib';
const extraOptions = {
  cryptSharedLibPath: credentials["SHARED_LIB_PATH"]
};

const keyVaultDB         = 'encryption';
const keyVaultCollection = '__keyVault';
const dbName             = 'QE';
const collectionName     = 'people';
const regex              = { "keyAltNames": { $regex: /people.QE/ }};

// Generate test key with: console.log( Buffer.from(crypto.randomBytes(96)).toString('base64') )
//  or from terminal: echo $(head -c 96 /dev/urandom | base64 | tr -d '\n')
// const LOCAL_MASTER_KEY = 'f6pv747dKhOer4xvdg/V5ga6RTISh3N0xgpFcn3fSDQUDfpi8cOsGwv57A3mGhzkJc9lhKGIZ7IQ0aWS1OM/nstjBASiBWCuaFZXQNG8DMVX+/YFJIKIleTsM344Hbxz'
// const localKey = { 'key': Buffer.from(LOCAL_MASTER_KEY, "base64") };
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
const encOptions = {
   'keyVaultNamespace': `${keyVaultDB}.${keyVaultCollection}`,
   'kmsProviders': kmsProviders,
   'extraOptions': extraOptions,
};

async function main() {

  client = new MongoClient( uri, { 'autoEncryption': encOptions } );
  await client.connect();

  //Get handle to ClientEncryption for vault & collection helper methods
  const clientEncryption = new ClientEncryption(client, encOptions);

  // *** DROP PREVIOUS TEST KEY VAULT AND COLLECTIONS ***
  var kdb = client.db( keyVaultDB );
  // await kdb.dropDatabase().catch(() => null);
  var db = client.db( dbName );
  await db.dropDatabase().catch(() => null);
  console.log( "\nRemoving old keys from keyVault in",`${keyVaultDB}.${keyVaultCollection}`,"matching",regex);
  await client.db(keyVaultDB).collection(keyVaultCollection).deleteMany( regex );
  
  console.log("Creating an encrypted collection:",`${dbName}.${collectionName}`,"\n");
  const collOptions = {
    'encryptedFields': { 'fields': [
      { path: 'ssn', bsonType: 'string',             queries: {'queryType': 'equality'} },
      { path: 'dob', bsonType: 'date',               queries: {'queryType': 'equality'} },
      { path: 'contacts.mobile', bsonType: 'string', queries: {'queryType': 'equality'} },
      // not queryable encrypted fields
      { path: 'object_data', bsonType: 'object' },
      { path: 'array_data', bsonType: 'array' }
    ]}
  };

  console.log("Creating index for the vault collection ... \n");
  await client.db(keyVaultDB).collection(keyVaultCollection).createIndex(
    { keyAltNames: 1 }, { unique: true, partialFilterExpression: { keyAltNames: { $exists: true } }}
  );
  // Note: Only mongosh automatically creates unique keyvault indexes

  const { collection, encryptedFields } =
    await clientEncryption.createEncryptedCollection(
      db,
      collectionName,
      { 'provider': 'local', 'createCollectionOptions': collOptions }
    );
  //console.log( collection );  console.log( encryptedFields );

  //Add keyAltName tag to each new auto-generated key 
  // e.g.: "dob.testCollection.testDb-autogenerated"

  await encryptedFields.fields.forEach(fields => {
     id = fields.keyId;
     clientEncryption.addKeyAltName(id, `${fields.path}.${collectionName}.${dbName}-autogenerated`);
  });
  
  console.log("Inserting 2 documents");
  try {
    await collection.insertOne({
       'name': 'Taylor',
       'ssn': '555-55-5555',
       'dob': new Date('1989-12-13'),
       'comment': 'random thing said by Taylor',
       'object_data': {record:1, num: 12345678},
       'array_data':[{foo:1, bar:2}, "secret"],
       'unenc_data':[{foo:1, bar:2}, "notsecret"],
       'contacts': {
          'address1': '123 Main St',
          'city':     'New York',
          'state':    'NY',
          'postal':   '10281',
          'mobile':   '212-867-5309',
       }
    })
  } catch (e) { console.log(e); }

  try {
    await collection.insertOne({
       'name': 'Thomas',
       'ssn': '290-66-1234',
       'dob': new Date('1960-11-06'),
       'comment': 'This is string to search on mongodb employee',
       'object_data': {record:1, num: 87654321},
       'array_data':[{foo:2, bar:3}, "secret2"],
       'unenc_data':[{foo:2, bar:3}, "notsecret2"],
       'contacts': {
          'address1': '6293 Girvin Dr',
          'city':     'Oakland',
          'state':    'CA',
          'postal':   '94611',
          'mobile':   '919-360-4368',
       }
    })
  } catch (e) { console.log(e); }

  
  console.log("\nRetrieve and automatically decrypt data in current (QE-enabled) session: ");
  try {
    console.log( await collection.findOne( {'ssn':'290-66-1234'} ))
  } catch (e) { console.log(e); }

  console.log("\nRetrieve encrypted data in a classic (non-QE-aware) session: ");
  var clientPlaintext = new MongoClient( uri );  // Note no encryption options passed after `uri`
  await clientPlaintext.connect();

  try {
    console.log( await clientPlaintext.db(dbName).collection(collectionName).findOne({'name': 'Thomas'}) )
  } catch (e) { console.log(e); }

  console.log("Run complete. Closing connection... \n\n");
  await client.close();
  await clientPlaintext.close();
}
main().catch(console.dir);
