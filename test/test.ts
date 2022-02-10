import test from 'ava';
import { StorageProvider, utils } from '../src/index';
import { Blob as nBlob } from 'blob-polyfill';

const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
// const gateway = false;
const gateway = 'http://localhost:9010/';
const appId = 1;
const debug = false;

const generateString = (length) => {
  let result = '';
  const charactersLength = characters.length;
  while (result.length < length) {
    result += 'a';
    // result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
};

function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

const MockFile = (name, size, mimeType) => {
  name = name || 'mock.txt';
  size = size || 1024;
  mimeType = mimeType || 'plain/txt';
  var blob = new Blob([generateString(size)], { type: mimeType });

  var dummyBlob = new nBlob([blob.arrayBuffer()], { type: mimeType });
  blob.arrayBuffer = dummyBlob.arrayBuffer;

  blob.lastModifiedDate = new Date();
  blob.name = name;
  return blob;
};

const bytesToHexString = (bytes) => {
  if (!bytes) return null;
  bytes = new Uint8Array(bytes);
  var hexBytes = [];
  for (var i = 0; i < bytes.length; ++i) {
    var byteString = bytes[i].toString(16);
    if (byteString.length < 2) byteString = '0' + byteString;
    hexBytes.push(byteString);
  }
  return hexBytes.join('');
};

function printFile(file) {
  const reader = new FileReader();
  reader.onload = function (evt) {
    console.log(evt.target.result);
  };
  reader.readAsText(file);
}

const makeEmail = () => {
  var strValues = 'abcdefg12345';
  var strEmail = '';
  var strTmp;
  for (var i = 0; i < 10; i++) {
    strTmp = strValues.charAt(Math.round(strValues.length * Math.random()));
    strEmail = strEmail + strTmp;
  }
  strTmp = '';
  strEmail = strEmail + '@example.com';
  return strEmail;
};

let file,
  did,
  arcanaInstance,
  access,
  receiverWallet,
  sharedInstance,
  file_count = 0;

test.before(async (t) => {
  file = MockFile('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.txt', 2 ** 10, 'image/txt');
  file = new File([file], file.name, { type: file.type });

  // Not working due to un-secure env
  const wallet = await utils.getRandomWallet();

  //Using PrivateKey from ganache
  //  let sPrivateKey = "dffba5d3570743eeb8b8aabf0f996c5c411d2e3f45cb2e585e921ce6c0386051" ;

  try {
    arcanaInstance = new StorageProvider({
      appId,
      privateKey: wallet.privateKey,
      email: makeEmail(),
      gateway,
      debug,
    });
    await arcanaInstance.login();

    //second instance
    receiverWallet = await utils.getRandomWallet();
    sharedInstance = new StorageProvider({
      appId,
      privateKey: receiverWallet.privateKey,
      email: makeEmail(),
      gateway,
      debug,
    });

    access = await arcanaInstance.getAccess();
  } catch (e) {
    console.log(e);
  }
});

test('Generate Wallet', async (t) => {
  const wallet = await utils.getWallet('dffba5d3570743eeb8b8aabf0f996c5c411d2e3f45cb2e585e921ce6c0386051');

  t.is(wallet.address, '0x98f92D5B2Eb666f993c5930624C2a73a3ED5B158');
  // chai.expect(wallet.address).to.equal('0xa23039d0Fca2af54E8b9ac2ECaE78e3084Cc687b');
});

test.serial('My Files should return empty array', async (t) => {
  // console.log("My Files");
  let files = await arcanaInstance.myFiles();
  t.is(files.length, 0);
});

test.serial('Shared Files should return empty array', async (t) => {
  let files = await arcanaInstance.sharedFiles();
  // chai.expect(files.length).equal(0);
  t.is(files.length, 0);
});

test.serial('Should upload a file', async (t) => {
  let upload = await arcanaInstance.getUploader();
  let complete = false;
  upload.onSuccess = () => {
    complete = true;
    file_count += 1;
  };
  upload.onError = (err) => {
    console.log('[ERROR]', err);
    throw Error(err);
  };

  // await t.notThrowsAsync(upload.upload(file))
  did = await upload.upload(file);
  while (!complete) {
    await sleep(1000);
  }

  t.pass();
});

test.serial('Fail download transaction', async (t) => {
  let download = await sharedInstance.getDownloader();
  const err = await t.throwsAsync(download.download(did));
  // t.is(err.code, 'UNAUTHORIZED');
  t.is(err.message, 'You cant download this file');
});

test.serial('Fail revoke transaction', async (t) => {
  let access = await sharedInstance.getAccess();

  let err = await t.throwsAsync(access.revoke(did, receiverWallet.address));

  t.is(err.code, 'TRANSACTION');
  t.is(err.message.substring(3), 'This function can only be called by file owner');
});

//Skiped as it returned DID, instead of error
test.serial('Should skip uploading same file', async (t) => {
  let upload = await arcanaInstance.getUploader();
  upload.onSuccess = () => {
    console.log('Skip file upload');
  };

  let err = await t.throwsAsync(upload.upload(file));
  t.is(err.code, 'TRANSACTION');
  t.true(err.message.includes('File is already uploaded'));
});

test.serial('My files', async (t) => {
  let files = await arcanaInstance.myFiles();
  t.is(files.length, 1);
  t.is(files[0].did, did.substring(2));
  t.is(files[0].size, file.size);
});

//Error: File must be uploaded before downloading it
test.serial('Should download a file', async (t) => {
  await sleep(5000);

  let download = await arcanaInstance.getDownloader();
  download.onSuccess = () => {
    console.log('Download completed');
  };
  download.onProgress = (a, b) => {
    console.log(a, b);
  };

await  t.notThrowsAsync(download.download(did));
});

test.serial('Share file', async (t) => {
  let tx = await access.share([did], [receiverWallet._signingKey().publicKey], [150]);
  // chai.expect(tx).not.null;
  t.truthy(tx);
});

//Error: File must be uploaded before downloading it
test.serial('Download shared file', async (t) => {
  let download = await sharedInstance.getDownloader();
  await t.notThrowsAsync(download.download(did));
});

test.serial('check shared users', async (t) => {
  // chai.expect((await access.getSharedUsers(did))[0]).equal(receiverWallet.address);
  // chai.expect((await access.getSharedUsers(did)).length).equal(1);

  t.is((await access.getSharedUsers(did))[0], receiverWallet.address);
  t.is((await access.getSharedUsers(did)).length, 1);
});

test.serial('Files shared with self', async (t) => {
  let files = await sharedInstance.sharedFiles();
  t.is(files.length, 1);
  t.is(files[0]['did'], did.substring(2));
  t.is(files[0]['size'], file.size);
});

test.serial('Get consumed and total upload limit', async (t) => {
  const Access = await arcanaInstance.getAccess();
  let [consumed, total] = await Access.getUploadLimit(did);
  // chai.expect(consumed).equal(file.size);
  t.is(consumed, file.size);
});

//Error: tus: failed to upload chunk at offset 0,
test.serial('Revoke', async (t) => {
  let before = await access.getSharedUsers(did);
  let tx = await access.revoke(did, receiverWallet.address);
  let after = await access.getSharedUsers(did);

  t.truthy(tx);

  t.is(before.includes(receiverWallet.address), true);
  t.is(after.includes(receiverWallet.address), false);
  t.is(before.length - after.length, 1);
  let files = await sharedInstance.sharedFiles();
  t.is(files.length, 0);
});

test.serial('Delete File', async (t) => {
  let files = await arcanaInstance.myFiles();
  t.plan(4);
  t.is(files.length, 1);
  t.is(files[0].did, did.substring(2));

  let tx = await access.deleteFile(did);
  files = await arcanaInstance.myFiles();

  t.is(files.length, 0);
  t.truthy(tx);
});