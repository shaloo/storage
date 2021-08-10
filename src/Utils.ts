import './SHA256';
import Sha256 from './SHA256';
import { Contract, providers, Wallet, utils, Bytes } from 'ethers';
import * as config from './config.json';
import * as arcana from './contracts/Arcana.json';
import { box, randomBytes } from 'tweetnacl';
import { encodeBase64, decodeBase64, decodeUTF8, encodeUTF8 } from 'tweetnacl-util';
import { MessageTypes, MsgParams, TypedMessage, TypedData, EthEncryptedData } from './Interfaces';

export class KeyGen {
  hasher: any;
  file: File;
  chunkSize: number;

  constructor(file: File, chunkSize = 10 * 2 ** 20) {
    this.file = file;
    this.hasher = new Sha256();
    this.chunkSize = chunkSize;
  }

  async read<T>(position: number, length: number, binary?: boolean): Promise<{ data: T; length: number }> {
    return new Promise((resolve, reject) => {
      this._chunk_reader(position, length, binary, (evt: any) => {
        if (evt.target.error == null) {
          resolve({ data: evt.target.result, length: evt.total });
        } else {
          reject(evt.target.error);
        }
      });
    });
  }

  private _chunk_reader(offset: number, length: number, binary: boolean, readEventHandler: (evt: any) => void) {
    const r: FileReader = new FileReader();
    let blob;
    if (!(offset === 0 && this.file.size <= length)) {
      blob = this.file.slice(offset, offset + length);
    } else {
      blob = this.file;
    }
    r.onload = readEventHandler;
    if (binary) {
      r.readAsBinaryString(blob);
    } else {
      r.readAsArrayBuffer(blob);
    }
  }

  getKey = async () => {
    await this.getHash();
    return this.hasher.digest().slice(16);
  };

  getHash = async () => {
    let offset = 0;
    while (offset < this.file.size) {
      let data = await this.read(offset, offset + this.chunkSize);
      offset += data.length;
      this.hasher.update(data.data);
    }
    return hasher2Hex(this.hasher.digest());
  };
}

function encrypt<T extends MessageTypes>(
  receiverPublicKey: string,
  msgParams: MsgParams<TypedData | TypedMessage<T>>,
  version: string,
): EthEncryptedData {
  switch (version) {
    case 'x25519-xsalsa20-poly1305': {
      if (typeof msgParams.data !== 'string') {
        throw new Error('Cannot detect secret message, message params should be of the form {data: "secret message"} ');
      }
      // generate ephemeral keypair
      const ephemeralKeyPair = box.keyPair();

      // assemble encryption parameters - from string to UInt8
      let pubKeyUInt8Array;
      try {
        pubKeyUInt8Array = decodeBase64(receiverPublicKey);
      } catch (err) {
        throw new Error('Bad public key');
      }

      const msgParamsUInt8Array = decodeUTF8(msgParams.data);
      const nonce = randomBytes(box.nonceLength);

      // encrypt
      const encryptedMessage = box(msgParamsUInt8Array, nonce, pubKeyUInt8Array, ephemeralKeyPair.secretKey);

      // handle encrypted data
      const output = {
        version: 'x25519-xsalsa20-poly1305',
        nonce: encodeBase64(nonce),
        ephemPublicKey: encodeBase64(ephemeralKeyPair.publicKey),
        ciphertext: encodeBase64(encryptedMessage),
      };
      // return encrypted msg data
      return output;
    }

    default:
      throw new Error('Encryption type/version not supported');
  }
}

export const hasher2Hex = (digest) => {
  return digest.map((x) => x.toString(16).padStart(2, '0')).join('');
};

export const fromHexString = (hexString: string): Uint8Array =>
  new Uint8Array(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));

export const toHexString = (bytes: ArrayBuffer): string =>
  new Uint8Array(bytes).reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');

export const Arcana = (wallet?: Wallet): Contract => {
  const provider = new providers.JsonRpcProvider(config.rpc);
  return new Contract(config.address, arcana.abi, wallet ? wallet : provider);
};

export const makeTx = async (wallet: Wallet, method: string, params) => {
  const arcana = Arcana(wallet);
  const tx = await arcana[method](...params);
  await tx.wait();
  return tx.hash;
};

export const AESEncrypt = async (key: CryptoKey, rawData: string) => {
  const iv = new Uint8Array(16);
  const enc = new TextEncoder();
  const encrypted_content = await window.crypto.subtle.encrypt(
    {
      name: 'AES-CTR',
      counter: iv,
      length: 128,
    },
    key,
    enc.encode(rawData),
  );
  return toHexString(encrypted_content);
};

export const AESDecrypt = async (key: CryptoKey, rawData: string) => {
  const iv = new Uint8Array(16);
  const encrypted_content = await window.crypto.subtle.decrypt(
    {
      name: 'AES-CTR',
      counter: iv,
      length: 128,
    },
    key,
    fromHexString(rawData),
  );
  const dec = new TextDecoder();
  const str = dec.decode(new Uint8Array(encrypted_content));
  return str;
};

export const createChildKey = async (privateKey: string, index: number) => {
  const enc = new TextEncoder();
  const key = await window.crypto.subtle.importKey(
    'raw', // raw format of the key - should be Uint8Array
    fromHexString(privateKey),
    {
      // algorithm details
      name: 'HMAC',
      hash: { name: 'SHA-256' },
    },
    false, // export = false
    ['sign', 'verify'], // what this key can do
  );
  const signature = await window.crypto.subtle.sign('HMAC', key, enc.encode(String(index)));
  return getWallet(toHexString(signature));
};

export const encryptKey = async (wallet: Wallet, key: string, metamask: boolean): Promise<Bytes> => {
  let pubKey;
  if (!metamask) {
    pubKey = await getEncryptionPublicKey(wallet, metamask);
  } else {
  }
  const encrypted = await encrypt(pubKey, { data: key }, 'x25519-xsalsa20-poly1305');
  return utils.toUtf8Bytes(JSON.stringify(encrypted));
};

export const encryptFromPubKey = async (pubKey: string, key: string): Promise<Bytes> => {
  const encrypted = await encrypt(pubKey, { data: key }, 'x25519-xsalsa20-poly1305');
  return utils.toUtf8Bytes(JSON.stringify(encrypted));
}

export const decryptKey = async (wallet: Wallet, encryptedKey: string, metamask: boolean): Promise<string> => {
  let key: string;
  if (!metamask) {
    const encryptedData = JSON.parse(encryptedKey);
    const nonce = decodeBase64(encryptedData.nonce);
    const ciphertext = decodeBase64(encryptedData.ciphertext);
    const ephemPublicKey = decodeBase64(encryptedData.ephemPublicKey);
    console.log('wallet', wallet.address, wallet.privateKey);
    const decryptedMessage = box.open(
      ciphertext,
      nonce,
      ephemPublicKey,
      nacl_decodeHex(wallet.privateKey.substring(wallet.privateKey.length - 64, wallet.privateKey.length)),
    );
    console.log(decryptedMessage);
    key = encodeUTF8(decryptedMessage);
    console.log('key', key);
  }
  return key;
};

export const getEncryptedKey = async (fileId: string): Promise<string> => {
  const arcana = Arcana();
  const file = await arcana.files(fileId);
  return utils.toUtf8String(file.encryptedKey);
};

export const getWallet = async (privateKey: string) => {
  const provider = new providers.JsonRpcProvider(config.rpc);
  return new Wallet(privateKey, provider);
};

export const getRandomWallet = () => {
  const provider = new providers.JsonRpcProvider(config.rpc);
  return Wallet.createRandom().connect(provider);
};

export class Api {
  baseUrl: string = config.developerServer;
  accessToken: string;
  email: string;
  wallet: any;
  appId: number;

  constructor(wallet: Wallet, email: string, appId: number) {
    this.wallet = wallet;
    this.email = email;
    this.appId = appId;
  }

  post = async (url: string, body: any) => {
    const headers = {
      Accept: '*/*',
      'Content-Type': 'application/json',
    };
    if (this.accessToken) headers['Authorization'] = `Bearer ${this.accessToken}`;
    return await fetch(this.baseUrl + url, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });
  };

  get = async (url: string) => {
    const headers = {
      Accept: '*/*',
    };
    if (this.accessToken) headers['Authorization'] = `Bearer ${this.accessToken}`;
    return await fetch(this.baseUrl + url, {
      method: 'GET',
      headers,
    });
  };

  register = async () => {
    const signature = await this.wallet.signMessage(`${this.email}, ${this.wallet.address}, register, ${this.appId}`);
    let res = await this.post('auth/signup', {
      email: this.email,
      address: this.wallet.address,
      signature,
    });
    return res.status;
  };

  login = async () => {
    const nonce = (await (await this.get(`auth/nonce/${this.email}`)).json()).nonce;
    const signature = await this.wallet.signMessage(`${this.email}, ${this.wallet.address}, login, ${nonce}`);
    let res = await this.post('auth/signin', {
      email: this.email,
      address: this.wallet.address,
      signature,
    });
    this.accessToken = (await res.json()).accessToken;

    // Fetch no of unused keys child keys
    const count = (await (await this.get('keys/buffer')).json()).count;
    const keys = [];
    let index = new Date().getTime();
    // Generate new child keys
    for (let i = 0; i < config.childTreshold - count; i++) {
      const cw = await createChildKey(this.wallet.privateKey, index);
      keys.push({
        publicKey: cw._signingKey().publicKey,
        nonce: index,
      });
      index++;
    }
    console.log('register child', await this.post('keys/multiple', keys));
    return this.accessToken;
  };
}

function nacl_decodeHex(msgHex) {
  const msgBase64 = Buffer.from(msgHex, 'hex').toString('base64');
  return decodeBase64(msgBase64);
}

export const getEncryptionPublicKey = async (wallet: Wallet, metamask: boolean): Promise<string> => {
  if (!metamask) {
    const privateKeyUint8Array = nacl_decodeHex(
      wallet.privateKey.substring(wallet.privateKey.length - 64, wallet.privateKey.length),
    );
    const encryptionPublicKey = box.keyPair.fromSecretKey(privateKeyUint8Array).publicKey;
    return encodeBase64(encryptionPublicKey);
  }
};
