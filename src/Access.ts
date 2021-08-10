import { utils } from 'ethers';
import { readHash } from './constant';
import { ArcanaOptions } from './Interfaces';
import { makeTx, getEncryptedKey, decryptKey, encryptKey } from './Utils';

export class Access {
  private wallet: any;
  private convergence: string;
  private opts: ArcanaOptions;
  constructor(wallet: any, convergence: string, opts: ArcanaOptions) {
    this.wallet = wallet;
    this.convergence = convergence;
    this.opts = opts;
  }

  share = async (fileId: string[], publicKey: string[], validity: number[]): Promise<string> => {
    let address = [];
    let encryptedKey = [];
    let accessType = [];
    await Promise.all(
      fileId.map(async (f) => {
        const EK = await getEncryptedKey(f);
        const key = await decryptKey(this.wallet, EK, this.opts.metamask);
        await Promise.all(
          publicKey.map(async (p) => {
            const pubKey = p.slice(p.length - 128);
            address.push(utils.computeAddress(p));
            encryptedKey.push(await encryptKey(this.wallet, key, this.opts.metamask));
            accessType.push(readHash);
          }),
        );
      }),
    );
    return await makeTx(this.wallet, 'share', [fileId, address, accessType, encryptedKey, validity]);
  };

  revoke = async (fileId: string, address: string): Promise<string> => {
    return await makeTx(this.wallet, 'revoke', [fileId, address, readHash]);
  };

  changeFileOwner = async (fileId: string, newOwnerAddress: string): Promise<string> => {
    return await makeTx(this.wallet, 'changeFileOwner', [fileId, newOwnerAddress]);
  };

  deleteFile = async (fileId: string): Promise<string> => {
    return await makeTx(this.wallet, 'deleteFile', [fileId]);
  };
}
