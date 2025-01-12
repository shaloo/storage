const ethSigUtil = require('eth-sig-util');
import { SigningKey } from '@ethersproject/signing-key';
import { Forwarder, Arcana } from './typechain';

const EIP712Domain = [
  { name: 'name', type: 'string' },
  { name: 'version', type: 'string' },
  { name: 'chainId', type: 'uint256' },
  { name: 'verifyingContract', type: 'address' },
];

const ForwardRequest = [
  { name: 'from', type: 'address' },
  { name: 'to', type: 'address' },
  { name: 'value', type: 'uint256' },
  { name: 'gas', type: 'uint256' },
  { name: 'nonce', type: 'uint256' },
  { name: 'data', type: 'bytes' },
];

function getMetaTxTypeData(chainId: number, verifyingContract: string) {
  return {
    types: {
      EIP712Domain,
      ForwardRequest,
    },
    domain: {
      name: 'Arcana Forwarder',
      version: '0.0.1',
      chainId,
      verifyingContract,
    },
    primaryType: 'ForwardRequest',
  };
}

async function signTypedData(signer: any, from: string, data: any) {
  // If signer is a private key, use it to sign
  const privateKey = Buffer.from(signer.privateKey.replace(/^0x/, ''), 'hex');
  return ethSigUtil.signTypedMessage(privateKey, { data });
}

async function buildRequest(forwarder: any, input: any) {
  const nonce = await forwarder.getNonce(input.from).then((nonce: { toString: () => any }) => nonce.toString());
  return { value: 0, gas: 1e6, nonce, ...input };
}

async function buildTypedData(forwarder: any, request: any) {
  const chainId = await forwarder.provider.getNetwork().then((n: { chainId: any }) => n.chainId);
  const typeData = getMetaTxTypeData(chainId, forwarder.address);
  return { ...typeData, message: request };
}

export async function signMetaTxRequest(signer: any, forwarder: Forwarder, input: any) {
  const request = await buildRequest(forwarder, input);
  const toSign = await buildTypedData(forwarder, request);
  const signature = await signTypedData(signer, input.from, toSign);
  return { signature, request };
}

export async function sign(signer: any, arcana: Arcana, forwarder: Forwarder, method: any, params: any) {
  const { request, signature } = await signMetaTxRequest(signer, forwarder, {
    from: signer.address,
    to: arcana.address,
    data: arcana.interface.encodeFunctionData(method, params),
  });
  request['signature'] = signature.replace('0x', '');
  request['from'] = request['from'].replace('0x', '');
  request['to'] = request['to'].replace('0x', '');
  request['data'] = request['data'].replace('0x', '');
  request['nonce'] = parseInt(request['nonce']);
  return request;
}
