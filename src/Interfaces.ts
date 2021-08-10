export interface MsgParams<D> {
  data: D;
  sig?: string;
}

export interface MessageTypeProperty {
  name: string;
  type: string;
}

export interface MessageTypes {
  EIP712Domain: MessageTypeProperty[];
  [additionalProperties: string]: MessageTypeProperty[];
}

export interface TypedMessage<T extends MessageTypes> {
  types: T;
  primaryType: keyof T;
  domain: {
    name?: string;
    version?: string;
    chainId?: number;
    verifyingContract?: string;
  };
  message: Record<string, unknown>;
}

export interface EIP712TypedData {
  name: string;
  type: string;
  value: any;
}

export type TypedData = string | EIP712TypedData | EIP712TypedData[];

export interface EthEncryptedData {
  version: string;
  nonce: string;
  ephemPublicKey: string;
  ciphertext: string;
}

export interface ArcanaOptions {
  metamask: boolean;
}