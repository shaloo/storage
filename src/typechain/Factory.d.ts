/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import {
  ethers,
  EventFilter,
  Signer,
  BigNumber,
  BigNumberish,
  PopulatedTransaction,
  BaseContract,
  ContractTransaction,
  Overrides,
  CallOverrides,
} from "ethers";
import { BytesLike } from "@ethersproject/bytes";
import { Listener, Provider } from "@ethersproject/providers";
import { FunctionFragment, EventFragment, Result } from "@ethersproject/abi";
import { TypedEventFilter, TypedEvent, TypedListener } from "./commons";

interface FactoryInterface extends ethers.utils.Interface {
  functions: {
    "app(address)": FunctionFragment;
    "createNewApp(string,address,bool,bool,uint128)": FunctionFragment;
    "defaultBandwidth()": FunctionFragment;
    "defaultStorage()": FunctionFragment;
    "idToAddress(uint128)": FunctionFragment;
    "isNode(address)": FunctionFragment;
    "isRegisteredUser(address,address)": FunctionFragment;
    "logic()": FunctionFragment;
    "modifyNode(address,bool)": FunctionFragment;
    "onlyDKGAdress(address)": FunctionFragment;
    "owner()": FunctionFragment;
    "renounceOwnership()": FunctionFragment;
    "setAppLevelLimit(address,uint256,uint256)": FunctionFragment;
    "setDefaultLimit(uint256,uint256)": FunctionFragment;
    "setLogic(address)": FunctionFragment;
    "setTreshold(uint256)": FunctionFragment;
    "thresholdVoting()": FunctionFragment;
    "totalNodes()": FunctionFragment;
    "totalVotes(address,address)": FunctionFragment;
    "transferOwnership(address)": FunctionFragment;
    "voteUser(address,address,bool)": FunctionFragment;
    "voteUserRegistration(address,address,address)": FunctionFragment;
  };

  encodeFunctionData(functionFragment: "app", values: [string]): string;
  encodeFunctionData(
    functionFragment: "createNewApp",
    values: [string, string, boolean, boolean, BigNumberish]
  ): string;
  encodeFunctionData(
    functionFragment: "defaultBandwidth",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "defaultStorage",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "idToAddress",
    values: [BigNumberish]
  ): string;
  encodeFunctionData(functionFragment: "isNode", values: [string]): string;
  encodeFunctionData(
    functionFragment: "isRegisteredUser",
    values: [string, string]
  ): string;
  encodeFunctionData(functionFragment: "logic", values?: undefined): string;
  encodeFunctionData(
    functionFragment: "modifyNode",
    values: [string, boolean]
  ): string;
  encodeFunctionData(
    functionFragment: "onlyDKGAdress",
    values: [string]
  ): string;
  encodeFunctionData(functionFragment: "owner", values?: undefined): string;
  encodeFunctionData(
    functionFragment: "renounceOwnership",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "setAppLevelLimit",
    values: [string, BigNumberish, BigNumberish]
  ): string;
  encodeFunctionData(
    functionFragment: "setDefaultLimit",
    values: [BigNumberish, BigNumberish]
  ): string;
  encodeFunctionData(functionFragment: "setLogic", values: [string]): string;
  encodeFunctionData(
    functionFragment: "setTreshold",
    values: [BigNumberish]
  ): string;
  encodeFunctionData(
    functionFragment: "thresholdVoting",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "totalNodes",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "totalVotes",
    values: [string, string]
  ): string;
  encodeFunctionData(
    functionFragment: "transferOwnership",
    values: [string]
  ): string;
  encodeFunctionData(
    functionFragment: "voteUser",
    values: [string, string, boolean]
  ): string;
  encodeFunctionData(
    functionFragment: "voteUserRegistration",
    values: [string, string, string]
  ): string;

  decodeFunctionResult(functionFragment: "app", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "createNewApp",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "defaultBandwidth",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "defaultStorage",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "idToAddress",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "isNode", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "isRegisteredUser",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "logic", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "modifyNode", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "onlyDKGAdress",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "owner", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "renounceOwnership",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "setAppLevelLimit",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "setDefaultLimit",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "setLogic", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "setTreshold",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "thresholdVoting",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "totalNodes", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "totalVotes", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "transferOwnership",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "voteUser", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "voteUserRegistration",
    data: BytesLike
  ): Result;

  events: {
    "NewApp(address,address)": EventFragment;
    "OwnershipTransferred(address,address)": EventFragment;
  };

  getEvent(nameOrSignatureOrTopic: "NewApp"): EventFragment;
  getEvent(nameOrSignatureOrTopic: "OwnershipTransferred"): EventFragment;
}

export class Factory extends BaseContract {
  connect(signerOrProvider: Signer | Provider | string): this;
  attach(addressOrName: string): this;
  deployed(): Promise<this>;

  listeners<EventArgsArray extends Array<any>, EventArgsObject>(
    eventFilter?: TypedEventFilter<EventArgsArray, EventArgsObject>
  ): Array<TypedListener<EventArgsArray, EventArgsObject>>;
  off<EventArgsArray extends Array<any>, EventArgsObject>(
    eventFilter: TypedEventFilter<EventArgsArray, EventArgsObject>,
    listener: TypedListener<EventArgsArray, EventArgsObject>
  ): this;
  on<EventArgsArray extends Array<any>, EventArgsObject>(
    eventFilter: TypedEventFilter<EventArgsArray, EventArgsObject>,
    listener: TypedListener<EventArgsArray, EventArgsObject>
  ): this;
  once<EventArgsArray extends Array<any>, EventArgsObject>(
    eventFilter: TypedEventFilter<EventArgsArray, EventArgsObject>,
    listener: TypedListener<EventArgsArray, EventArgsObject>
  ): this;
  removeListener<EventArgsArray extends Array<any>, EventArgsObject>(
    eventFilter: TypedEventFilter<EventArgsArray, EventArgsObject>,
    listener: TypedListener<EventArgsArray, EventArgsObject>
  ): this;
  removeAllListeners<EventArgsArray extends Array<any>, EventArgsObject>(
    eventFilter: TypedEventFilter<EventArgsArray, EventArgsObject>
  ): this;

  listeners(eventName?: string): Array<Listener>;
  off(eventName: string, listener: Listener): this;
  on(eventName: string, listener: Listener): this;
  once(eventName: string, listener: Listener): this;
  removeListener(eventName: string, listener: Listener): this;
  removeAllListeners(eventName?: string): this;

  queryFilter<EventArgsArray extends Array<any>, EventArgsObject>(
    event: TypedEventFilter<EventArgsArray, EventArgsObject>,
    fromBlockOrBlockhash?: string | number | undefined,
    toBlock?: string | number | undefined
  ): Promise<Array<TypedEvent<EventArgsArray & EventArgsObject>>>;

  interface: FactoryInterface;

  functions: {
    app(arg0: string, overrides?: CallOverrides): Promise<[string]>;

    createNewApp(
      _appName: string,
      _relayer: string,
      _onlyDKGAddress: boolean,
      _aggregateLogin: boolean,
      _appId: BigNumberish,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<ContractTransaction>;

    defaultBandwidth(overrides?: CallOverrides): Promise<[BigNumber]>;

    defaultStorage(overrides?: CallOverrides): Promise<[BigNumber]>;

    idToAddress(
      arg0: BigNumberish,
      overrides?: CallOverrides
    ): Promise<[string]>;

    isNode(arg0: string, overrides?: CallOverrides): Promise<[boolean]>;

    isRegisteredUser(
      _app: string,
      _user: string,
      overrides?: CallOverrides
    ): Promise<[boolean]>;

    logic(overrides?: CallOverrides): Promise<[string]>;

    modifyNode(
      _node: string,
      _value: boolean,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<ContractTransaction>;

    onlyDKGAdress(arg0: string, overrides?: CallOverrides): Promise<[boolean]>;

    owner(overrides?: CallOverrides): Promise<[string]>;

    renounceOwnership(
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<ContractTransaction>;

    setAppLevelLimit(
      _app: string,
      store: BigNumberish,
      bandwidth: BigNumberish,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<ContractTransaction>;

    setDefaultLimit(
      _storage: BigNumberish,
      _bandwidth: BigNumberish,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<ContractTransaction>;

    setLogic(
      _logic: string,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<ContractTransaction>;

    setTreshold(
      _newTreshold: BigNumberish,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<ContractTransaction>;

    thresholdVoting(overrides?: CallOverrides): Promise<[BigNumber]>;

    totalNodes(overrides?: CallOverrides): Promise<[BigNumber]>;

    totalVotes(
      arg0: string,
      arg1: string,
      overrides?: CallOverrides
    ): Promise<[BigNumber]>;

    transferOwnership(
      newOwner: string,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<ContractTransaction>;

    voteUser(
      _app: string,
      _user: string,
      _value: boolean,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<ContractTransaction>;

    voteUserRegistration(
      arg0: string,
      arg1: string,
      arg2: string,
      overrides?: CallOverrides
    ): Promise<[boolean]>;
  };

  app(arg0: string, overrides?: CallOverrides): Promise<string>;

  createNewApp(
    _appName: string,
    _relayer: string,
    _onlyDKGAddress: boolean,
    _aggregateLogin: boolean,
    _appId: BigNumberish,
    overrides?: Overrides & { from?: string | Promise<string> }
  ): Promise<ContractTransaction>;

  defaultBandwidth(overrides?: CallOverrides): Promise<BigNumber>;

  defaultStorage(overrides?: CallOverrides): Promise<BigNumber>;

  idToAddress(arg0: BigNumberish, overrides?: CallOverrides): Promise<string>;

  isNode(arg0: string, overrides?: CallOverrides): Promise<boolean>;

  isRegisteredUser(
    _app: string,
    _user: string,
    overrides?: CallOverrides
  ): Promise<boolean>;

  logic(overrides?: CallOverrides): Promise<string>;

  modifyNode(
    _node: string,
    _value: boolean,
    overrides?: Overrides & { from?: string | Promise<string> }
  ): Promise<ContractTransaction>;

  onlyDKGAdress(arg0: string, overrides?: CallOverrides): Promise<boolean>;

  owner(overrides?: CallOverrides): Promise<string>;

  renounceOwnership(
    overrides?: Overrides & { from?: string | Promise<string> }
  ): Promise<ContractTransaction>;

  setAppLevelLimit(
    _app: string,
    store: BigNumberish,
    bandwidth: BigNumberish,
    overrides?: Overrides & { from?: string | Promise<string> }
  ): Promise<ContractTransaction>;

  setDefaultLimit(
    _storage: BigNumberish,
    _bandwidth: BigNumberish,
    overrides?: Overrides & { from?: string | Promise<string> }
  ): Promise<ContractTransaction>;

  setLogic(
    _logic: string,
    overrides?: Overrides & { from?: string | Promise<string> }
  ): Promise<ContractTransaction>;

  setTreshold(
    _newTreshold: BigNumberish,
    overrides?: Overrides & { from?: string | Promise<string> }
  ): Promise<ContractTransaction>;

  thresholdVoting(overrides?: CallOverrides): Promise<BigNumber>;

  totalNodes(overrides?: CallOverrides): Promise<BigNumber>;

  totalVotes(
    arg0: string,
    arg1: string,
    overrides?: CallOverrides
  ): Promise<BigNumber>;

  transferOwnership(
    newOwner: string,
    overrides?: Overrides & { from?: string | Promise<string> }
  ): Promise<ContractTransaction>;

  voteUser(
    _app: string,
    _user: string,
    _value: boolean,
    overrides?: Overrides & { from?: string | Promise<string> }
  ): Promise<ContractTransaction>;

  voteUserRegistration(
    arg0: string,
    arg1: string,
    arg2: string,
    overrides?: CallOverrides
  ): Promise<boolean>;

  callStatic: {
    app(arg0: string, overrides?: CallOverrides): Promise<string>;

    createNewApp(
      _appName: string,
      _relayer: string,
      _onlyDKGAddress: boolean,
      _aggregateLogin: boolean,
      _appId: BigNumberish,
      overrides?: CallOverrides
    ): Promise<void>;

    defaultBandwidth(overrides?: CallOverrides): Promise<BigNumber>;

    defaultStorage(overrides?: CallOverrides): Promise<BigNumber>;

    idToAddress(arg0: BigNumberish, overrides?: CallOverrides): Promise<string>;

    isNode(arg0: string, overrides?: CallOverrides): Promise<boolean>;

    isRegisteredUser(
      _app: string,
      _user: string,
      overrides?: CallOverrides
    ): Promise<boolean>;

    logic(overrides?: CallOverrides): Promise<string>;

    modifyNode(
      _node: string,
      _value: boolean,
      overrides?: CallOverrides
    ): Promise<void>;

    onlyDKGAdress(arg0: string, overrides?: CallOverrides): Promise<boolean>;

    owner(overrides?: CallOverrides): Promise<string>;

    renounceOwnership(overrides?: CallOverrides): Promise<void>;

    setAppLevelLimit(
      _app: string,
      store: BigNumberish,
      bandwidth: BigNumberish,
      overrides?: CallOverrides
    ): Promise<void>;

    setDefaultLimit(
      _storage: BigNumberish,
      _bandwidth: BigNumberish,
      overrides?: CallOverrides
    ): Promise<void>;

    setLogic(_logic: string, overrides?: CallOverrides): Promise<void>;

    setTreshold(
      _newTreshold: BigNumberish,
      overrides?: CallOverrides
    ): Promise<void>;

    thresholdVoting(overrides?: CallOverrides): Promise<BigNumber>;

    totalNodes(overrides?: CallOverrides): Promise<BigNumber>;

    totalVotes(
      arg0: string,
      arg1: string,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    transferOwnership(
      newOwner: string,
      overrides?: CallOverrides
    ): Promise<void>;

    voteUser(
      _app: string,
      _user: string,
      _value: boolean,
      overrides?: CallOverrides
    ): Promise<void>;

    voteUserRegistration(
      arg0: string,
      arg1: string,
      arg2: string,
      overrides?: CallOverrides
    ): Promise<boolean>;
  };

  filters: {
    NewApp(
      owner?: null,
      appProxy?: null
    ): TypedEventFilter<[string, string], { owner: string; appProxy: string }>;

    OwnershipTransferred(
      previousOwner?: string | null,
      newOwner?: string | null
    ): TypedEventFilter<
      [string, string],
      { previousOwner: string; newOwner: string }
    >;
  };

  estimateGas: {
    app(arg0: string, overrides?: CallOverrides): Promise<BigNumber>;

    createNewApp(
      _appName: string,
      _relayer: string,
      _onlyDKGAddress: boolean,
      _aggregateLogin: boolean,
      _appId: BigNumberish,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<BigNumber>;

    defaultBandwidth(overrides?: CallOverrides): Promise<BigNumber>;

    defaultStorage(overrides?: CallOverrides): Promise<BigNumber>;

    idToAddress(
      arg0: BigNumberish,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    isNode(arg0: string, overrides?: CallOverrides): Promise<BigNumber>;

    isRegisteredUser(
      _app: string,
      _user: string,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    logic(overrides?: CallOverrides): Promise<BigNumber>;

    modifyNode(
      _node: string,
      _value: boolean,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<BigNumber>;

    onlyDKGAdress(arg0: string, overrides?: CallOverrides): Promise<BigNumber>;

    owner(overrides?: CallOverrides): Promise<BigNumber>;

    renounceOwnership(
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<BigNumber>;

    setAppLevelLimit(
      _app: string,
      store: BigNumberish,
      bandwidth: BigNumberish,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<BigNumber>;

    setDefaultLimit(
      _storage: BigNumberish,
      _bandwidth: BigNumberish,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<BigNumber>;

    setLogic(
      _logic: string,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<BigNumber>;

    setTreshold(
      _newTreshold: BigNumberish,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<BigNumber>;

    thresholdVoting(overrides?: CallOverrides): Promise<BigNumber>;

    totalNodes(overrides?: CallOverrides): Promise<BigNumber>;

    totalVotes(
      arg0: string,
      arg1: string,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    transferOwnership(
      newOwner: string,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<BigNumber>;

    voteUser(
      _app: string,
      _user: string,
      _value: boolean,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<BigNumber>;

    voteUserRegistration(
      arg0: string,
      arg1: string,
      arg2: string,
      overrides?: CallOverrides
    ): Promise<BigNumber>;
  };

  populateTransaction: {
    app(arg0: string, overrides?: CallOverrides): Promise<PopulatedTransaction>;

    createNewApp(
      _appName: string,
      _relayer: string,
      _onlyDKGAddress: boolean,
      _aggregateLogin: boolean,
      _appId: BigNumberish,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<PopulatedTransaction>;

    defaultBandwidth(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    defaultStorage(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    idToAddress(
      arg0: BigNumberish,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    isNode(
      arg0: string,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    isRegisteredUser(
      _app: string,
      _user: string,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    logic(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    modifyNode(
      _node: string,
      _value: boolean,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<PopulatedTransaction>;

    onlyDKGAdress(
      arg0: string,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    owner(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    renounceOwnership(
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<PopulatedTransaction>;

    setAppLevelLimit(
      _app: string,
      store: BigNumberish,
      bandwidth: BigNumberish,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<PopulatedTransaction>;

    setDefaultLimit(
      _storage: BigNumberish,
      _bandwidth: BigNumberish,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<PopulatedTransaction>;

    setLogic(
      _logic: string,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<PopulatedTransaction>;

    setTreshold(
      _newTreshold: BigNumberish,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<PopulatedTransaction>;

    thresholdVoting(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    totalNodes(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    totalVotes(
      arg0: string,
      arg1: string,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    transferOwnership(
      newOwner: string,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<PopulatedTransaction>;

    voteUser(
      _app: string,
      _user: string,
      _value: boolean,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<PopulatedTransaction>;

    voteUserRegistration(
      arg0: string,
      arg1: string,
      arg2: string,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;
  };
}
