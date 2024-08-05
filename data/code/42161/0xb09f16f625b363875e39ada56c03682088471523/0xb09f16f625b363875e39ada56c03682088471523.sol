
pragma solidity ^0.8.22;
enum Currency {
    USDC,
    USDT,
    Native
}
struct Donation {
    uint256 usdc;
    uint256 usdt;
    uint256 native;
}
interface IDonate {
    error InsufficientMsgValue();
    error InsufficientBalance();
    error UnsupportedCurrency(Currency currency);
    error WithdrawDonationFailed();
    error InvalidNativeStargate();
    error InvalidDonationReceiver();
    error UnexpectedMsgValue();
    event Donated(Currency currency, address from, address beneficiary, uint256 amount);
    event DonationWithdrawn(Currency currency, address to, uint256 amount);
    function getDonation(address user) external view returns (Donation memory donation);
    function withdrawDonation(Currency currency, uint256 minAmount) external payable;
    function donate(Currency currency, uint256 amount, address beneficiary) external payable;
}
pragma solidity >=0.8.0;
interface IMessagingComposer {
    event ComposeSent(address from, address to, bytes32 guid, uint16 index, bytes message);
    event ComposeDelivered(address from, address to, bytes32 guid, uint16 index);
    event LzComposeAlert(
        address indexed from,
        address indexed to,
        address indexed executor,
        bytes32 guid,
        uint16 index,
        uint256 gas,
        uint256 value,
        bytes message,
        bytes extraData,
        bytes reason
    );
    function composeQueue(
        address _from,
        address _to,
        bytes32 _guid,
        uint16 _index
    ) external view returns (bytes32 messageHash);
    function sendCompose(address _to, bytes32 _guid, uint16 _index, bytes calldata _message) external;
    function lzCompose(
        address _from,
        address _to,
        bytes32 _guid,
        uint16 _index,
        bytes calldata _message,
        bytes calldata _extraData
    ) external payable;
}
pragma solidity ^0.8.20;
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }
    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }
    function _contextSuffixLength() internal view virtual returns (uint256) {
        return 0;
    }
}
pragma solidity ^0.8.22;
import { SafeERC20, IERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { MessagingReceipt } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { IOFT } from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";
import { IDonate, Currency } from "./donate/IDonate.sol";
import { IClaim } from "./claim/IClaim.sol";
contract DonateAndClaim {
    using SafeERC20 for IERC20;
    address public immutable donateContract;
    address public immutable claimContract;
    address public immutable stargateUsdc;
    address public immutable stargateUsdt;
    address public immutable stargateNative;
    IERC20 public immutable tokenUsdc;
    IERC20 public immutable tokenUsdt;
    constructor(
        address _donateContract,
        address _claimContract,
        address _stargateUsdc,
        address _stargateUsdt,
        address _stargateNative
    ) {
        donateContract = _donateContract;
        claimContract = _claimContract;
        if (_stargateUsdc != address(0)) {
            stargateUsdc = _stargateUsdc;
            tokenUsdc = IERC20(IOFT(stargateUsdc).token());
            tokenUsdc.forceApprove(donateContract, type(uint256).max);
        }
        if (_stargateUsdt != address(0)) {
            stargateUsdt = _stargateUsdt;
            tokenUsdt = IERC20(IOFT(stargateUsdt).token());
            tokenUsdt.forceApprove(donateContract, type(uint256).max);
        }
        if (_stargateNative != address(0)) {
            stargateNative = _stargateNative;
            if (IOFT(stargateNative).token() != address(0)) {
                revert IDonate.InvalidNativeStargate();
            }
        }
    }
    function donateAndClaim(
        Currency currency,
        uint256 amountToDonate,
        uint256 _zroAmount,
        bytes32[] calldata _proof,
        address _to,
        bytes calldata _extraBytes
    ) external payable returns (MessagingReceipt memory receipt) {
        uint256 donateNativeAmount;
        uint256 msgFee;
        if (currency == Currency.USDC && stargateUsdc != address(0)) {
            tokenUsdc.safeTransferFrom(msg.sender, address(this), amountToDonate);
            msgFee = msg.value;
        } else if (currency == Currency.USDT && stargateUsdt != address(0)) {
            tokenUsdt.safeTransferFrom(msg.sender, address(this), amountToDonate);
            msgFee = msg.value;
        } else if (currency == Currency.Native && stargateNative != address(0)) {
            if (msg.value < amountToDonate) revert IDonate.InsufficientMsgValue();
            donateNativeAmount = amountToDonate;
            msgFee = msg.value - donateNativeAmount;
        } else {
            revert IDonate.UnsupportedCurrency(currency);
        }
        IDonate(donateContract).donate{ value: donateNativeAmount }(currency, amountToDonate, msg.sender);
        return IClaim(claimContract).claim{ value: msgFee }(msg.sender, currency, _zroAmount, _proof, _to, _extraBytes);
    }
}
pragma solidity ^0.8.20;
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { IOAppCore, ILayerZeroEndpointV2 } from "./interfaces/IOAppCore.sol";
abstract contract OAppCore is IOAppCore, Ownable {
    ILayerZeroEndpointV2 public immutable endpoint;
    mapping(uint32 eid => bytes32 peer) public peers;
    constructor(address _endpoint, address _delegate) {
        endpoint = ILayerZeroEndpointV2(_endpoint);
        if (_delegate == address(0)) revert InvalidDelegate();
        endpoint.setDelegate(_delegate);
    }
    function setPeer(uint32 _eid, bytes32 _peer) public virtual onlyOwner {
        _setPeer(_eid, _peer);
    }
    function _setPeer(uint32 _eid, bytes32 _peer) internal virtual {
        peers[_eid] = _peer;
        emit PeerSet(_eid, _peer);
    }
    function _getPeerOrRevert(uint32 _eid) internal view virtual returns (bytes32) {
        bytes32 peer = peers[_eid];
        if (peer == bytes32(0)) revert NoPeer(_eid);
        return peer;
    }
    function setDelegate(address _delegate) public onlyOwner {
        endpoint.setDelegate(_delegate);
    }
}
pragma solidity ^0.8.22;
import { MessagingReceipt } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { IDonate, Currency, Donation } from "../donate/IDonate.sol";
interface IClaim {
    error AlreadyClaimed(address user);
    error InsufficientDonation(Currency currency, uint256 expectedAmount, uint256 actualAmount);
    error InvalidProof();
    error InvalidNativeStargate();
    error InvalidNativePrice();
    error OnlyDonateAndClaim();
    error DonateAndClaimAlreadySet();
    error WithdrawFailed();
    error MsgValueNotSupported();
    error InvalidToAddress();
    event MerkleRootSet(bytes32 merkleRoot);
    event ZRORequested(address requester, uint256 zroAmount, address to);
    event DonateAndClaimSet(address donateAndClaim);
    event ZroWithdrawn(address to, uint256 amount);
    event NativeWithdrawn(address to, uint256 amount);
    function claim(
        Currency currency,
        uint256 zroAmount,
        bytes32[] calldata proof,
        address to,
        bytes calldata extraBytes
    ) external payable returns (MessagingReceipt memory receipt);
    function claim(
        address user,
        Currency currency,
        uint256 zroAmount,
        bytes32[] calldata proof,
        address to,
        bytes calldata extraBytes
    ) external payable returns (MessagingReceipt memory receipt);
}
pragma solidity >=0.8.0;
import { IMessageLibManager } from "./IMessageLibManager.sol";
import { IMessagingComposer } from "./IMessagingComposer.sol";
import { IMessagingChannel } from "./IMessagingChannel.sol";
import { IMessagingContext } from "./IMessagingContext.sol";
struct MessagingParams {
    uint32 dstEid;
    bytes32 receiver;
    bytes message;
    bytes options;
    bool payInLzToken;
}
struct MessagingReceipt {
    bytes32 guid;
    uint64 nonce;
    MessagingFee fee;
}
struct MessagingFee {
    uint256 nativeFee;
    uint256 lzTokenFee;
}
struct Origin {
    uint32 srcEid;
    bytes32 sender;
    uint64 nonce;
}
interface ILayerZeroEndpointV2 is IMessageLibManager, IMessagingComposer, IMessagingChannel, IMessagingContext {
    event PacketSent(bytes encodedPayload, bytes options, address sendLibrary);
    event PacketVerified(Origin origin, address receiver, bytes32 payloadHash);
    event PacketDelivered(Origin origin, address receiver);
    event LzReceiveAlert(
        address indexed receiver,
        address indexed executor,
        Origin origin,
        bytes32 guid,
        uint256 gas,
        uint256 value,
        bytes message,
        bytes extraData,
        bytes reason
    );
    event LzTokenSet(address token);
    event DelegateSet(address sender, address delegate);
    function quote(MessagingParams calldata _params, address _sender) external view returns (MessagingFee memory);
    function send(
        MessagingParams calldata _params,
        address _refundAddress
    ) external payable returns (MessagingReceipt memory);
    function verify(Origin calldata _origin, address _receiver, bytes32 _payloadHash) external;
    function verifiable(Origin calldata _origin, address _receiver) external view returns (bool);
    function initializable(Origin calldata _origin, address _receiver) external view returns (bool);
    function lzReceive(
        Origin calldata _origin,
        address _receiver,
        bytes32 _guid,
        bytes calldata _message,
        bytes calldata _extraData
    ) external payable;
    function clear(address _oapp, Origin calldata _origin, bytes32 _guid, bytes calldata _message) external;
    function setLzToken(address _lzToken) external;
    function lzToken() external view returns (address);
    function nativeToken() external view returns (address);
    function setDelegate(address _delegate) external;
}
pragma solidity ^0.8.20;
import {Context} from "../utils/Context.sol";
abstract contract Ownable is Context {
    address private _owner;
    error OwnableUnauthorizedAccount(address account);
    error OwnableInvalidOwner(address owner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    constructor(address initialOwner) {
        if (initialOwner == address(0)) {
            revert OwnableInvalidOwner(address(0));
        }
        _transferOwnership(initialOwner);
    }
    modifier onlyOwner() {
        _checkOwner();
        _;
    }
    function owner() public view virtual returns (address) {
        return _owner;
    }
    function _checkOwner() internal view virtual {
        if (owner() != _msgSender()) {
            revert OwnableUnauthorizedAccount(_msgSender());
        }
    }
    function renounceOwnership() public virtual onlyOwner {
        _transferOwnership(address(0));
    }
    function transferOwnership(address newOwner) public virtual onlyOwner {
        if (newOwner == address(0)) {
            revert OwnableInvalidOwner(address(0));
        }
        _transferOwnership(newOwner);
    }
    function _transferOwnership(address newOwner) internal virtual {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}
pragma solidity ^0.8.20;
import { SafeERC20, IERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { MessagingParams, MessagingFee, MessagingReceipt } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { OAppCore } from "./OAppCore.sol";
abstract contract OAppSender is OAppCore {
    using SafeERC20 for IERC20;
    error NotEnoughNative(uint256 msgValue);
    error LzTokenUnavailable();
    uint64 internal constant SENDER_VERSION = 1;
    function oAppVersion() public view virtual returns (uint64 senderVersion, uint64 receiverVersion) {
        return (SENDER_VERSION, 0);
    }
    function _quote(
        uint32 _dstEid,
        bytes memory _message,
        bytes memory _options,
        bool _payInLzToken
    ) internal view virtual returns (MessagingFee memory fee) {
        return
            endpoint.quote(
                MessagingParams(_dstEid, _getPeerOrRevert(_dstEid), _message, _options, _payInLzToken),
                address(this)
            );
    }
    function _lzSend(
        uint32 _dstEid,
        bytes memory _message,
        bytes memory _options,
        MessagingFee memory _fee,
        address _refundAddress
    ) internal virtual returns (MessagingReceipt memory receipt) {
        uint256 messageValue = _payNative(_fee.nativeFee);
        if (_fee.lzTokenFee > 0) _payLzToken(_fee.lzTokenFee);
        return
            endpoint.send{ value: messageValue }(
                MessagingParams(_dstEid, _getPeerOrRevert(_dstEid), _message, _options, _fee.lzTokenFee > 0),
                _refundAddress
            );
    }
    function _payNative(uint256 _nativeFee) internal virtual returns (uint256 nativeFee) {
        if (msg.value != _nativeFee) revert NotEnoughNative(msg.value);
        return _nativeFee;
    }
    function _payLzToken(uint256 _lzTokenFee) internal virtual {
        address lzToken = endpoint.lzToken();
        if (lzToken == address(0)) revert LzTokenUnavailable();
        IERC20(lzToken).safeTransferFrom(msg.sender, address(endpoint), _lzTokenFee);
    }
}
pragma solidity ^0.8.20;
interface IERC20 {
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 value) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}
pragma solidity ^0.8.20;
library Address {
    error AddressInsufficientBalance(address account);
    error AddressEmptyCode(address target);
    error FailedInnerCall();
    function sendValue(address payable recipient, uint256 amount) internal {
        if (address(this).balance < amount) {
            revert AddressInsufficientBalance(address(this));
        }
        (bool success, ) = recipient.call{value: amount}("");
        if (!success) {
            revert FailedInnerCall();
        }
    }
    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0);
    }
    function functionCallWithValue(address target, bytes memory data, uint256 value) internal returns (bytes memory) {
        if (address(this).balance < value) {
            revert AddressInsufficientBalance(address(this));
        }
        (bool success, bytes memory returndata) = target.call{value: value}(data);
        return verifyCallResultFromTarget(target, success, returndata);
    }
    function functionStaticCall(address target, bytes memory data) internal view returns (bytes memory) {
        (bool success, bytes memory returndata) = target.staticcall(data);
        return verifyCallResultFromTarget(target, success, returndata);
    }
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        (bool success, bytes memory returndata) = target.delegatecall(data);
        return verifyCallResultFromTarget(target, success, returndata);
    }
    function verifyCallResultFromTarget(
        address target,
        bool success,
        bytes memory returndata
    ) internal view returns (bytes memory) {
        if (!success) {
            _revert(returndata);
        } else {
            if (returndata.length == 0 && target.code.length == 0) {
                revert AddressEmptyCode(target);
            }
            return returndata;
        }
    }
    function verifyCallResult(bool success, bytes memory returndata) internal pure returns (bytes memory) {
        if (!success) {
            _revert(returndata);
        } else {
            return returndata;
        }
    }
    function _revert(bytes memory returndata) private pure {
        if (returndata.length > 0) {
            assembly {
                let returndata_size := mload(returndata)
                revert(add(32, returndata), returndata_size)
            }
        } else {
            revert FailedInnerCall();
        }
    }
}
pragma solidity ^0.8.20;
interface IERC20Permit {
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;
    function nonces(address owner) external view returns (uint256);
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}
pragma solidity ^0.8.20;
import { ILayerZeroEndpointV2 } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
interface IOAppCore {
    error OnlyPeer(uint32 eid, bytes32 sender);
    error NoPeer(uint32 eid);
    error InvalidEndpointCall();
    error InvalidDelegate();
    event PeerSet(uint32 eid, bytes32 peer);
    function oAppVersion() external view returns (uint64 senderVersion, uint64 receiverVersion);
    function endpoint() external view returns (ILayerZeroEndpointV2 iEndpoint);
    function peers(uint32 _eid) external view returns (bytes32 peer);
    function setPeer(uint32 _eid, bytes32 _peer) external;
    function setDelegate(address _delegate) external;
}
pragma solidity >=0.8.0;
interface IMessagingChannel {
    event InboundNonceSkipped(uint32 srcEid, bytes32 sender, address receiver, uint64 nonce);
    event PacketNilified(uint32 srcEid, bytes32 sender, address receiver, uint64 nonce, bytes32 payloadHash);
    event PacketBurnt(uint32 srcEid, bytes32 sender, address receiver, uint64 nonce, bytes32 payloadHash);
    function eid() external view returns (uint32);
    function skip(address _oapp, uint32 _srcEid, bytes32 _sender, uint64 _nonce) external;
    function nilify(address _oapp, uint32 _srcEid, bytes32 _sender, uint64 _nonce, bytes32 _payloadHash) external;
    function burn(address _oapp, uint32 _srcEid, bytes32 _sender, uint64 _nonce, bytes32 _payloadHash) external;
    function nextGuid(address _sender, uint32 _dstEid, bytes32 _receiver) external view returns (bytes32);
    function inboundNonce(address _receiver, uint32 _srcEid, bytes32 _sender) external view returns (uint64);
    function outboundNonce(address _sender, uint32 _dstEid, bytes32 _receiver) external view returns (uint64);
    function inboundPayloadHash(
        address _receiver,
        uint32 _srcEid,
        bytes32 _sender,
        uint64 _nonce
    ) external view returns (bytes32);
    function lazyInboundNonce(address _receiver, uint32 _srcEid, bytes32 _sender) external view returns (uint64);
}
pragma solidity >=0.8.0;
interface IMessagingContext {
    function isSendingMessage() external view returns (bool);
    function getSendContext() external view returns (uint32 dstEid, address sender);
}
pragma solidity >=0.8.0;
struct SetConfigParam {
    uint32 eid;
    uint32 configType;
    bytes config;
}
interface IMessageLibManager {
    struct Timeout {
        address lib;
        uint256 expiry;
    }
    event LibraryRegistered(address newLib);
    event DefaultSendLibrarySet(uint32 eid, address newLib);
    event DefaultReceiveLibrarySet(uint32 eid, address newLib);
    event DefaultReceiveLibraryTimeoutSet(uint32 eid, address oldLib, uint256 expiry);
    event SendLibrarySet(address sender, uint32 eid, address newLib);
    event ReceiveLibrarySet(address receiver, uint32 eid, address newLib);
    event ReceiveLibraryTimeoutSet(address receiver, uint32 eid, address oldLib, uint256 timeout);
    function registerLibrary(address _lib) external;
    function isRegisteredLibrary(address _lib) external view returns (bool);
    function getRegisteredLibraries() external view returns (address[] memory);
    function setDefaultSendLibrary(uint32 _eid, address _newLib) external;
    function defaultSendLibrary(uint32 _eid) external view returns (address);
    function setDefaultReceiveLibrary(uint32 _eid, address _newLib, uint256 _gracePeriod) external;
    function defaultReceiveLibrary(uint32 _eid) external view returns (address);
    function setDefaultReceiveLibraryTimeout(uint32 _eid, address _lib, uint256 _expiry) external;
    function defaultReceiveLibraryTimeout(uint32 _eid) external view returns (address lib, uint256 expiry);
    function isSupportedEid(uint32 _eid) external view returns (bool);
    function isValidReceiveLibrary(address _receiver, uint32 _eid, address _lib) external view returns (bool);
    function setSendLibrary(address _oapp, uint32 _eid, address _newLib) external;
    function getSendLibrary(address _sender, uint32 _eid) external view returns (address lib);
    function isDefaultSendLibrary(address _sender, uint32 _eid) external view returns (bool);
    function setReceiveLibrary(address _oapp, uint32 _eid, address _newLib, uint256 _gracePeriod) external;
    function getReceiveLibrary(address _receiver, uint32 _eid) external view returns (address lib, bool isDefault);
    function setReceiveLibraryTimeout(address _oapp, uint32 _eid, address _lib, uint256 _expiry) external;
    function receiveLibraryTimeout(address _receiver, uint32 _eid) external view returns (address lib, uint256 expiry);
    function setConfig(address _oapp, address _lib, SetConfigParam[] calldata _params) external;
    function getConfig(
        address _oapp,
        address _lib,
        uint32 _eid,
        uint32 _configType
    ) external view returns (bytes memory config);
}
pragma solidity ^0.8.20;
import { MessagingReceipt, MessagingFee } from "../../oapp/OAppSender.sol";
struct SendParam {
    uint32 dstEid; 
    bytes32 to; 
    uint256 amountLD; 
    uint256 minAmountLD; 
    bytes extraOptions; 
    bytes composeMsg; 
    bytes oftCmd; 
}
struct OFTLimit {
    uint256 minAmountLD; 
    uint256 maxAmountLD; 
}
struct OFTReceipt {
    uint256 amountSentLD; 
    uint256 amountReceivedLD; 
}
struct OFTFeeDetail {
    int256 feeAmountLD; 
    string description; 
}
interface IOFT {
    error InvalidLocalDecimals();
    error SlippageExceeded(uint256 amountLD, uint256 minAmountLD);
    event OFTSent(
        bytes32 indexed guid, 
        uint32 dstEid, 
        address indexed fromAddress, 
        uint256 amountSentLD, 
        uint256 amountReceivedLD 
    );
    event OFTReceived(
        bytes32 indexed guid, 
        uint32 srcEid, 
        address indexed toAddress, 
        uint256 amountReceivedLD 
    );
    function oftVersion() external view returns (bytes4 interfaceId, uint64 version);
    function token() external view returns (address);
    function approvalRequired() external view returns (bool);
    function sharedDecimals() external view returns (uint8);
    function quoteOFT(
        SendParam calldata _sendParam
    ) external view returns (OFTLimit memory, OFTFeeDetail[] memory oftFeeDetails, OFTReceipt memory);
    function quoteSend(SendParam calldata _sendParam, bool _payInLzToken) external view returns (MessagingFee memory);
    function send(
        SendParam calldata _sendParam,
        MessagingFee calldata _fee,
        address _refundAddress
    ) external payable returns (MessagingReceipt memory, OFTReceipt memory);
}
pragma solidity ^0.8.20;
import {IERC20} from "../IERC20.sol";
import {IERC20Permit} from "../extensions/IERC20Permit.sol";
import {Address} from "../../../utils/Address.sol";
library SafeERC20 {
    using Address for address;
    error SafeERC20FailedOperation(address token);
    error SafeERC20FailedDecreaseAllowance(address spender, uint256 currentAllowance, uint256 requestedDecrease);
    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeCall(token.transfer, (to, value)));
    }
    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeCall(token.transferFrom, (from, to, value)));
    }
    function safeIncreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        uint256 oldAllowance = token.allowance(address(this), spender);
        forceApprove(token, spender, oldAllowance + value);
    }
    function safeDecreaseAllowance(IERC20 token, address spender, uint256 requestedDecrease) internal {
        unchecked {
            uint256 currentAllowance = token.allowance(address(this), spender);
            if (currentAllowance < requestedDecrease) {
                revert SafeERC20FailedDecreaseAllowance(spender, currentAllowance, requestedDecrease);
            }
            forceApprove(token, spender, currentAllowance - requestedDecrease);
        }
    }
    function forceApprove(IERC20 token, address spender, uint256 value) internal {
        bytes memory approvalCall = abi.encodeCall(token.approve, (spender, value));
        if (!_callOptionalReturnBool(token, approvalCall)) {
            _callOptionalReturn(token, abi.encodeCall(token.approve, (spender, 0)));
            _callOptionalReturn(token, approvalCall);
        }
    }
    function _callOptionalReturn(IERC20 token, bytes memory data) private {
        bytes memory returndata = address(token).functionCall(data);
        if (returndata.length != 0 && !abi.decode(returndata, (bool))) {
            revert SafeERC20FailedOperation(address(token));
        }
    }
    function _callOptionalReturnBool(IERC20 token, bytes memory data) private returns (bool) {
        (bool success, bytes memory returndata) = address(token).call(data);
        return success && (returndata.length == 0 || abi.decode(returndata, (bool))) && address(token).code.length > 0;
    }
}
