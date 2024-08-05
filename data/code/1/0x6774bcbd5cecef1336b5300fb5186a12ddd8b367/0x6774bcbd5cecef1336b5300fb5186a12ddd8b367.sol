// SPDX-License-Identifier: MIT

pragma solidity =0.8.16;

import {IScrollChain} from "./rollup/IScrollChain.sol";
import {IL1MessageQueue} from "./rollup/IL1MessageQueue.sol";
import {IL1ScrollMessenger} from "./IL1ScrollMessenger.sol";
import {ScrollConstants} from "../libraries/constants/ScrollConstants.sol";
import {IScrollMessenger} from "../libraries/IScrollMessenger.sol";
import {ScrollMessengerBase} from "../libraries/ScrollMessengerBase.sol";
import {WithdrawTrieVerifier} from "../libraries/verifier/WithdrawTrieVerifier.sol";

import {IMessageDropCallback} from "../libraries/callbacks/IMessageDropCallback.sol";

// solhint-disable avoid-low-level-calls
// solhint-disable not-rely-on-time
// solhint-disable reason-string

/// @title L1ScrollMessenger
/// @notice The `L1ScrollMessenger` contract can:
///
/// 1. send messages from layer 1 to layer 2;
/// 2. relay messages from layer 2 layer 1;
/// 3. replay failed message by replacing the gas limit;
/// 4. drop expired message due to sequencer problems.
///
/// @dev All deposited Ether (including `WETH` deposited throng `L1WETHGateway`) will locked in
/// this contract.
contract L1ScrollMessenger is ScrollMessengerBase, IL1ScrollMessenger {
    /*************
     * Constants *
     *************/

    /// @notice The address of Rollup contract.
    address public immutable rollup;

    /// @notice The address of L1MessageQueue contract.
    address public immutable messageQueue;

    /***********
     * Structs *
     ***********/

    struct ReplayState {
        // The number of replayed times.
        uint128 times;
        // The queue index of lastest replayed one. If it is zero, it means the message has not been replayed.
        uint128 lastIndex;
    }

    /*************
     * Variables *
     *************/

    /// @notice Mapping from L1 message hash to the timestamp when the message is sent.
    mapping(bytes32 => uint256) public messageSendTimestamp;

    /// @notice Mapping from L2 message hash to a boolean value indicating if the message has been successfully executed.
    mapping(bytes32 => bool) public isL2MessageExecuted;

    /// @notice Mapping from L1 message hash to drop status.
    mapping(bytes32 => bool) public isL1MessageDropped;

    /// @dev The storage slot used as Rollup contract, which is deprecated now.
    address private __rollup;

    /// @dev The storage slot used as L1MessageQueue contract, which is deprecated now.
    address private __messageQueue;

    /// @notice The maximum number of times each L1 message can be replayed.
    uint256 public maxReplayTimes;

    /// @notice Mapping from L1 message hash to replay state.
    mapping(bytes32 => ReplayState) public replayStates;

    /// @notice Mapping from queue index to previous replay queue index.
    ///
    /// @dev If a message `x` was replayed 3 times with index `q1`, `q2` and `q3`, the
    /// value of `prevReplayIndex` and `replayStates` will be `replayStates[hash(x)].lastIndex = q3`,
    /// `replayStates[hash(x)].times = 3`, `prevReplayIndex[q3] = q2`, `prevReplayIndex[q2] = q1`,
    /// `prevReplayIndex[q1] = x` and `prevReplayIndex[x]=nil`.
    ///
    /// @dev The index `x` that `prevReplayIndex[x]=nil` is used as the termination of the list.
    /// Usually we use `0` to represent `nil`, but we cannot distinguish it with the first message
    /// with index zero. So a nonzero offset `1` is added to the value of `prevReplayIndex[x]` to
    /// avoid such situation.
    mapping(uint256 => uint256) public prevReplayIndex;

    /***************
     * Constructor *
     ***************/

    constructor(
        address _counterpart,
        address _rollup,
        address _messageQueue
    ) ScrollMessengerBase(_counterpart) {
        if (_rollup == address(0) || _messageQueue == address(0)) {
            revert ErrorZeroAddress();
        }

        _disableInitializers();

        rollup = _rollup;
        messageQueue = _messageQueue;
    }

    /// @notice Initialize the storage of L1ScrollMessenger.
    ///
    /// @dev The parameters `_counterpart`, `_rollup` and `_messageQueue` are no longer used.
    ///
    /// @param _counterpart The address of L2ScrollMessenger contract in L2.
    /// @param _feeVault The address of fee vault, which will be used to collect relayer fee.
    /// @param _rollup The address of ScrollChain contract.
    /// @param _messageQueue The address of L1MessageQueue contract.
    function initialize(
        address _counterpart,
        address _feeVault,
        address _rollup,
        address _messageQueue
    ) public initializer {
        ScrollMessengerBase.__ScrollMessengerBase_init(_counterpart, _feeVault);

        __rollup = _rollup;
        __messageQueue = _messageQueue;

        maxReplayTimes = 3;
        emit UpdateMaxReplayTimes(0, 3);
    }

    /*****************************
     * Public Mutating Functions *
     *****************************/

    /// @inheritdoc IScrollMessenger
    function sendMessage(
        address _to,
        uint256 _value,
        bytes memory _message,
        uint256 _gasLimit
    ) external payable override whenNotPaused {
        _sendMessage(_to, _value, _message, _gasLimit, _msgSender());
    }

    /// @inheritdoc IScrollMessenger
    function sendMessage(
        address _to,
        uint256 _value,
        bytes calldata _message,
        uint256 _gasLimit,
        address _refundAddress
    ) external payable override whenNotPaused {
        _sendMessage(_to, _value, _message, _gasLimit, _refundAddress);
    }

    /// @inheritdoc IL1ScrollMessenger
    function relayMessageWithProof(
        address _from,
        address _to,
        uint256 _value,
        uint256 _nonce,
        bytes memory _message,
        L2MessageProof memory _proof
    ) external override whenNotPaused notInExecution {
        bytes32 _xDomainCalldataHash = keccak256(_encodeXDomainCalldata(_from, _to, _value, _nonce, _message));
        require(!isL2MessageExecuted[_xDomainCalldataHash], "Message was already successfully executed");

        {
            require(IScrollChain(rollup).isBatchFinalized(_proof.batchIndex), "Batch is not finalized");
            bytes32 _messageRoot = IScrollChain(rollup).withdrawRoots(_proof.batchIndex);
            require(
                WithdrawTrieVerifier.verifyMerkleProof(_messageRoot, _xDomainCalldataHash, _nonce, _proof.merkleProof),
                "Invalid proof"
            );
        }

        // @note check more `_to` address to avoid attack in the future when we add more gateways.
        require(_to != messageQueue, "Forbid to call message queue");
        _validateTargetAddress(_to);

        // @note This usually will never happen, just in case.
        require(_from != xDomainMessageSender, "Invalid message sender");

        xDomainMessageSender = _from;
        (bool success, ) = _to.call{value: _value}(_message);
        // reset value to refund gas.
        xDomainMessageSender = ScrollConstants.DEFAULT_XDOMAIN_MESSAGE_SENDER;

        if (success) {
            isL2MessageExecuted[_xDomainCalldataHash] = true;
            emit RelayedMessage(_xDomainCalldataHash);
        } else {
            emit FailedRelayedMessage(_xDomainCalldataHash);
        }
    }

    /// @inheritdoc IL1ScrollMessenger
    function replayMessage(
        address _from,
        address _to,
        uint256 _value,
        uint256 _messageNonce,
        bytes memory _message,
        uint32 _newGasLimit,
        address _refundAddress
    ) external payable override whenNotPaused notInExecution {
        // We will use a different `queueIndex` for the replaced message. However, the original `queueIndex` or `nonce`
        // is encoded in the `_message`. We will check the `xDomainCalldata` on layer 2 to avoid duplicated execution.
        // So, only one message will succeed on layer 2. If one of the message is executed successfully, the other one
        // will revert with "Message was already successfully executed".
        bytes memory _xDomainCalldata = _encodeXDomainCalldata(_from, _to, _value, _messageNonce, _message);
        bytes32 _xDomainCalldataHash = keccak256(_xDomainCalldata);

        require(messageSendTimestamp[_xDomainCalldataHash] > 0, "Provided message has not been enqueued");
        // cannot replay dropped message
        require(!isL1MessageDropped[_xDomainCalldataHash], "Message already dropped");

        // compute and deduct the messaging fee to fee vault.
        uint256 _fee = IL1MessageQueue(messageQueue).estimateCrossDomainMessageFee(_newGasLimit);

        // charge relayer fee
        require(msg.value >= _fee, "Insufficient msg.value for fee");
        if (_fee > 0) {
            (bool _success, ) = feeVault.call{value: _fee}("");
            require(_success, "Failed to deduct the fee");
        }

        // enqueue the new transaction
        uint256 _nextQueueIndex = IL1MessageQueue(messageQueue).nextCrossDomainMessageIndex();
        IL1MessageQueue(messageQueue).appendCrossDomainMessage(counterpart, _newGasLimit, _xDomainCalldata);

        ReplayState memory _replayState = replayStates[_xDomainCalldataHash];
        // update the replayed message chain.
        unchecked {
            if (_replayState.lastIndex == 0) {
                // the message has not been replayed before.
                prevReplayIndex[_nextQueueIndex] = _messageNonce + 1;
            } else {
                prevReplayIndex[_nextQueueIndex] = _replayState.lastIndex + 1;
            }
        }
        _replayState.lastIndex = uint128(_nextQueueIndex);

        // update replay times
        require(_replayState.times < maxReplayTimes, "Exceed maximum replay times");
        unchecked {
            _replayState.times += 1;
        }
        replayStates[_xDomainCalldataHash] = _replayState;

        // refund fee to `_refundAddress`
        unchecked {
            uint256 _refund = msg.value - _fee;
            if (_refund > 0) {
                (bool _success, ) = _refundAddress.call{value: _refund}("");
                require(_success, "Failed to refund the fee");
            }
        }
    }

    /// @inheritdoc IL1ScrollMessenger
    function dropMessage(
        address _from,
        address _to,
        uint256 _value,
        uint256 _messageNonce,
        bytes memory _message
    ) external override whenNotPaused notInExecution {
        // The criteria for dropping a message:
        // 1. The message is a L1 message.
        // 2. The message has not been dropped before.
        // 3. the message and all of its replacement are finalized in L1.
        // 4. the message and all of its replacement are skipped.
        //
        // Possible denial of service attack:
        // + replayMessage is called every time someone want to drop the message.
        // + replayMessage is called so many times for a skipped message, thus results a long list.
        //
        // We limit the number of `replayMessage` calls of each message, which may solve the above problem.

        // check message exists
        bytes memory _xDomainCalldata = _encodeXDomainCalldata(_from, _to, _value, _messageNonce, _message);
        bytes32 _xDomainCalldataHash = keccak256(_xDomainCalldata);
        require(messageSendTimestamp[_xDomainCalldataHash] > 0, "Provided message has not been enqueued");

        // check message not dropped
        require(!isL1MessageDropped[_xDomainCalldataHash], "Message already dropped");

        // check message is finalized
        uint256 _lastIndex = replayStates[_xDomainCalldataHash].lastIndex;
        if (_lastIndex == 0) _lastIndex = _messageNonce;

        // check message is skipped and drop it.
        // @note If the list is very long, the message may never be dropped.
        while (true) {
            IL1MessageQueue(messageQueue).dropCrossDomainMessage(_lastIndex);
            _lastIndex = prevReplayIndex[_lastIndex];
            if (_lastIndex == 0) break;
            unchecked {
                _lastIndex = _lastIndex - 1;
            }
        }

        isL1MessageDropped[_xDomainCalldataHash] = true;

        // set execution context
        xDomainMessageSender = ScrollConstants.DROP_XDOMAIN_MESSAGE_SENDER;
        IMessageDropCallback(_from).onDropMessage{value: _value}(_message);
        // clear execution context
        xDomainMessageSender = ScrollConstants.DEFAULT_XDOMAIN_MESSAGE_SENDER;
    }

    /************************
     * Restricted Functions *
     ************************/

    /// @notice Update max replay times.
    /// @dev This function can only called by contract owner.
    /// @param _newMaxReplayTimes The new max replay times.
    function updateMaxReplayTimes(uint256 _newMaxReplayTimes) external onlyOwner {
        uint256 _oldMaxReplayTimes = maxReplayTimes;
        maxReplayTimes = _newMaxReplayTimes;

        emit UpdateMaxReplayTimes(_oldMaxReplayTimes, _newMaxReplayTimes);
    }

    /**********************
     * Internal Functions *
     **********************/

    function _sendMessage(
        address _to,
        uint256 _value,
        bytes memory _message,
        uint256 _gasLimit,
        address _refundAddress
    ) internal nonReentrant {
        // compute the actual cross domain message calldata.
        uint256 _messageNonce = IL1MessageQueue(messageQueue).nextCrossDomainMessageIndex();
        bytes memory _xDomainCalldata = _encodeXDomainCalldata(_msgSender(), _to, _value, _messageNonce, _message);

        // compute and deduct the messaging fee to fee vault.
        uint256 _fee = IL1MessageQueue(messageQueue).estimateCrossDomainMessageFee(_gasLimit);
        require(msg.value >= _fee + _value, "Insufficient msg.value");
        if (_fee > 0) {
            (bool _success, ) = feeVault.call{value: _fee}("");
            require(_success, "Failed to deduct the fee");
        }

        // append message to L1MessageQueue
        IL1MessageQueue(messageQueue).appendCrossDomainMessage(counterpart, _gasLimit, _xDomainCalldata);

        // record the message hash for future use.
        bytes32 _xDomainCalldataHash = keccak256(_xDomainCalldata);

        // normally this won't happen, since each message has different nonce, but just in case.
        require(messageSendTimestamp[_xDomainCalldataHash] == 0, "Duplicated message");
        messageSendTimestamp[_xDomainCalldataHash] = block.timestamp;

        emit SentMessage(_msgSender(), _to, _value, _messageNonce, _gasLimit, _message);

        // refund fee to `_refundAddress`
        unchecked {
            uint256 _refund = msg.value - _fee - _value;
            if (_refund > 0) {
                (bool _success, ) = _refundAddress.call{value: _refund}("");
                require(_success, "Failed to refund the fee");
            }
        }
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.7.0) (security/Pausable.sol)

pragma solidity ^0.8.0;

import "../utils/ContextUpgradeable.sol";
import "../proxy/utils/Initializable.sol";

/**
 * @dev Contract module which allows children to implement an emergency stop
 * mechanism that can be triggered by an authorized account.
 *
 * This module is used through inheritance. It will make available the
 * modifiers `whenNotPaused` and `whenPaused`, which can be applied to
 * the functions of your contract. Note that they will not be pausable by
 * simply including this module, only once the modifiers are put in place.
 */
abstract contract PausableUpgradeable is Initializable, ContextUpgradeable {
    /**
     * @dev Emitted when the pause is triggered by `account`.
     */
    event Paused(address account);

    /**
     * @dev Emitted when the pause is lifted by `account`.
     */
    event Unpaused(address account);

    bool private _paused;

    /**
     * @dev Initializes the contract in unpaused state.
     */
    function __Pausable_init() internal onlyInitializing {
        __Pausable_init_unchained();
    }

    function __Pausable_init_unchained() internal onlyInitializing {
        _paused = false;
    }

    /**
     * @dev Modifier to make a function callable only when the contract is not paused.
     *
     * Requirements:
     *
     * - The contract must not be paused.
     */
    modifier whenNotPaused() {
        _requireNotPaused();
        _;
    }

    /**
     * @dev Modifier to make a function callable only when the contract is paused.
     *
     * Requirements:
     *
     * - The contract must be paused.
     */
    modifier whenPaused() {
        _requirePaused();
        _;
    }

    /**
     * @dev Returns true if the contract is paused, and false otherwise.
     */
    function paused() public view virtual returns (bool) {
        return _paused;
    }

    /**
     * @dev Throws if the contract is paused.
     */
    function _requireNotPaused() internal view virtual {
        require(!paused(), "Pausable: paused");
    }

    /**
     * @dev Throws if the contract is not paused.
     */
    function _requirePaused() internal view virtual {
        require(paused(), "Pausable: not paused");
    }

    /**
     * @dev Triggers stopped state.
     *
     * Requirements:
     *
     * - The contract must not be paused.
     */
    function _pause() internal virtual whenNotPaused {
        _paused = true;
        emit Paused(_msgSender());
    }

    /**
     * @dev Returns to normal state.
     *
     * Requirements:
     *
     * - The contract must be paused.
     */
    function _unpause() internal virtual whenPaused {
        _paused = false;
        emit Unpaused(_msgSender());
    }

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[49] private __gap;
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (proxy/utils/Initializable.sol)

pragma solidity ^0.8.2;

import "../../utils/AddressUpgradeable.sol";

/**
 * @dev This is a base contract to aid in writing upgradeable contracts, or any kind of contract that will be deployed
 * behind a proxy. Since proxied contracts do not make use of a constructor, it's common to move constructor logic to an
 * external initializer function, usually called `initialize`. It then becomes necessary to protect this initializer
 * function so it can only be called once. The {initializer} modifier provided by this contract will have this effect.
 *
 * The initialization functions use a version number. Once a version number is used, it is consumed and cannot be
 * reused. This mechanism prevents re-execution of each "step" but allows the creation of new initialization steps in
 * case an upgrade adds a module that needs to be initialized.
 *
 * For example:
 *
 * [.hljs-theme-light.nopadding]
 * ```solidity
 * contract MyToken is ERC20Upgradeable {
 *     function initialize() initializer public {
 *         __ERC20_init("MyToken", "MTK");
 *     }
 * }
 *
 * contract MyTokenV2 is MyToken, ERC20PermitUpgradeable {
 *     function initializeV2() reinitializer(2) public {
 *         __ERC20Permit_init("MyToken");
 *     }
 * }
 * ```
 *
 * TIP: To avoid leaving the proxy in an uninitialized state, the initializer function should be called as early as
 * possible by providing the encoded function call as the `_data` argument to {ERC1967Proxy-constructor}.
 *
 * CAUTION: When used with inheritance, manual care must be taken to not invoke a parent initializer twice, or to ensure
 * that all initializers are idempotent. This is not verified automatically as constructors are by Solidity.
 *
 * [CAUTION]
 * ====
 * Avoid leaving a contract uninitialized.
 *
 * An uninitialized contract can be taken over by an attacker. This applies to both a proxy and its implementation
 * contract, which may impact the proxy. To prevent the implementation contract from being used, you should invoke
 * the {_disableInitializers} function in the constructor to automatically lock it when it is deployed:
 *
 * [.hljs-theme-light.nopadding]
 * ```
 * /// @custom:oz-upgrades-unsafe-allow constructor
 * constructor() {
 *     _disableInitializers();
 * }
 * ```
 * ====
 */
abstract contract Initializable {
    /**
     * @dev Indicates that the contract has been initialized.
     * @custom:oz-retyped-from bool
     */
    uint8 private _initialized;

    /**
     * @dev Indicates that the contract is in the process of being initialized.
     */
    bool private _initializing;

    /**
     * @dev Triggered when the contract has been initialized or reinitialized.
     */
    event Initialized(uint8 version);

    /**
     * @dev A modifier that defines a protected initializer function that can be invoked at most once. In its scope,
     * `onlyInitializing` functions can be used to initialize parent contracts.
     *
     * Similar to `reinitializer(1)`, except that functions marked with `initializer` can be nested in the context of a
     * constructor.
     *
     * Emits an {Initialized} event.
     */
    modifier initializer() {
        bool isTopLevelCall = !_initializing;
        require(
            (isTopLevelCall && _initialized < 1) || (!AddressUpgradeable.isContract(address(this)) && _initialized == 1),
            "Initializable: contract is already initialized"
        );
        _initialized = 1;
        if (isTopLevelCall) {
            _initializing = true;
        }
        _;
        if (isTopLevelCall) {
            _initializing = false;
            emit Initialized(1);
        }
    }

    /**
     * @dev A modifier that defines a protected reinitializer function that can be invoked at most once, and only if the
     * contract hasn't been initialized to a greater version before. In its scope, `onlyInitializing` functions can be
     * used to initialize parent contracts.
     *
     * A reinitializer may be used after the original initialization step. This is essential to configure modules that
     * are added through upgrades and that require initialization.
     *
     * When `version` is 1, this modifier is similar to `initializer`, except that functions marked with `reinitializer`
     * cannot be nested. If one is invoked in the context of another, execution will revert.
     *
     * Note that versions can jump in increments greater than 1; this implies that if multiple reinitializers coexist in
     * a contract, executing them in the right order is up to the developer or operator.
     *
     * WARNING: setting the version to 255 will prevent any future reinitialization.
     *
     * Emits an {Initialized} event.
     */
    modifier reinitializer(uint8 version) {
        require(!_initializing && _initialized < version, "Initializable: contract is already initialized");
        _initialized = version;
        _initializing = true;
        _;
        _initializing = false;
        emit Initialized(version);
    }

    /**
     * @dev Modifier to protect an initialization function so that it can only be invoked by functions with the
     * {initializer} and {reinitializer} modifiers, directly or indirectly.
     */
    modifier onlyInitializing() {
        require(_initializing, "Initializable: contract is not initializing");
        _;
    }

    /**
     * @dev Locks the contract, preventing any future reinitialization. This cannot be part of an initializer call.
     * Calling this in the constructor of a contract will prevent that contract from being initialized or reinitialized
     * to any version. It is recommended to use this to lock implementation contracts that are designed to be called
     * through proxies.
     *
     * Emits an {Initialized} event the first time it is successfully executed.
     */
    function _disableInitializers() internal virtual {
        require(!_initializing, "Initializable: contract is initializing");
        if (_initialized != type(uint8).max) {
            _initialized = type(uint8).max;
            emit Initialized(type(uint8).max);
        }
    }

    /**
     * @dev Returns the highest version that has been initialized. See {reinitializer}.
     */
    function _getInitializedVersion() internal view returns (uint8) {
        return _initialized;
    }

    /**
     * @dev Returns `true` if the contract is currently initializing. See {onlyInitializing}.
     */
    function _isInitializing() internal view returns (bool) {
        return _initializing;
    }
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.16;

interface IScrollMessenger {
    /**********
     * Events *
     **********/

    /// @notice Emitted when a cross domain message is sent.
    /// @param sender The address of the sender who initiates the message.
    /// @param target The address of target contract to call.
    /// @param value The amount of value passed to the target contract.
    /// @param messageNonce The nonce of the message.
    /// @param gasLimit The optional gas limit passed to L1 or L2.
    /// @param message The calldata passed to the target contract.
    event SentMessage(
        address indexed sender,
        address indexed target,
        uint256 value,
        uint256 messageNonce,
        uint256 gasLimit,
        bytes message
    );

    /// @notice Emitted when a cross domain message is relayed successfully.
    /// @param messageHash The hash of the message.
    event RelayedMessage(bytes32 indexed messageHash);

    /// @notice Emitted when a cross domain message is failed to relay.
    /// @param messageHash The hash of the message.
    event FailedRelayedMessage(bytes32 indexed messageHash);

    /**********
     * Errors *
     **********/

    /// @dev Thrown when the given address is `address(0)`.
    error ErrorZeroAddress();

    /*************************
     * Public View Functions *
     *************************/

    /// @notice Return the sender of a cross domain message.
    function xDomainMessageSender() external view returns (address);

    /*****************************
     * Public Mutating Functions *
     *****************************/

    /// @notice Send cross chain message from L1 to L2 or L2 to L1.
    /// @param target The address of account who receive the message.
    /// @param value The amount of ether passed when call target contract.
    /// @param message The content of the message.
    /// @param gasLimit Gas limit required to complete the message relay on corresponding chain.
    function sendMessage(
        address target,
        uint256 value,
        bytes calldata message,
        uint256 gasLimit
    ) external payable;

    /// @notice Send cross chain message from L1 to L2 or L2 to L1.
    /// @param target The address of account who receive the message.
    /// @param value The amount of ether passed when call target contract.
    /// @param message The content of the message.
    /// @param gasLimit Gas limit required to complete the message relay on corresponding chain.
    /// @param refundAddress The address of account who will receive the refunded fee.
    function sendMessage(
        address target,
        uint256 value,
        bytes calldata message,
        uint256 gasLimit,
        address refundAddress
    ) external payable;
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.16;

library ScrollConstants {
    /// @notice The address of default cross chain message sender.
    address internal constant DEFAULT_XDOMAIN_MESSAGE_SENDER = address(1);

    /// @notice The address for dropping message.
    /// @dev The first 20 bytes of keccak("drop")
    address internal constant DROP_XDOMAIN_MESSAGE_SENDER = 0x6f297C61B5C92eF107fFD30CD56AFFE5A273e841;
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.16;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

import {ScrollConstants} from "./constants/ScrollConstants.sol";
import {IScrollMessenger} from "./IScrollMessenger.sol";

// solhint-disable var-name-mixedcase

abstract contract ScrollMessengerBase is
    OwnableUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    IScrollMessenger
{
    /**********
     * Events *
     **********/

    /// @notice Emitted when owner updates fee vault contract.
    /// @param _oldFeeVault The address of old fee vault contract.
    /// @param _newFeeVault The address of new fee vault contract.
    event UpdateFeeVault(address _oldFeeVault, address _newFeeVault);

    /*************
     * Constants *
     *************/

    /// @notice The address of counterpart ScrollMessenger contract in L1/L2.
    address public immutable counterpart;

    /*************
     * Variables *
     *************/

    /// @notice See {IScrollMessenger-xDomainMessageSender}
    address public override xDomainMessageSender;

    /// @dev The storage slot used as counterpart ScrollMessenger contract, which is deprecated now.
    address private __counterpart;

    /// @notice The address of fee vault, collecting cross domain messaging fee.
    address public feeVault;

    /// @dev The storage slot used as ETH rate limiter contract, which is deprecated now.
    address private __rateLimiter;

    /// @dev The storage slots for future usage.
    uint256[46] private __gap;

    /**********************
     * Function Modifiers *
     **********************/

    modifier notInExecution() {
        require(
            xDomainMessageSender == ScrollConstants.DEFAULT_XDOMAIN_MESSAGE_SENDER,
            "Message is already in execution"
        );
        _;
    }

    /***************
     * Constructor *
     ***************/

    constructor(address _counterpart) {
        if (_counterpart == address(0)) {
            revert ErrorZeroAddress();
        }

        counterpart = _counterpart;
    }

    function __ScrollMessengerBase_init(address, address _feeVault) internal onlyInitializing {
        OwnableUpgradeable.__Ownable_init();
        PausableUpgradeable.__Pausable_init();
        ReentrancyGuardUpgradeable.__ReentrancyGuard_init();

        // initialize to a nonzero value
        xDomainMessageSender = ScrollConstants.DEFAULT_XDOMAIN_MESSAGE_SENDER;

        if (_feeVault != address(0)) {
            feeVault = _feeVault;
        }
    }

    // make sure only owner can send ether to messenger to avoid possible user fund loss.
    receive() external payable onlyOwner {}

    /************************
     * Restricted Functions *
     ************************/

    /// @notice Update fee vault contract.
    /// @dev This function can only called by contract owner.
    /// @param _newFeeVault The address of new fee vault contract.
    function updateFeeVault(address _newFeeVault) external onlyOwner {
        address _oldFeeVault = feeVault;

        feeVault = _newFeeVault;
        emit UpdateFeeVault(_oldFeeVault, _newFeeVault);
    }

    /// @notice Pause the contract
    /// @dev This function can only called by contract owner.
    /// @param _status The pause status to update.
    function setPause(bool _status) external onlyOwner {
        if (_status) {
            _pause();
        } else {
            _unpause();
        }
    }

    /**********************
     * Internal Functions *
     **********************/

    /// @dev Internal function to generate the correct cross domain calldata for a message.
    /// @param _sender Message sender address.
    /// @param _target Target contract address.
    /// @param _value The amount of ETH pass to the target.
    /// @param _messageNonce Nonce for the provided message.
    /// @param _message Message to send to the target.
    /// @return ABI encoded cross domain calldata.
    function _encodeXDomainCalldata(
        address _sender,
        address _target,
        uint256 _value,
        uint256 _messageNonce,
        bytes memory _message
    ) internal pure returns (bytes memory) {
        return
            abi.encodeWithSignature(
                "relayMessage(address,address,uint256,uint256,bytes)",
                _sender,
                _target,
                _value,
                _messageNonce,
                _message
            );
    }

    /// @dev Internal function to check whether the `_target` address is allowed to avoid attack.
    /// @param _target The address of target address to check.
    function _validateTargetAddress(address _target) internal view {
        // @note check more `_target` address to avoid attack in the future when we add more external contracts.

        require(_target != address(this), "Forbid to call self");
    }
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.16;

interface IMessageDropCallback {
    function onDropMessage(bytes memory message) external payable;
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.16;

// solhint-disable no-inline-assembly

library WithdrawTrieVerifier {
    /// @dev Verify the merkle proof given root, leaf node and proof.
    ///
    /// Vulnerability:
    ///   The initially provided message hash can be hashed with the first hash of the proof,
    ///   thereby giving an intermediate node of the trie. This can then be used with a shortened
    ///   proof to pass the verification, which may lead to replayability.
    ///
    ///   However, it is designed to verify the withdraw trie in `L2MessageQueue`. The `_hash` given
    ///   in the parameter is always a leaf node. So we assume the length of proof is correct and
    ///   cannot be shortened.
    /// @param _root The expected root node hash of the withdraw trie.
    /// @param _hash The leaf node hash of the withdraw trie.
    /// @param _nonce The index of the leaf node from left to right, starting from 0.
    /// @param _proof The concatenated merkle proof verified the leaf node.
    function verifyMerkleProof(
        bytes32 _root,
        bytes32 _hash,
        uint256 _nonce,
        bytes memory _proof
    ) internal pure returns (bool) {
        require(_proof.length % 32 == 0, "Invalid proof");
        uint256 _length = _proof.length / 32;

        for (uint256 i = 0; i < _length; i++) {
            bytes32 item;
            assembly {
                item := mload(add(add(_proof, 0x20), mul(i, 0x20)))
            }
            if (_nonce % 2 == 0) {
                _hash = _efficientHash(_hash, item);
            } else {
                _hash = _efficientHash(item, _hash);
            }
            _nonce /= 2;
        }
        return _hash == _root;
    }

    function _efficientHash(bytes32 a, bytes32 b) private pure returns (bytes32 value) {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            mstore(0x00, a)
            mstore(0x20, b)
            value := keccak256(0x00, 0x40)
        }
    }
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.16;

interface IScrollChain {
    /**********
     * Events *
     **********/

    /// @notice Emitted when a new batch is committed.
    /// @param batchIndex The index of the batch.
    /// @param batchHash The hash of the batch.
    event CommitBatch(uint256 indexed batchIndex, bytes32 indexed batchHash);

    /// @notice revert a pending batch.
    /// @param batchIndex The index of the batch.
    /// @param batchHash The hash of the batch
    event RevertBatch(uint256 indexed batchIndex, bytes32 indexed batchHash);

    /// @notice Emitted when a batch is finalized.
    /// @param batchIndex The index of the batch.
    /// @param batchHash The hash of the batch
    /// @param stateRoot The state root on layer 2 after this batch.
    /// @param withdrawRoot The merkle root on layer2 after this batch.
    event FinalizeBatch(uint256 indexed batchIndex, bytes32 indexed batchHash, bytes32 stateRoot, bytes32 withdrawRoot);

    /**********
     * Errors *
     **********/

    /// @dev Thrown when the given address is `address(0)`.
    error ErrorZeroAddress();

    /*************************
     * Public View Functions *
     *************************/

    /// @notice The latest finalized batch index.
    function lastFinalizedBatchIndex() external view returns (uint256);

    /// @notice Return the batch hash of a committed batch.
    /// @param batchIndex The index of the batch.
    function committedBatches(uint256 batchIndex) external view returns (bytes32);

    /// @notice Return the state root of a committed batch.
    /// @param batchIndex The index of the batch.
    function finalizedStateRoots(uint256 batchIndex) external view returns (bytes32);

    /// @notice Return the message root of a committed batch.
    /// @param batchIndex The index of the batch.
    function withdrawRoots(uint256 batchIndex) external view returns (bytes32);

    /// @notice Return whether the batch is finalized by batch index.
    /// @param batchIndex The index of the batch.
    function isBatchFinalized(uint256 batchIndex) external view returns (bool);

    /*****************************
     * Public Mutating Functions *
     *****************************/

    /// @notice Commit a batch of transactions on layer 1.
    ///
    /// @param version The version of current batch.
    /// @param parentBatchHeader The header of parent batch, see the comments of `BatchHeaderV0Codec`.
    /// @param chunks The list of encoded chunks, see the comments of `ChunkCodec`.
    /// @param skippedL1MessageBitmap The bitmap indicates whether each L1 message is skipped or not.
    function commitBatch(
        uint8 version,
        bytes calldata parentBatchHeader,
        bytes[] memory chunks,
        bytes calldata skippedL1MessageBitmap
    ) external;

    /// @notice Revert a pending batch.
    /// @dev one can only revert unfinalized batches.
    /// @param batchHeader The header of current batch, see the encoding in comments of `commitBatch`.
    /// @param count The number of subsequent batches to revert, including current batch.
    function revertBatch(bytes calldata batchHeader, uint256 count) external;

    /// @notice Finalize a committed batch on layer 1.
    /// @param batchHeader The header of current batch, see the encoding in comments of `commitBatch.
    /// @param prevStateRoot The state root of parent batch.
    /// @param postStateRoot The state root of current batch.
    /// @param withdrawRoot The withdraw trie root of current batch.
    /// @param aggrProof The aggregation proof for current batch.
    function finalizeBatchWithProof(
        bytes calldata batchHeader,
        bytes32 prevStateRoot,
        bytes32 postStateRoot,
        bytes32 withdrawRoot,
        bytes calldata aggrProof
    ) external;
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (access/Ownable.sol)

pragma solidity ^0.8.0;

import "../utils/ContextUpgradeable.sol";
import "../proxy/utils/Initializable.sol";

/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * By default, the owner account will be the one that deploys the contract. This
 * can later be changed with {transferOwnership}.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be applied to your functions to restrict their use to
 * the owner.
 */
abstract contract OwnableUpgradeable is Initializable, ContextUpgradeable {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the deployer as the initial owner.
     */
    function __Ownable_init() internal onlyInitializing {
        __Ownable_init_unchained();
    }

    function __Ownable_init_unchained() internal onlyInitializing {
        _transferOwnership(_msgSender());
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view virtual returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if the sender is not the owner.
     */
    function _checkOwner() internal view virtual {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
    }

    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions. Can only be called by the current owner.
     *
     * NOTE: Renouncing ownership will leave the contract without an owner,
     * thereby disabling any functionality that is only available to the owner.
     */
    function renounceOwnership() public virtual onlyOwner {
        _transferOwnership(address(0));
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        _transferOwnership(newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Internal function without access restriction.
     */
    function _transferOwnership(address newOwner) internal virtual {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[49] private __gap;
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (utils/Context.sol)

pragma solidity ^0.8.0;
import "../proxy/utils/Initializable.sol";

/**
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract ContextUpgradeable is Initializable {
    function __Context_init() internal onlyInitializing {
    }

    function __Context_init_unchained() internal onlyInitializing {
    }
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[50] private __gap;
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (security/ReentrancyGuard.sol)

pragma solidity ^0.8.0;
import "../proxy/utils/Initializable.sol";

/**
 * @dev Contract module that helps prevent reentrant calls to a function.
 *
 * Inheriting from `ReentrancyGuard` will make the {nonReentrant} modifier
 * available, which can be applied to functions to make sure there are no nested
 * (reentrant) calls to them.
 *
 * Note that because there is a single `nonReentrant` guard, functions marked as
 * `nonReentrant` may not call one another. This can be worked around by making
 * those functions `private`, and then adding `external` `nonReentrant` entry
 * points to them.
 *
 * TIP: If you would like to learn more about reentrancy and alternative ways
 * to protect against it, check out our blog post
 * https://blog.openzeppelin.com/reentrancy-after-istanbul/[Reentrancy After Istanbul].
 */
abstract contract ReentrancyGuardUpgradeable is Initializable {
    // Booleans are more expensive than uint256 or any type that takes up a full
    // word because each write operation emits an extra SLOAD to first read the
    // slot's contents, replace the bits taken up by the boolean, and then write
    // back. This is the compiler's defense against contract upgrades and
    // pointer aliasing, and it cannot be disabled.

    // The values being non-zero value makes deployment a bit more expensive,
    // but in exchange the refund on every call to nonReentrant will be lower in
    // amount. Since refunds are capped to a percentage of the total
    // transaction's gas, it is best to keep them low in cases like this one, to
    // increase the likelihood of the full refund coming into effect.
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    uint256 private _status;

    function __ReentrancyGuard_init() internal onlyInitializing {
        __ReentrancyGuard_init_unchained();
    }

    function __ReentrancyGuard_init_unchained() internal onlyInitializing {
        _status = _NOT_ENTERED;
    }

    /**
     * @dev Prevents a contract from calling itself, directly or indirectly.
     * Calling a `nonReentrant` function from another `nonReentrant`
     * function is not supported. It is possible to prevent this from happening
     * by making the `nonReentrant` function external, and making it call a
     * `private` function that does the actual work.
     */
    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    function _nonReentrantBefore() private {
        // On the first call to nonReentrant, _status will be _NOT_ENTERED
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");

        // Any calls to nonReentrant after this point will fail
        _status = _ENTERED;
    }

    function _nonReentrantAfter() private {
        // By storing the original value once again, a refund is triggered (see
        // https://eips.ethereum.org/EIPS/eip-2200)
        _status = _NOT_ENTERED;
    }

    /**
     * @dev Returns true if the reentrancy guard is currently set to "entered", which indicates there is a
     * `nonReentrant` function in the call stack.
     */
    function _reentrancyGuardEntered() internal view returns (bool) {
        return _status == _ENTERED;
    }

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[49] private __gap;
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (utils/Address.sol)

pragma solidity ^0.8.1;

/**
 * @dev Collection of functions related to the address type
 */
library AddressUpgradeable {
    /**
     * @dev Returns true if `account` is a contract.
     *
     * [IMPORTANT]
     * ====
     * It is unsafe to assume that an address for which this function returns
     * false is an externally-owned account (EOA) and not a contract.
     *
     * Among others, `isContract` will return false for the following
     * types of addresses:
     *
     *  - an externally-owned account
     *  - a contract in construction
     *  - an address where a contract will be created
     *  - an address where a contract lived, but was destroyed
     *
     * Furthermore, `isContract` will also return true if the target contract within
     * the same transaction is already scheduled for destruction by `SELFDESTRUCT`,
     * which only has an effect at the end of a transaction.
     * ====
     *
     * [IMPORTANT]
     * ====
     * You shouldn't rely on `isContract` to protect against flash loan attacks!
     *
     * Preventing calls from contracts is highly discouraged. It breaks composability, breaks support for smart wallets
     * like Gnosis Safe, and does not provide security since it can be circumvented by calling from a contract
     * constructor.
     * ====
     */
    function isContract(address account) internal view returns (bool) {
        // This method relies on extcodesize/address.code.length, which returns 0
        // for contracts in construction, since the code is only stored at the end
        // of the constructor execution.

        return account.code.length > 0;
    }

    /**
     * @dev Replacement for Solidity's `transfer`: sends `amount` wei to
     * `recipient`, forwarding all available gas and reverting on errors.
     *
     * https://eips.ethereum.org/EIPS/eip-1884[EIP1884] increases the gas cost
     * of certain opcodes, possibly making contracts go over the 2300 gas limit
     * imposed by `transfer`, making them unable to receive funds via
     * `transfer`. {sendValue} removes this limitation.
     *
     * https://consensys.net/diligence/blog/2019/09/stop-using-soliditys-transfer-now/[Learn more].
     *
     * IMPORTANT: because control is transferred to `recipient`, care must be
     * taken to not create reentrancy vulnerabilities. Consider using
     * {ReentrancyGuard} or the
     * https://solidity.readthedocs.io/en/v0.8.0/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].
     */
    function sendValue(address payable recipient, uint256 amount) internal {
        require(address(this).balance >= amount, "Address: insufficient balance");

        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }

    /**
     * @dev Performs a Solidity function call using a low level `call`. A
     * plain `call` is an unsafe replacement for a function call: use this
     * function instead.
     *
     * If `target` reverts with a revert reason, it is bubbled up by this
     * function (like regular Solidity function calls).
     *
     * Returns the raw returned data. To convert to the expected return value,
     * use https://solidity.readthedocs.io/en/latest/units-and-global-variables.html?highlight=abi.decode#abi-encoding-and-decoding-functions[`abi.decode`].
     *
     * Requirements:
     *
     * - `target` must be a contract.
     * - calling `target` with `data` must not revert.
     *
     * _Available since v3.1._
     */
    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0, "Address: low-level call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`], but with
     * `errorMessage` as a fallback revert reason when `target` reverts.
     *
     * _Available since v3.1._
     */
    function functionCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but also transferring `value` wei to `target`.
     *
     * Requirements:
     *
     * - the calling contract must have an ETH balance of at least `value`.
     * - the called Solidity function must be `payable`.
     *
     * _Available since v3.1._
     */
    function functionCallWithValue(address target, bytes memory data, uint256 value) internal returns (bytes memory) {
        return functionCallWithValue(target, data, value, "Address: low-level call with value failed");
    }

    /**
     * @dev Same as {xref-Address-functionCallWithValue-address-bytes-uint256-}[`functionCallWithValue`], but
     * with `errorMessage` as a fallback revert reason when `target` reverts.
     *
     * _Available since v3.1._
     */
    function functionCallWithValue(
        address target,
        bytes memory data,
        uint256 value,
        string memory errorMessage
    ) internal returns (bytes memory) {
        require(address(this).balance >= value, "Address: insufficient balance for call");
        (bool success, bytes memory returndata) = target.call{value: value}(data);
        return verifyCallResultFromTarget(target, success, returndata, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a static call.
     *
     * _Available since v3.3._
     */
    function functionStaticCall(address target, bytes memory data) internal view returns (bytes memory) {
        return functionStaticCall(target, data, "Address: low-level static call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],
     * but performing a static call.
     *
     * _Available since v3.3._
     */
    function functionStaticCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal view returns (bytes memory) {
        (bool success, bytes memory returndata) = target.staticcall(data);
        return verifyCallResultFromTarget(target, success, returndata, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a delegate call.
     *
     * _Available since v3.4._
     */
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionDelegateCall(target, data, "Address: low-level delegate call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],
     * but performing a delegate call.
     *
     * _Available since v3.4._
     */
    function functionDelegateCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal returns (bytes memory) {
        (bool success, bytes memory returndata) = target.delegatecall(data);
        return verifyCallResultFromTarget(target, success, returndata, errorMessage);
    }

    /**
     * @dev Tool to verify that a low level call to smart-contract was successful, and revert (either by bubbling
     * the revert reason or using the provided one) in case of unsuccessful call or if target was not a contract.
     *
     * _Available since v4.8._
     */
    function verifyCallResultFromTarget(
        address target,
        bool success,
        bytes memory returndata,
        string memory errorMessage
    ) internal view returns (bytes memory) {
        if (success) {
            if (returndata.length == 0) {
                // only check isContract if the call was successful and the return data is empty
                // otherwise we already know that it was a contract
                require(isContract(target), "Address: call to non-contract");
            }
            return returndata;
        } else {
            _revert(returndata, errorMessage);
        }
    }

    /**
     * @dev Tool to verify that a low level call was successful, and revert if it wasn't, either by bubbling the
     * revert reason or using the provided one.
     *
     * _Available since v4.3._
     */
    function verifyCallResult(
        bool success,
        bytes memory returndata,
        string memory errorMessage
    ) internal pure returns (bytes memory) {
        if (success) {
            return returndata;
        } else {
            _revert(returndata, errorMessage);
        }
    }

    function _revert(bytes memory returndata, string memory errorMessage) private pure {
        // Look for revert reason and bubble it up if present
        if (returndata.length > 0) {
            // The easiest way to bubble the revert reason is using memory via assembly
            /// @solidity memory-safe-assembly
            assembly {
                let returndata_size := mload(returndata)
                revert(add(32, returndata), returndata_size)
            }
        } else {
            revert(errorMessage);
        }
    }
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.16;

import {IScrollMessenger} from "../libraries/IScrollMessenger.sol";

interface IL1ScrollMessenger is IScrollMessenger {
    /**********
     * Events *
     **********/

    /// @notice Emitted when the maximum number of times each message can be replayed is updated.
    /// @param oldMaxReplayTimes The old maximum number of times each message can be replayed.
    /// @param newMaxReplayTimes The new maximum number of times each message can be replayed.
    event UpdateMaxReplayTimes(uint256 oldMaxReplayTimes, uint256 newMaxReplayTimes);

    /***********
     * Structs *
     ***********/

    struct L2MessageProof {
        // The index of the batch where the message belongs to.
        uint256 batchIndex;
        // Concatenation of merkle proof for withdraw merkle trie.
        bytes merkleProof;
    }

    /*****************************
     * Public Mutating Functions *
     *****************************/

    /// @notice Relay a L2 => L1 message with message proof.
    /// @param from The address of the sender of the message.
    /// @param to The address of the recipient of the message.
    /// @param value The msg.value passed to the message call.
    /// @param nonce The nonce of the message to avoid replay attack.
    /// @param message The content of the message.
    /// @param proof The proof used to verify the correctness of the transaction.
    function relayMessageWithProof(
        address from,
        address to,
        uint256 value,
        uint256 nonce,
        bytes memory message,
        L2MessageProof memory proof
    ) external;

    /// @notice Replay an existing message.
    /// @param from The address of the sender of the message.
    /// @param to The address of the recipient of the message.
    /// @param value The msg.value passed to the message call.
    /// @param messageNonce The nonce for the message to replay.
    /// @param message The content of the message.
    /// @param newGasLimit New gas limit to be used for this message.
    /// @param refundAddress The address of account who will receive the refunded fee.
    function replayMessage(
        address from,
        address to,
        uint256 value,
        uint256 messageNonce,
        bytes memory message,
        uint32 newGasLimit,
        address refundAddress
    ) external payable;

    /// @notice Drop a skipped message.
    /// @param from The address of the sender of the message.
    /// @param to The address of the recipient of the message.
    /// @param value The msg.value passed to the message call.
    /// @param messageNonce The nonce for the message to drop.
    /// @param message The content of the message.
    function dropMessage(
        address from,
        address to,
        uint256 value,
        uint256 messageNonce,
        bytes memory message
    ) external;
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.16;

interface IL1MessageQueue {
    /**********
     * Events *
     **********/

    /// @notice Emitted when a new L1 => L2 transaction is appended to the queue.
    /// @param sender The address of account who initiates the transaction.
    /// @param target The address of account who will receive the transaction.
    /// @param value The value passed with the transaction.
    /// @param queueIndex The index of this transaction in the queue.
    /// @param gasLimit Gas limit required to complete the message relay on L2.
    /// @param data The calldata of the transaction.
    event QueueTransaction(
        address indexed sender,
        address indexed target,
        uint256 value,
        uint64 queueIndex,
        uint256 gasLimit,
        bytes data
    );

    /// @notice Emitted when some L1 => L2 transactions are included in L1.
    /// @param startIndex The start index of messages popped.
    /// @param count The number of messages popped.
    /// @param skippedBitmap A bitmap indicates whether a message is skipped.
    event DequeueTransaction(uint256 startIndex, uint256 count, uint256 skippedBitmap);

    /// @notice Emitted when a message is dropped from L1.
    /// @param index The index of message dropped.
    event DropTransaction(uint256 index);

    /// @notice Emitted when owner updates gas oracle contract.
    /// @param _oldGasOracle The address of old gas oracle contract.
    /// @param _newGasOracle The address of new gas oracle contract.
    event UpdateGasOracle(address indexed _oldGasOracle, address indexed _newGasOracle);

    /// @notice Emitted when owner updates max gas limit.
    /// @param _oldMaxGasLimit The old max gas limit.
    /// @param _newMaxGasLimit The new max gas limit.
    event UpdateMaxGasLimit(uint256 _oldMaxGasLimit, uint256 _newMaxGasLimit);

    /**********
     * Errors *
     **********/

    /// @dev Thrown when the given address is `address(0)`.
    error ErrorZeroAddress();

    /*************************
     * Public View Functions *
     *************************/

    /// @notice The start index of all pending inclusion messages.
    function pendingQueueIndex() external view returns (uint256);

    /// @notice Return the index of next appended message.
    /// @dev Also the total number of appended messages.
    function nextCrossDomainMessageIndex() external view returns (uint256);

    /// @notice Return the message of in `queueIndex`.
    /// @param queueIndex The index to query.
    function getCrossDomainMessage(uint256 queueIndex) external view returns (bytes32);

    /// @notice Return the amount of ETH should pay for cross domain message.
    /// @param gasLimit Gas limit required to complete the message relay on L2.
    function estimateCrossDomainMessageFee(uint256 gasLimit) external view returns (uint256);

    /// @notice Return the amount of intrinsic gas fee should pay for cross domain message.
    /// @param _calldata The calldata of L1-initiated transaction.
    function calculateIntrinsicGasFee(bytes calldata _calldata) external view returns (uint256);

    /// @notice Return the hash of a L1 message.
    /// @param sender The address of sender.
    /// @param queueIndex The queue index of this message.
    /// @param value The amount of Ether transfer to target.
    /// @param target The address of target.
    /// @param gasLimit The gas limit provided.
    /// @param data The calldata passed to target address.
    function computeTransactionHash(
        address sender,
        uint256 queueIndex,
        uint256 value,
        address target,
        uint256 gasLimit,
        bytes calldata data
    ) external view returns (bytes32);

    /// @notice Return whether the message is skipped.
    /// @param queueIndex The queue index of the message to check.
    function isMessageSkipped(uint256 queueIndex) external view returns (bool);

    /// @notice Return whether the message is dropped.
    /// @param queueIndex The queue index of the message to check.
    function isMessageDropped(uint256 queueIndex) external view returns (bool);

    /*****************************
     * Public Mutating Functions *
     *****************************/

    /// @notice Append a L1 to L2 message into this contract.
    /// @param target The address of target contract to call in L2.
    /// @param gasLimit The maximum gas should be used for relay this message in L2.
    /// @param data The calldata passed to target contract.
    function appendCrossDomainMessage(
        address target,
        uint256 gasLimit,
        bytes calldata data
    ) external;

    /// @notice Append an enforced transaction to this contract.
    /// @dev The address of sender should be an EOA.
    /// @param sender The address of sender who will initiate this transaction in L2.
    /// @param target The address of target contract to call in L2.
    /// @param value The value passed
    /// @param gasLimit The maximum gas should be used for this transaction in L2.
    /// @param data The calldata passed to target contract.
    function appendEnforcedTransaction(
        address sender,
        address target,
        uint256 value,
        uint256 gasLimit,
        bytes calldata data
    ) external;

    /// @notice Pop finalized messages from queue.
    ///
    /// @dev We can pop at most 256 messages each time. And if the message is not skipped,
    ///      the corresponding entry will be cleared.
    ///
    /// @param startIndex The start index to pop.
    /// @param count The number of messages to pop.
    /// @param skippedBitmap A bitmap indicates whether a message is skipped.
    function popCrossDomainMessage(
        uint256 startIndex,
        uint256 count,
        uint256 skippedBitmap
    ) external;

    /// @notice Drop a skipped message from the queue.
    function dropCrossDomainMessage(uint256 index) external;
}

