// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import { AssetType, OrderType, Transfer } from "../lib/Structs.sol";

interface IDelegate {
    function transfer(
        address caller,
        OrderType orderType,
        Transfer[] calldata transfers,
        uint256 length
    ) external returns (bool[] memory successful);
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.5.0) (interfaces/draft-IERC1822.sol)

pragma solidity ^0.8.0;

/**
 * @dev ERC1822: Universal Upgradeable Proxy Standard (UUPS) documents a method for upgradeability through a simplified
 * proxy whose upgrades are fully controlled by the current implementation.
 */
interface IERC1822ProxiableUpgradeable {
    /**
     * @dev Returns the storage slot that the proxiable contract assumes is being used to store the implementation
     * address.
     *
     * IMPORTANT: A proxy pointing at a proxiable contract should not be considered proxiable itself, because this risks
     * bricking a proxy that upgrades to it, by delegating to itself until out of gas. Thus it is critical that this
     * function revert if invoked through a proxy.
     */
    function proxiableUUID() external view returns (bytes32);
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import {
    Fees,
    FeeRate,
    Transfer,
    OrderType
} from "../lib/Structs.sol";

interface IExecutor {
    error ETHTransferFailed();
    error PoolTransferFailed();
    error PoolWithdrawFromFailed();
    error PoolDepositFailed();
    error OrderFulfilled();

    event Execution(
        Transfer transfer,
        bytes32 orderHash,
        uint256 listingIndex,
        uint256 price,
        FeeRate makerFee,
        Fees fees,
        OrderType orderType
    );

    event Execution721Packed(
        bytes32 orderHash,
        uint256 tokenIdListingIndexTrader,
        uint256 collectionPriceSide
    );

    event Execution721TakerFeePacked(
        bytes32 orderHash,
        uint256 tokenIdListingIndexTrader,
        uint256 collectionPriceSide,
        uint256 takerFeeRecipientRate
    );

    event Execution721MakerFeePacked(
        bytes32 orderHash,
        uint256 tokenIdListingIndexTrader,
        uint256 collectionPriceSide,
        uint256 makerFeeRecipientRate
    );
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.8.0) (utils/cryptography/MerkleProof.sol)

pragma solidity ^0.8.0;

/**
 * @dev These functions deal with verification of Merkle Tree proofs.
 *
 * The tree and the proofs can be generated using our
 * https://github.com/OpenZeppelin/merkle-tree[JavaScript library].
 * You will find a quickstart guide in the readme.
 *
 * WARNING: You should avoid using leaf values that are 64 bytes long prior to
 * hashing, or use a hash function other than keccak256 for hashing leaves.
 * This is because the concatenation of a sorted pair of internal nodes in
 * the merkle tree could be reinterpreted as a leaf value.
 * OpenZeppelin's JavaScript library generates merkle trees that are safe
 * against this attack out of the box.
 */
library MerkleProof {
    /**
     * @dev Returns true if a `leaf` can be proved to be a part of a Merkle tree
     * defined by `root`. For this, a `proof` must be provided, containing
     * sibling hashes on the branch from the leaf to the root of the tree. Each
     * pair of leaves and each pair of pre-images are assumed to be sorted.
     */
    function verify(bytes32[] memory proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        return processProof(proof, leaf) == root;
    }

    /**
     * @dev Calldata version of {verify}
     *
     * _Available since v4.7._
     */
    function verifyCalldata(bytes32[] calldata proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        return processProofCalldata(proof, leaf) == root;
    }

    /**
     * @dev Returns the rebuilt hash obtained by traversing a Merkle tree up
     * from `leaf` using `proof`. A `proof` is valid if and only if the rebuilt
     * hash matches the root of the tree. When processing the proof, the pairs
     * of leafs & pre-images are assumed to be sorted.
     *
     * _Available since v4.4._
     */
    function processProof(bytes32[] memory proof, bytes32 leaf) internal pure returns (bytes32) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computedHash = _hashPair(computedHash, proof[i]);
        }
        return computedHash;
    }

    /**
     * @dev Calldata version of {processProof}
     *
     * _Available since v4.7._
     */
    function processProofCalldata(bytes32[] calldata proof, bytes32 leaf) internal pure returns (bytes32) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computedHash = _hashPair(computedHash, proof[i]);
        }
        return computedHash;
    }

    /**
     * @dev Returns true if the `leaves` can be simultaneously proven to be a part of a merkle tree defined by
     * `root`, according to `proof` and `proofFlags` as described in {processMultiProof}.
     *
     * CAUTION: Not all merkle trees admit multiproofs. See {processMultiProof} for details.
     *
     * _Available since v4.7._
     */
    function multiProofVerify(
        bytes32[] memory proof,
        bool[] memory proofFlags,
        bytes32 root,
        bytes32[] memory leaves
    ) internal pure returns (bool) {
        return processMultiProof(proof, proofFlags, leaves) == root;
    }

    /**
     * @dev Calldata version of {multiProofVerify}
     *
     * CAUTION: Not all merkle trees admit multiproofs. See {processMultiProof} for details.
     *
     * _Available since v4.7._
     */
    function multiProofVerifyCalldata(
        bytes32[] calldata proof,
        bool[] calldata proofFlags,
        bytes32 root,
        bytes32[] memory leaves
    ) internal pure returns (bool) {
        return processMultiProofCalldata(proof, proofFlags, leaves) == root;
    }

    /**
     * @dev Returns the root of a tree reconstructed from `leaves` and sibling nodes in `proof`. The reconstruction
     * proceeds by incrementally reconstructing all inner nodes by combining a leaf/inner node with either another
     * leaf/inner node or a proof sibling node, depending on whether each `proofFlags` item is true or false
     * respectively.
     *
     * CAUTION: Not all merkle trees admit multiproofs. To use multiproofs, it is sufficient to ensure that: 1) the tree
     * is complete (but not necessarily perfect), 2) the leaves to be proven are in the opposite order they are in the
     * tree (i.e., as seen from right to left starting at the deepest layer and continuing at the next layer).
     *
     * _Available since v4.7._
     */
    function processMultiProof(
        bytes32[] memory proof,
        bool[] memory proofFlags,
        bytes32[] memory leaves
    ) internal pure returns (bytes32 merkleRoot) {
        // This function rebuilds the root hash by traversing the tree up from the leaves. The root is rebuilt by
        // consuming and producing values on a queue. The queue starts with the `leaves` array, then goes onto the
        // `hashes` array. At the end of the process, the last hash in the `hashes` array should contain the root of
        // the merkle tree.
        uint256 leavesLen = leaves.length;
        uint256 totalHashes = proofFlags.length;

        // Check proof validity.
        require(leavesLen + proof.length - 1 == totalHashes, "MerkleProof: invalid multiproof");

        // The xxxPos values are "pointers" to the next value to consume in each array. All accesses are done using
        // `xxx[xxxPos++]`, which return the current value and increment the pointer, thus mimicking a queue's "pop".
        bytes32[] memory hashes = new bytes32[](totalHashes);
        uint256 leafPos = 0;
        uint256 hashPos = 0;
        uint256 proofPos = 0;
        // At each step, we compute the next hash using two values:
        // - a value from the "main queue". If not all leaves have been consumed, we get the next leaf, otherwise we
        //   get the next hash.
        // - depending on the flag, either another value from the "main queue" (merging branches) or an element from the
        //   `proof` array.
        for (uint256 i = 0; i < totalHashes; i++) {
            bytes32 a = leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++];
            bytes32 b = proofFlags[i]
                ? (leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++])
                : proof[proofPos++];
            hashes[i] = _hashPair(a, b);
        }

        if (totalHashes > 0) {
            unchecked {
                return hashes[totalHashes - 1];
            }
        } else if (leavesLen > 0) {
            return leaves[0];
        } else {
            return proof[0];
        }
    }

    /**
     * @dev Calldata version of {processMultiProof}.
     *
     * CAUTION: Not all merkle trees admit multiproofs. See {processMultiProof} for details.
     *
     * _Available since v4.7._
     */
    function processMultiProofCalldata(
        bytes32[] calldata proof,
        bool[] calldata proofFlags,
        bytes32[] memory leaves
    ) internal pure returns (bytes32 merkleRoot) {
        // This function rebuilds the root hash by traversing the tree up from the leaves. The root is rebuilt by
        // consuming and producing values on a queue. The queue starts with the `leaves` array, then goes onto the
        // `hashes` array. At the end of the process, the last hash in the `hashes` array should contain the root of
        // the merkle tree.
        uint256 leavesLen = leaves.length;
        uint256 totalHashes = proofFlags.length;

        // Check proof validity.
        require(leavesLen + proof.length - 1 == totalHashes, "MerkleProof: invalid multiproof");

        // The xxxPos values are "pointers" to the next value to consume in each array. All accesses are done using
        // `xxx[xxxPos++]`, which return the current value and increment the pointer, thus mimicking a queue's "pop".
        bytes32[] memory hashes = new bytes32[](totalHashes);
        uint256 leafPos = 0;
        uint256 hashPos = 0;
        uint256 proofPos = 0;
        // At each step, we compute the next hash using two values:
        // - a value from the "main queue". If not all leaves have been consumed, we get the next leaf, otherwise we
        //   get the next hash.
        // - depending on the flag, either another value from the "main queue" (merging branches) or an element from the
        //   `proof` array.
        for (uint256 i = 0; i < totalHashes; i++) {
            bytes32 a = leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++];
            bytes32 b = proofFlags[i]
                ? (leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++])
                : proof[proofPos++];
            hashes[i] = _hashPair(a, b);
        }

        if (totalHashes > 0) {
            unchecked {
                return hashes[totalHashes - 1];
            }
        } else if (leavesLen > 0) {
            return leaves[0];
        } else {
            return proof[0];
        }
    }

    function _hashPair(bytes32 a, bytes32 b) private pure returns (bytes32) {
        return a < b ? _efficientHash(a, b) : _efficientHash(b, a);
    }

    function _efficientHash(bytes32 a, bytes32 b) private pure returns (bytes32 value) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, a)
            mstore(0x20, b)
            value := keccak256(0x00, 0x40)
        }
    }
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
// OpenZeppelin Contracts v4.4.1 (proxy/beacon/IBeacon.sol)

pragma solidity ^0.8.0;

/**
 * @dev This is the interface that {BeaconProxy} expects of its beacon.
 */
interface IBeaconUpgradeable {
    /**
     * @dev Must return an address that can be used as a delegate call target.
     *
     * {BeaconProxy} will check that this address is a contract.
     */
    function implementation() external view returns (address);
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import { FeeRate } from "../lib/Structs.sol";

interface IValidation {
    function protocolFee() external view returns (address, uint16);

    function amountTaken(address user, bytes32 hash, uint256 listingIndex) external view returns (uint256);
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.8.1) (proxy/utils/Initializable.sol)

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
 * ```
 * contract MyToken is ERC20Upgradeable {
 *     function initialize() initializer public {
 *         __ERC20_init("MyToken", "MTK");
 *     }
 * }
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
        if (_initialized < type(uint8).max) {
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

// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.17;

/// @notice Upgradeable gas optimized reentrancy protection for smart contracts.
/// @author Modified from Solmate (https://github.com/transmissions11/solmate/blob/main/src/utils/ReentrancyGuard.sol)
abstract contract ReentrancyGuardUpgradeable {
    uint256 private locked;

    function __Reentrancy_init() internal {
        locked = 1;
    }

    modifier nonReentrant() virtual {
        require(locked == 1, "REENTRANCY");

        locked = 2;

        _;

        locked = 1;
    }

    uint256[49] private __gap;
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import { MerkleProof } from "lib/openzeppelin-contracts/contracts/utils/cryptography/MerkleProof.sol";

import { Signatures } from "./Signatures.sol";
import { AssetType, Order, Exchange, Listing, OrderType, FeeRate, Fees, Taker } from "./lib/Structs.sol";
import { IValidation } from "./interfaces/IValidation.sol";

abstract contract Validation is IValidation, Signatures {
    uint256 internal constant _BASIS_POINTS = 10_000;
    uint256 internal constant _MAX_PROTOCOL_FEE_RATE = 250;

    FeeRate public protocolFee;

    /* amountTaken[user][orderHash][listingIndex] */
    mapping(address => mapping(bytes32 => mapping(uint256 => uint256))) public amountTaken;

    constructor(address proxy) Signatures(proxy) {}

    /**
     * @notice Check if an order has expired
     * @param order Order to check liveness
     * @return Order is live
     */
    function _checkLiveness(Order memory order) private view returns (bool) {
        return (order.expirationTime > block.timestamp);
    }

    /**
     * @notice Check that the fees to be taken will not overflow the purchase price
     * @param makerFee Maker fee amount
     * @param fees Protocol and taker fee rates
     * @return Fees are valid
     */
    function _checkFee(FeeRate memory makerFee, Fees memory fees) private pure returns (bool) {
        return makerFee.rate + fees.takerFee.rate + fees.protocolFee.rate <= _BASIS_POINTS;
    }

    /**
     * @notice Validate a list of orders and prepare arrays for recording pending fulfillments
     * @param orders List of orders
     * @param orderType Order type for all orders
     * @param signatures Bytes array of the order signatures
     * @param fees Protocol and taker fee rates
     */
    function _validateOrders(
        Order[] memory orders,
        OrderType orderType,
        bytes memory signatures,
        Fees memory fees
    ) internal view returns (bool[] memory validOrders, uint256[][] memory pendingAmountTaken) {
        uint256 ordersLength = orders.length;
        validOrders = new bool[](ordersLength);
        pendingAmountTaken = new uint256[][](ordersLength);
        for (uint256 i; i < ordersLength; ) {
            pendingAmountTaken[i] = new uint256[](orders[i].numberOfListings);
            validOrders[i] = _validateOrder(orders[i], orderType, signatures, fees, i);
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Validate an order
     * @param order Order to validate
     * @param orderType Order type
     * @param signatures Bytes array of order signatures
     * @param fees Protocol and taker fee rates
     * @param signatureIndex Index of the order signature
     * @return Validity of the order
     */
    function _validateOrder(
        Order memory order,
        OrderType orderType,
        bytes memory signatures,
        Fees memory fees,
        uint256 signatureIndex
    ) internal view returns (bool) {
        bytes32 orderHash = hashOrder(order, orderType);

        /* After hashing, the salt is no longer needed so we can store the order hash here. */
        order.salt = uint256(orderHash);

        return _verifyAuthorization(
            order.trader,
            orderHash,
            signatures,
            signatureIndex
        ) &&
            _checkLiveness(order) &&
            _checkFee(order.makerFee, fees);
    }

    /**
     * @notice Validate a listing (only valid if the order has be prevalidated)
     * @dev Validation can be manipulated by inputting the same order twice in the orders array,
     * which will effectively bypass the `pendingAmountTaken` check. There is a safety check at the
     * execution phase that will revert the transaction if this manipulation overdraws an order.
     * @param order Order of the listing
     * @param orderType Order type
     * @param exchange Exchange containing the listing
     * @param validOrders List indicated which orders were validated
     * @param pendingAmountTaken Pending fulfillments from the current batch
     * @return validListing Validity of the listing
     */
    function _validateListingFromBatch(
        Order memory order,
        OrderType orderType,
        Exchange memory exchange,
        bool[] memory validOrders,
        uint256[][] memory pendingAmountTaken
    ) internal view returns (bool validListing) {
        Listing memory listing = exchange.listing;
        uint256 listingIndex = listing.index;
        uint256 amountTaken = amountTaken[order.trader][bytes32(order.salt)][listingIndex];
        uint256 pendingAmountTaken = pendingAmountTaken[exchange.index][listingIndex];
        uint256 takerAmount = exchange.taker.amount;
        unchecked {
            validListing =
                validOrders[exchange.index] &&
                _validateListing(order, orderType, exchange) &&
                pendingAmountTaken + takerAmount <= type(uint256).max - amountTaken &&
                amountTaken + pendingAmountTaken + takerAmount <= listing.amount;
        }
    }

    /**
     * @notice Validate a listing and its proposed exchange
     * @param order Order of the listing
     * @param orderType Order type
     * @param exchange Exchange containing the listing
     * @return validListing Validity of the listing and its proposed exchange
     */
    function _validateListing(
        Order memory order,
        OrderType orderType,
        Exchange memory exchange
    ) private pure returns (bool validListing) {
        Listing memory listing = exchange.listing;
        validListing = MerkleProof.verify(exchange.proof, order.listingsRoot, hashListing(listing));
        Taker memory taker = exchange.taker;
        if (orderType == OrderType.ASK) {
            if (order.assetType == AssetType.ERC721) {
                validListing = validListing && taker.amount == 1 && listing.amount == 1;
            }
            validListing = validListing && listing.tokenId == taker.tokenId;
        } else {
            if (order.assetType == AssetType.ERC721) {
                validListing = validListing && taker.amount == 1;
            } else {
                validListing = validListing && listing.tokenId == taker.tokenId;
            }
        }
    }

    /**
     * @notice Validate both the listing and it's parent order (only for single executions)
     * @param order Order of the listing
     * @param orderType Order type
     * @param exchange Exchange containing the listing
     * @param signature Order signature
     * @param fees Protocol and taker fee rates
     * @return Validity of the order and listing
     */
    function _validateOrderAndListing(
        Order memory order,
        OrderType orderType,
        Exchange memory exchange,
        bytes memory signature,
        Fees memory fees
    ) internal view returns (bool) {
        Listing memory listing = exchange.listing;
        uint256 listingIndex = listing.index;
        return
            _validateOrder(order, orderType, signature, fees, 0) &&
            _validateListing(order, orderType, exchange) &&
            amountTaken[order.trader][bytes32(order.salt)][listingIndex] + exchange.taker.amount <=
            listing.amount;
    }

    uint256[49] private __gap;
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import {
    TakeAsk,
    TakeBid,
    TakeAskSingle,
    TakeBidSingle,
    Order,
    OrderType,
    Listing
} from "../lib/Structs.sol";

interface ISignatures {
    error Unauthorized();
    error ExpiredOracleSignature();
    error UnauthorizedOracle();
    error InvalidOracleSignature();
    error InvalidDomain();

    function oracles(address oracle) external view returns (uint256);
    function nonces(address user) external view returns (uint256);
    function blockRange() external view returns (uint256);

    function verifyDomain() external view;

    function information() external view returns (string memory version, bytes32 domainSeparator);
    function hashListing(Listing memory listing) external pure returns (bytes32);
    function hashOrder(Order memory order, OrderType orderType) external view returns (bytes32);
    function hashTakeAsk(TakeAsk memory inputs, address _caller) external pure returns (bytes32);
    function hashTakeBid(TakeBid memory inputs, address _caller) external pure returns (bytes32);
    function hashTakeAskSingle(TakeAskSingle memory inputs, address _caller) external pure returns (bytes32);
    function hashTakeBidSingle(TakeBidSingle memory inputs, address _caller) external pure returns (bytes32);
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.7.0) (utils/StorageSlot.sol)

pragma solidity ^0.8.0;

/**
 * @dev Library for reading and writing primitive types to specific storage slots.
 *
 * Storage slots are often used to avoid storage conflict when dealing with upgradeable contracts.
 * This library helps with reading and writing to such slots without the need for inline assembly.
 *
 * The functions in this library return Slot structs that contain a `value` member that can be used to read or write.
 *
 * Example usage to set ERC1967 implementation slot:
 * ```
 * contract ERC1967 {
 *     bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
 *
 *     function _getImplementation() internal view returns (address) {
 *         return StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value;
 *     }
 *
 *     function _setImplementation(address newImplementation) internal {
 *         require(Address.isContract(newImplementation), "ERC1967: new implementation is not a contract");
 *         StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value = newImplementation;
 *     }
 * }
 * ```
 *
 * _Available since v4.1 for `address`, `bool`, `bytes32`, and `uint256`._
 */
library StorageSlotUpgradeable {
    struct AddressSlot {
        address value;
    }

    struct BooleanSlot {
        bool value;
    }

    struct Bytes32Slot {
        bytes32 value;
    }

    struct Uint256Slot {
        uint256 value;
    }

    /**
     * @dev Returns an `AddressSlot` with member `value` located at `slot`.
     */
    function getAddressSlot(bytes32 slot) internal pure returns (AddressSlot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `BooleanSlot` with member `value` located at `slot`.
     */
    function getBooleanSlot(bytes32 slot) internal pure returns (BooleanSlot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `Bytes32Slot` with member `value` located at `slot`.
     */
    function getBytes32Slot(bytes32 slot) internal pure returns (Bytes32Slot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `Uint256Slot` with member `value` located at `slot`.
     */
    function getUint256Slot(bytes32 slot) internal pure returns (Uint256Slot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := slot
        }
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.8.3) (interfaces/IERC1967.sol)

pragma solidity ^0.8.0;

/**
 * @dev ERC-1967: Proxy Storage Slots. This interface contains the events defined in the ERC.
 *
 * _Available since v4.9._
 */
interface IERC1967Upgradeable {
    /**
     * @dev Emitted when the implementation is upgraded.
     */
    event Upgraded(address indexed implementation);

    /**
     * @dev Emitted when the admin account has changed.
     */
    event AdminChanged(address previousAdmin, address newAdmin);

    /**
     * @dev Emitted when the beacon is changed.
     */
    event BeaconUpgraded(address indexed beacon);
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.8.0) (proxy/utils/UUPSUpgradeable.sol)

pragma solidity ^0.8.0;

import "../../interfaces/draft-IERC1822Upgradeable.sol";
import "../ERC1967/ERC1967UpgradeUpgradeable.sol";
import "./Initializable.sol";

/**
 * @dev An upgradeability mechanism designed for UUPS proxies. The functions included here can perform an upgrade of an
 * {ERC1967Proxy}, when this contract is set as the implementation behind such a proxy.
 *
 * A security mechanism ensures that an upgrade does not turn off upgradeability accidentally, although this risk is
 * reinstated if the upgrade retains upgradeability but removes the security mechanism, e.g. by replacing
 * `UUPSUpgradeable` with a custom implementation of upgrades.
 *
 * The {_authorizeUpgrade} function must be overridden to include access restriction to the upgrade mechanism.
 *
 * _Available since v4.1._
 */
abstract contract UUPSUpgradeable is Initializable, IERC1822ProxiableUpgradeable, ERC1967UpgradeUpgradeable {
    function __UUPSUpgradeable_init() internal onlyInitializing {
    }

    function __UUPSUpgradeable_init_unchained() internal onlyInitializing {
    }
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable state-variable-assignment
    address private immutable __self = address(this);

    /**
     * @dev Check that the execution is being performed through a delegatecall call and that the execution context is
     * a proxy contract with an implementation (as defined in ERC1967) pointing to self. This should only be the case
     * for UUPS and transparent proxies that are using the current contract as their implementation. Execution of a
     * function through ERC1167 minimal proxies (clones) would not normally pass this test, but is not guaranteed to
     * fail.
     */
    modifier onlyProxy() {
        require(address(this) != __self, "Function must be called through delegatecall");
        require(_getImplementation() == __self, "Function must be called through active proxy");
        _;
    }

    /**
     * @dev Check that the execution is not being performed through a delegate call. This allows a function to be
     * callable on the implementing contract but not through proxies.
     */
    modifier notDelegated() {
        require(address(this) == __self, "UUPSUpgradeable: must not be called through delegatecall");
        _;
    }

    /**
     * @dev Implementation of the ERC1822 {proxiableUUID} function. This returns the storage slot used by the
     * implementation. It is used to validate the implementation's compatibility when performing an upgrade.
     *
     * IMPORTANT: A proxy pointing at a proxiable contract should not be considered proxiable itself, because this risks
     * bricking a proxy that upgrades to it, by delegating to itself until out of gas. Thus it is critical that this
     * function revert if invoked through a proxy. This is guaranteed by the `notDelegated` modifier.
     */
    function proxiableUUID() external view virtual override notDelegated returns (bytes32) {
        return _IMPLEMENTATION_SLOT;
    }

    /**
     * @dev Upgrade the implementation of the proxy to `newImplementation`.
     *
     * Calls {_authorizeUpgrade}.
     *
     * Emits an {Upgraded} event.
     */
    function upgradeTo(address newImplementation) external virtual onlyProxy {
        _authorizeUpgrade(newImplementation);
        _upgradeToAndCallUUPS(newImplementation, new bytes(0), false);
    }

    /**
     * @dev Upgrade the implementation of the proxy to `newImplementation`, and subsequently execute the function call
     * encoded in `data`.
     *
     * Calls {_authorizeUpgrade}.
     *
     * Emits an {Upgraded} event.
     */
    function upgradeToAndCall(address newImplementation, bytes memory data) external payable virtual onlyProxy {
        _authorizeUpgrade(newImplementation);
        _upgradeToAndCallUUPS(newImplementation, data, true);
    }

    /**
     * @dev Function that should revert when `msg.sender` is not authorized to upgrade the contract. Called by
     * {upgradeTo} and {upgradeToAndCall}.
     *
     * Normally, this function will use an xref:access.adoc[access control] modifier such as {Ownable-onlyOwner}.
     *
     * ```solidity
     * function _authorizeUpgrade(address) internal override onlyOwner {}
     * ```
     */
    function _authorizeUpgrade(address newImplementation) internal virtual;

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[50] private __gap;
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import { Ownable2StepUpgradeable } from "lib/openzeppelin-contracts-upgradeable/contracts/access/Ownable2StepUpgradeable.sol";
import { UUPSUpgradeable } from "lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";

import { Executor } from "./Executor.sol";
import "./lib/Constants.sol";
import {
    TakeAsk,
    TakeBid,
    TakeAskSingle,
    TakeBidSingle,
    Order,
    Exchange,
    Fees,
    FeeRate,
    AssetType,
    OrderType,
    Transfer,
    FungibleTransfers,
    StateUpdate,
    AtomicExecution,
    Cancel,
    Listing
} from "./lib/Structs.sol";
import { IBlurExchangeV2 } from "./interfaces/IBlurExchangeV2.sol";
import { ReentrancyGuardUpgradeable } from "./lib/ReentrancyGuardUpgradeable.sol";

contract BlurExchangeV2 is
    IBlurExchangeV2,
    Ownable2StepUpgradeable,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable,
    Executor
{
    address public governor;

    // required by the OZ UUPS module
    function _authorizeUpgrade(address) internal override onlyOwner {}

    constructor(address delegate, address pool, address proxy) Executor(delegate, pool, proxy) {
        _disableInitializers();
    }

    function initialize() external initializer {
        __UUPSUpgradeable_init();
        __Ownable_init();
        __Reentrancy_init();
        verifyDomain();
    }

    modifier onlyGovernor() {
        if (msg.sender != governor) {
            revert Unauthorized();
        }
        _;
    }

    /**
     * @notice Governor only function to set the protocol fee rate and recipient
     * @param recipient Protocol fee recipient
     * @param rate Protocol fee rate
     */
    function setProtocolFee(address recipient, uint16 rate) external onlyGovernor {
        if (rate > _MAX_PROTOCOL_FEE_RATE) {
            revert ProtocolFeeTooHigh();
        }
        protocolFee = FeeRate(recipient, rate);
        emit NewProtocolFee(recipient, rate);
    }

    /**
     * @notice Admin only function to set the governor of the exchange
     * @param _governor Address of governor to set
     */
    function setGovernor(address _governor) external onlyOwner {
        governor = _governor;
        emit NewGovernor(_governor);
    }

    /**
     * @notice Admin only function to grant or revoke the approval of an oracle
     * @param oracle Address to set approval of
     * @param approved If the oracle should be approved or not
     */
    function setOracle(address oracle, bool approved) external onlyOwner {
        if (approved) {
            oracles[oracle] = 1;
        } else {
            oracles[oracle] = 0;
        }
        emit SetOracle(oracle, approved);
    }

    /**
     * @notice Admin only function to set the block range
     * @param _blockRange Block range that oracle signatures are valid for
     */
    function setBlockRange(uint256 _blockRange) external onlyOwner {
        blockRange = _blockRange;
        emit NewBlockRange(_blockRange);
    }

    /**
     * @notice Cancel listings by recording their fulfillment
     * @param cancels List of cancels to execute
     */
    function cancelTrades(Cancel[] memory cancels) external {
        uint256 cancelsLength = cancels.length;
        for (uint256 i; i < cancelsLength; ) {
            Cancel memory cancel = cancels[i];
            amountTaken[msg.sender][cancel.hash][cancel.index] += cancel.amount;
            emit CancelTrade(msg.sender, cancel.hash, cancel.index, cancel.amount);
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Cancels all orders by incrementing caller nonce
     */
    function incrementNonce() external {
        emit NonceIncremented(msg.sender, ++nonces[msg.sender]);
    }

    /*//////////////////////////////////////////////////////////////
                          EXECUTION WRAPPERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Wrapper of _takeAsk that verifies an oracle signature of the calldata before executing
     * @param inputs Inputs for _takeAsk
     * @param oracleSignature Oracle signature of inputs
     */
    function takeAsk(
        TakeAsk memory inputs,
        bytes calldata oracleSignature
    )
        public
        payable
        nonReentrant
        verifyOracleSignature(_hashCalldata(msg.sender), oracleSignature)
    {
        _takeAsk(
            inputs.orders,
            inputs.exchanges,
            inputs.takerFee,
            inputs.signatures,
            inputs.tokenRecipient
        );
    }

    /**
     * @notice Wrapper of _takeBid that verifies an oracle signature of the calldata before executing
     * @param inputs Inputs for _takeBid
     * @param oracleSignature Oracle signature of inputs
     */
    function takeBid(
        TakeBid memory inputs,
        bytes calldata oracleSignature
    ) public verifyOracleSignature(_hashCalldata(msg.sender), oracleSignature) {
        _takeBid(inputs.orders, inputs.exchanges, inputs.takerFee, inputs.signatures);
    }

    /**
     * @notice Wrapper of _takeAskSingle that verifies an oracle signature of the calldata before executing
     * @param inputs Inputs for _takeAskSingle
     * @param oracleSignature Oracle signature of inputs
     */
    function takeAskSingle(
        TakeAskSingle memory inputs,
        bytes calldata oracleSignature
    )
        public
        payable
        nonReentrant
        verifyOracleSignature(_hashCalldata(msg.sender), oracleSignature)
    {
        _takeAskSingle(
            inputs.order,
            inputs.exchange,
            inputs.takerFee,
            inputs.signature,
            inputs.tokenRecipient
        );
    }

    /**
     * @notice Wrapper of _takeBidSingle that verifies an oracle signature of the calldata before executing
     * @param inputs Inputs for _takeBidSingle
     * @param oracleSignature Oracle signature of inputs
     */
    function takeBidSingle(
        TakeBidSingle memory inputs,
        bytes calldata oracleSignature
    ) external verifyOracleSignature(_hashCalldata(msg.sender), oracleSignature) {
        _takeBidSingle(inputs.order, inputs.exchange, inputs.takerFee, inputs.signature);
    }

    /*//////////////////////////////////////////////////////////////
                        EXECUTION POOL WRAPPERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Wrapper of takeAskSingle that withdraws ETH from the caller's pool balance prior to executing
     * @param inputs Inputs for takeAskSingle
     * @param oracleSignature Oracle signature of inputs
     * @param amountToWithdraw Amount of ETH to withdraw from the pool
     */
    function takeAskSinglePool(
        TakeAskSingle memory inputs,
        bytes calldata oracleSignature,
        uint256 amountToWithdraw
    ) external payable {
        _withdrawFromPool(msg.sender, amountToWithdraw);

        takeAskSingle(inputs, oracleSignature);
    }

    /**
     * @notice Wrapper of takeAsk that withdraws ETH from the caller's pool balance prior to executing
     * @param inputs Inputs for takeAsk
     * @param oracleSignature Oracle signature of inputs
     * @param amountToWithdraw Amount of ETH to withdraw from the pool
     */
    function takeAskPool(
        TakeAsk memory inputs,
        bytes calldata oracleSignature,
        uint256 amountToWithdraw
    ) external payable {
        _withdrawFromPool(msg.sender, amountToWithdraw);

        takeAsk(inputs, oracleSignature);
    }

    /*//////////////////////////////////////////////////////////////
                          EXECUTION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Take a single ask
     * @param order Order of listing to fulfill
     * @param exchange Exchange struct indicating the listing to take and the parameters to match it with
     * @param takerFee Taker fee to be taken
     * @param signature Order signature
     * @param tokenRecipient Address to receive the token transfer
     */
    function _takeAskSingle(
        Order memory order,
        Exchange memory exchange,
        FeeRate memory takerFee,
        bytes memory signature,
        address tokenRecipient
    ) internal {
        Fees memory fees = Fees(protocolFee, takerFee);
        Listing memory listing = exchange.listing;
        uint256 takerAmount = exchange.taker.amount;

        /* Validate the order and listing, revert if not. */
        if (!_validateOrderAndListing(order, OrderType.ASK, exchange, signature, fees)) {
            revert InvalidOrder();
        }

        /* Create single execution batch and insert the transfer. */
        bytes memory executionBatch = _initializeSingleExecution(
            order,
            OrderType.ASK,
            listing.tokenId,
            takerAmount,
            tokenRecipient
        );

        /* Set the fulfillment of the order. */
        unchecked {
            amountTaken[order.trader][bytes32(order.salt)][listing.index] += takerAmount;
        }

        /* Execute the token transfers, revert if not successful. */
        {
            bool[] memory successfulTransfers = _executeNonfungibleTransfers(executionBatch, 1);
            if (!successfulTransfers[0]) {
                revert TokenTransferFailed();
            }
        }

        (
            uint256 totalPrice,
            uint256 protocolFeeAmount,
            uint256 makerFeeAmount,
            uint256 takerFeeAmount
        ) = _computeFees(listing.price, takerAmount, order.makerFee, fees);

        /* If there are insufficient funds to cover the price with the fees, revert. */
        unchecked {
            if (address(this).balance < totalPrice + takerFeeAmount) {
                revert InsufficientFunds();
            }
        }

        /* Execute ETH transfers. */
        _transferETH(fees.protocolFee.recipient, protocolFeeAmount);
        _transferETH(fees.takerFee.recipient, takerFeeAmount);
        _transferETH(order.makerFee.recipient, makerFeeAmount);
        unchecked {
            _transferETH(order.trader, totalPrice - makerFeeAmount - protocolFeeAmount);
        }

        _emitExecutionEvent(executionBatch, order, listing.index, totalPrice, fees, OrderType.ASK);

        /* Return dust. */
        _transferETH(msg.sender, address(this).balance);
    }

    /**
     * @notice Take a single bid
     * @param order Order of listing to fulfill
     * @param exchange Exchange struct indicating the listing to take and the parameters to match it with
     * @param takerFee Taker fee to be taken
     * @param signature Order signature
     */
    function _takeBidSingle(
        Order memory order,
        Exchange memory exchange,
        FeeRate memory takerFee,
        bytes memory signature
    ) internal {
        Fees memory fees = Fees(protocolFee, takerFee);
        Listing memory listing = exchange.listing;
        uint256 takerAmount = exchange.taker.amount;

        /* Validate the order and listing, revert if not. */
        if (!_validateOrderAndListing(order, OrderType.BID, exchange, signature, fees)) {
            revert InvalidOrder();
        }

        /* Create single execution batch and insert the transfer. */
        bytes memory executionBatch = _initializeSingleExecution(
            order,
            OrderType.BID,
            exchange.taker.tokenId,
            takerAmount,
            msg.sender
        );

        /* Execute the token transfers, revert if not successful. */
        {
            bool[] memory successfulTransfers = _executeNonfungibleTransfers(executionBatch, 1);
            if (!successfulTransfers[0]) {
                revert TokenTransferFailed();
            }
        }

        (
            uint256 totalPrice,
            uint256 protocolFeeAmount,
            uint256 makerFeeAmount,
            uint256 takerFeeAmount
        ) = _computeFees(listing.price, takerAmount, order.makerFee, fees);

        /* Execute pool transfers and set the fulfillment of the order. */
        address trader = order.trader;
        _transferPool(trader, order.makerFee.recipient, makerFeeAmount);
        _transferPool(trader, fees.takerFee.recipient, takerFeeAmount);
        _transferPool(trader, fees.protocolFee.recipient, protocolFeeAmount);
        unchecked {
            _transferPool(trader, msg.sender, totalPrice - takerFeeAmount - protocolFeeAmount);

            amountTaken[trader][bytes32(order.salt)][listing.index] += exchange.taker.amount;
        }

        _emitExecutionEvent(executionBatch, order, listing.index, totalPrice, fees, OrderType.BID);
    }

    /**
     * @notice Take multiple asks; efficiently verifying and executing the transfers in bulk
     * @param orders List of orders
     * @param exchanges List of exchanges indicating the listing to take and the parameters to match it with
     * @param takerFee Taker fee to be taken on each exchange
     * @param signatures Bytes array of order signatures
     * @param tokenRecipient Address to receive the tokens purchased
     */
    function _takeAsk(
        Order[] memory orders,
        Exchange[] memory exchanges,
        FeeRate memory takerFee,
        bytes memory signatures,
        address tokenRecipient
    ) internal {
        Fees memory fees = Fees(protocolFee, takerFee);

        /**
         * Validate all the orders potentially used in the execution and
         * initialize the arrays for pending fulfillments.
         */
        (bool[] memory validOrders, uint256[][] memory pendingAmountTaken) = _validateOrders(
            orders,
            OrderType.ASK,
            signatures,
            fees
        );

        uint256 exchangesLength = exchanges.length;

        /* Initialize the execution batch structs. */
        (
            bytes memory executionBatch,
            FungibleTransfers memory fungibleTransfers
        ) = _initializeBatch(exchangesLength, OrderType.ASK, tokenRecipient);

        Order memory order;
        Exchange memory exchange;

        uint256 remainingETH = address(this).balance;
        for (uint256 i; i < exchangesLength; ) {
            exchange = exchanges[i];
            order = orders[exchange.index];

            /* Check the listing and exchange is valid and its parent order has already been validated. */
            if (
                _validateListingFromBatch(
                    order,
                    OrderType.ASK,
                    exchange,
                    validOrders,
                    pendingAmountTaken
                )
            ) {
                /* Insert the transfers into the batch. */
                bool inserted;
                (remainingETH, inserted) = _insertExecutionAsk(
                    executionBatch,
                    fungibleTransfers,
                    order,
                    exchange,
                    fees,
                    remainingETH
                );
                if (inserted) {
                    unchecked {
                        pendingAmountTaken[exchange.index][exchange.listing.index] += exchange
                            .taker
                            .amount;
                    }
                }
            }

            unchecked {
                ++i;
            }
        }

        /* Execute all transfers. */
        _executeBatchTransfer(executionBatch, fungibleTransfers, fees, OrderType.ASK);

        /* Return dust. */
        _transferETH(msg.sender, address(this).balance);
    }

    /**
     * @notice Take multiple bids; efficiently verifying and executing the transfers in bulk
     * @param orders List of orders
     * @param exchanges List of exchanges indicating the listing to take and the parameters to match it with
     * @param takerFee Taker fee to be taken on each exchange
     * @param signatures Bytes array of order signatures
     */
    function _takeBid(
        Order[] memory orders,
        Exchange[] memory exchanges,
        FeeRate memory takerFee,
        bytes memory signatures
    ) internal {
        Fees memory fees = Fees(protocolFee, takerFee);

        /**
         * Validate all the orders potentially used in the execution and
         * initialize the arrays for pending fulfillments.
         */
        (bool[] memory validOrders, uint256[][] memory pendingAmountTaken) = _validateOrders(
            orders,
            OrderType.BID,
            signatures,
            fees
        );

        uint256 exchangesLength = exchanges.length;

        /* Initialize the execution batch structs. */
        (
            bytes memory executionBatch,
            FungibleTransfers memory fungibleTransfers
        ) = _initializeBatch(exchangesLength, OrderType.BID, msg.sender);

        Order memory order;
        Exchange memory exchange;

        for (uint256 i; i < exchangesLength; ) {
            exchange = exchanges[i];
            order = orders[exchange.index];

            /* Check the listing and exchange is valid and its parent order has already been validated. */
            if (
                _validateListingFromBatch(
                    order,
                    OrderType.BID,
                    exchange,
                    validOrders,
                    pendingAmountTaken
                )
            ) {
                /* Insert the transfers into the batch. */
                _insertExecutionBid(executionBatch, fungibleTransfers, order, exchange, fees);

                /* Record the pending fulfillment. */
                unchecked {
                    pendingAmountTaken[exchange.index][exchange.listing.index] += exchange
                        .taker
                        .amount;
                }
            }

            unchecked {
                ++i;
            }
        }

        /* Execute all transfers. */
        _executeBatchTransfer(executionBatch, fungibleTransfers, fees, OrderType.BID);
    }

    /*//////////////////////////////////////////////////////////////
                          EXECUTION HELPERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initialize the ExecutionBatch and FungibleTransfers objects for bulk execution
     * @param exchangesLength Number of exchanges
     * @param orderType Order type
     * @param taker Order taker address
     */
    function _initializeBatch(
        uint256 exchangesLength,
        OrderType orderType,
        address taker
    )
        internal
        pure
        returns (bytes memory executionBatch, FungibleTransfers memory fungibleTransfers)
    {
        /* Initialize the batch. Constructing it manually in calldata packing allows for cheaper delegate execution. */
        uint256 arrayLength = Transfer_size * exchangesLength + One_word;
        uint256 executionBatchLength = ExecutionBatch_base_size + arrayLength;
        executionBatch = new bytes(executionBatchLength);
        assembly {
            let calldataPointer := add(executionBatch, ExecutionBatch_calldata_offset)
            mstore(add(calldataPointer, ExecutionBatch_taker_offset), taker)
            mstore(add(calldataPointer, ExecutionBatch_orderType_offset), orderType)
            mstore(add(calldataPointer, ExecutionBatch_transfers_pointer_offset), ExecutionBatch_transfers_offset) // set the transfers pointer
            mstore(add(calldataPointer, ExecutionBatch_transfers_offset), exchangesLength) // set the length of the transfers array
        }

        /* Initialize the fungible transfers object. */
        AtomicExecution[] memory executions = new AtomicExecution[](exchangesLength);
        address[] memory feeRecipients = new address[](exchangesLength);
        address[] memory makers = new address[](exchangesLength);
        uint256[] memory makerTransfers = new uint256[](exchangesLength);
        uint256[] memory feeTransfers = new uint256[](exchangesLength);
        fungibleTransfers = FungibleTransfers({
            totalProtocolFee: 0,
            totalSellerTransfer: 0,
            totalTakerFee: 0,
            feeRecipientId: 0,
            feeRecipients: feeRecipients,
            makerId: 0,
            makers: makers,
            feeTransfers: feeTransfers,
            makerTransfers: makerTransfers,
            executions: executions
        });
    }

    /**
     * @notice Initialize the ExecutionBatch object for a single execution
     * @param order Order to take a Listing from
     * @param orderType Order type
     * @param tokenId Token id
     * @param amount ERC721/ERC1155 amount
     * @param taker Order taker address
     */
    function _initializeSingleExecution(
        Order memory order,
        OrderType orderType,
        uint256 tokenId,
        uint256 amount,
        address taker
    ) internal pure returns (bytes memory executionBatch) {
        /* Initialize the batch. Constructing it manually in calldata packing allows for cheaper delegate execution. */
        uint256 arrayLength = Transfer_size + One_word;
        uint256 executionBatchLength = ExecutionBatch_base_size + arrayLength;
        executionBatch = new bytes(executionBatchLength);
        assembly {
            let calldataPointer := add(executionBatch, ExecutionBatch_calldata_offset)
            mstore(add(calldataPointer, ExecutionBatch_taker_offset), taker)
            mstore(add(calldataPointer, ExecutionBatch_orderType_offset), orderType)
            mstore(add(calldataPointer, ExecutionBatch_transfers_pointer_offset), ExecutionBatch_transfers_offset) // set the transfers pointer
            mstore(add(calldataPointer, ExecutionBatch_transfers_offset), 1) // set the length of the transfers array
        }

        /* Insert the transfer into the batch. */
        _insertNonfungibleTransfer(executionBatch, order, tokenId, amount);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import { Validation } from "./Validation.sol";
import "./lib/Constants.sol";
import {
    Order,
    Exchange,
    FungibleTransfers,
    StateUpdate,
    AtomicExecution,
    AssetType,
    Fees,
    FeeRate,
    Listing,
    Taker,
    Transfer,
    OrderType
} from "./lib/Structs.sol";
import { IDelegate } from "./interfaces/IDelegate.sol";
import { IExecutor } from "./interfaces/IExecutor.sol";

abstract contract Executor is IExecutor, Validation {
    address private immutable _DELEGATE;
    address private immutable _POOL;

    constructor(address delegate, address pool, address proxy) Validation(proxy) {
        _DELEGATE = delegate;
        _POOL = pool;
    }

    receive() external payable {
        if (msg.sender != _POOL) {
            revert Unauthorized();
        }
    }

    /**
     * @notice Insert a validated ask listing into the batch if there's sufficient ETH to fulfill
     * @param executionBatch Execution batch
     * @param fungibleTransfers Fungible transfers
     * @param order Order of the listing to insert
     * @param exchange Exchange containing the listing to insert
     * @param fees Protocol and taker fees
     * @param remainingETH Available ETH remaining
     * @return Available ETH remaining after insertion; if the listing was inserted in the batch
     */
    function _insertExecutionAsk(
        bytes memory executionBatch,
        FungibleTransfers memory fungibleTransfers,
        Order memory order,
        Exchange memory exchange,
        Fees memory fees,
        uint256 remainingETH
    ) internal pure returns (uint256, bool) {
        uint256 takerAmount = exchange.taker.amount;

        (
            uint256 totalPrice,
            uint256 protocolFeeAmount,
            uint256 makerFeeAmount,
            uint256 takerFeeAmount
        ) = _computeFees(exchange.listing.price, takerAmount, order.makerFee, fees);

        /* Only insert the executions if there are sufficient funds to execute. */
        if (remainingETH >= totalPrice + takerFeeAmount) {
            unchecked {
                remainingETH = remainingETH - totalPrice - takerFeeAmount;
            }

            _setAddresses(fungibleTransfers, order);

            uint256 index = _insertNonfungibleTransfer(
                executionBatch,
                order,
                exchange.listing.tokenId,
                takerAmount
            );

            _insertFungibleTransfers(
                fungibleTransfers,
                takerAmount,
                exchange.listing,
                bytes32(order.salt),
                index,
                totalPrice,
                protocolFeeAmount,
                makerFeeAmount,
                takerFeeAmount,
                true
            );

            return (remainingETH, true);
        } else {
            return (remainingETH, false);
        }
    }

    /**
     * @notice Insert a validated bid listing into the batch
     * @param executionBatch Execution batch
     * @param fungibleTransfers Fungible transfers
     * @param order Order of the listing to insert
     * @param exchange Exchange containing listing to insert
     * @param fees Protocol and taker fees
     */
    function _insertExecutionBid(
        bytes memory executionBatch,
        FungibleTransfers memory fungibleTransfers,
        Order memory order,
        Exchange memory exchange,
        Fees memory fees
    ) internal pure {
        uint256 takerAmount = exchange.taker.amount;

        (
            uint256 totalPrice,
            uint256 protocolFeeAmount,
            uint256 makerFeeAmount,
            uint256 takerFeeAmount
        ) = _computeFees(exchange.listing.price, takerAmount, order.makerFee, fees);

        _setAddresses(fungibleTransfers, order);

        uint256 index = _insertNonfungibleTransfer(
            executionBatch,
            order,
            exchange.taker.tokenId,
            takerAmount
        );

        _insertFungibleTransfers(
            fungibleTransfers,
            takerAmount,
            exchange.listing,
            bytes32(order.salt),
            index,
            totalPrice,
            protocolFeeAmount,
            makerFeeAmount,
            takerFeeAmount,
            false
        );
    }

    /**
     * @notice Insert the nonfungible transfer into the batch
     * @param executionBatch Execution batch
     * @param order Order
     * @param tokenId Token id
     * @param amount Number of token units
     * @return transferIndex Index of the transfer
     */
    function _insertNonfungibleTransfer(
        bytes memory executionBatch,
        Order memory order,
        uint256 tokenId,
        uint256 amount
    ) internal pure returns (uint256 transferIndex) {
        assembly {
            let calldataPointer := add(executionBatch, ExecutionBatch_calldata_offset)
            transferIndex := mload(add(calldataPointer, ExecutionBatch_length_offset))

            let transfersOffset := mload(add(calldataPointer, ExecutionBatch_transfers_pointer_offset))
            let transferPointer := add(
                add(calldataPointer, add(transfersOffset, One_word)),
                mul(transferIndex, Transfer_size)
            )
            mstore(
                add(transferPointer, Transfer_trader_offset),
                mload(add(order, Order_trader_offset))
            ) // set the trader
            mstore(add(transferPointer, Transfer_id_offset), tokenId) // set the token id
            mstore(
                add(transferPointer, Transfer_collection_offset),
                mload(add(order, Order_collection_offset))
            ) // set the collection
            mstore(
                add(transferPointer, Transfer_assetType_offset),
                mload(add(order, Order_assetType_offset))
            ) // set the asset type
            mstore(add(calldataPointer, ExecutionBatch_length_offset), add(transferIndex, 1)) // increment the batch length

            if eq(mload(add(order, Order_assetType_offset)), AssetType_ERC1155) {
                mstore(add(transferPointer, Transfer_amount_offset), amount) // set the amount (don't need to set for ERC721's)
            }
        }
    }

    /**
     * @notice Insert the fungible transfers that need to be executed atomically
     * @param fungibleTransfers Fungible transfers struct
     * @param takerAmount Amount of the listing being taken
     * @param listing Listing to execute
     * @param orderHash Order hash
     * @param index Execution index
     * @param totalPrice Total price of the purchased tokens
     * @param protocolFeeAmount Computed protocol fee
     * @param makerFeeAmount Computed maker fee
     * @param takerFeeAmount Computed taker fee
     * @param makerIsSeller Is the order maker the seller
     */
    function _insertFungibleTransfers(
        FungibleTransfers memory fungibleTransfers,
        uint256 takerAmount,
        Listing memory listing,
        bytes32 orderHash,
        uint256 index,
        uint256 totalPrice,
        uint256 protocolFeeAmount,
        uint256 makerFeeAmount,
        uint256 takerFeeAmount,
        bool makerIsSeller
    ) internal pure {
        uint256 makerId = fungibleTransfers.makerId;
        fungibleTransfers.executions[index].makerId = makerId;
        fungibleTransfers.executions[index].makerFeeRecipientId = fungibleTransfers.feeRecipientId;
        fungibleTransfers.executions[index].stateUpdate = StateUpdate({
            trader: fungibleTransfers.makers[makerId],
            hash: orderHash,
            index: listing.index,
            value: takerAmount,
            maxAmount: listing.amount
        });
        if (makerIsSeller) {
            unchecked {
                fungibleTransfers.executions[index].sellerAmount =
                    totalPrice -
                    protocolFeeAmount -
                    makerFeeAmount;
            }
        } else {
            unchecked {
                fungibleTransfers.executions[index].sellerAmount =
                    totalPrice -
                    protocolFeeAmount -
                    takerFeeAmount;
            }
        }
        fungibleTransfers.executions[index].makerFeeAmount = makerFeeAmount;
        fungibleTransfers.executions[index].takerFeeAmount = takerFeeAmount;
        fungibleTransfers.executions[index].protocolFeeAmount = protocolFeeAmount;
    }

    /**
     * @notice Set the addresses of the maker fee recipient and order maker if different than currently being batched
     * @param fungibleTransfers Fungible transfers struct
     * @param order Parent order of listing being added to the batch
     */
    function _setAddresses(
        FungibleTransfers memory fungibleTransfers,
        Order memory order
    ) internal pure {
        address feeRecipient = order.makerFee.recipient;
        uint256 feeRecipientId = fungibleTransfers.feeRecipientId;
        address currentFeeRecipient = fungibleTransfers.feeRecipients[feeRecipientId];
        if (feeRecipient != currentFeeRecipient) {
            if (currentFeeRecipient == address(0)) {
                fungibleTransfers.feeRecipients[feeRecipientId] = feeRecipient;
            } else {
                unchecked {
                    fungibleTransfers.feeRecipients[++feeRecipientId] = feeRecipient;
                }
                fungibleTransfers.feeRecipientId = feeRecipientId;
            }
        }
        address trader = order.trader;
        uint256 makerId = fungibleTransfers.makerId;
        address currentTrader = fungibleTransfers.makers[makerId];
        if (trader != currentTrader) {
            if (currentTrader == address(0)) {
                fungibleTransfers.makers[makerId] = trader;
            } else {
                unchecked {
                    fungibleTransfers.makers[++makerId] = trader;
                }
                fungibleTransfers.makerId = makerId;
            }
        }
    }

    /**
     * @notice Compute all necessary fees to be taken
     * @param pricePerToken Price per token unit
     * @param takerAmount Number of token units taken (should only be greater than 1 for ERC1155)
     * @param fees Protocol and taker fee set by the transaction
     */
    function _computeFees(
        uint256 pricePerToken,
        uint256 takerAmount,
        FeeRate memory makerFee,
        Fees memory fees
    )
        internal
        pure
        returns (
            uint256 totalPrice,
            uint256 protocolFeeAmount,
            uint256 makerFeeAmount,
            uint256 takerFeeAmount
        )
    {
        totalPrice = pricePerToken * takerAmount;
        makerFeeAmount = (totalPrice * makerFee.rate) / _BASIS_POINTS;
        takerFeeAmount = (totalPrice * fees.takerFee.rate) / _BASIS_POINTS;
        protocolFeeAmount = (totalPrice * fees.protocolFee.rate) / _BASIS_POINTS;
    }

    /*//////////////////////////////////////////////////////////////
                        EXECUTION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Execute the transfers by first attempting the nonfungible transfers, for the successful transfers sum the fungible transfers by the recipients and execute
     * @param executionBatch Execution batch struct
     * @param fungibleTransfers Fungible transfers struct
     * @param fees Protocol, maker, taker fees (note: makerFee will be inaccurate at this point in execution)
     * @param orderType Order type
     */
    function _executeBatchTransfer(
        bytes memory executionBatch,
        FungibleTransfers memory fungibleTransfers,
        Fees memory fees,
        OrderType orderType
    ) internal {
        uint256 batchLength;
        assembly {
            let calldataPointer := add(executionBatch, ExecutionBatch_calldata_offset)
            batchLength := mload(add(calldataPointer, ExecutionBatch_length_offset))
        }
        if (batchLength > 0) {
            bool[] memory successfulTransfers = _executeNonfungibleTransfers(
                executionBatch,
                batchLength
            );

            uint256 transfersLength = successfulTransfers.length;
            for (uint256 i; i < transfersLength; ) {
                if (successfulTransfers[i]) {
                    AtomicExecution memory execution = fungibleTransfers.executions[i];
                    FeeRate memory makerFee;
                    uint256 price;
                    unchecked {
                        if (orderType == OrderType.ASK) {
                            fungibleTransfers.makerTransfers[execution.makerId] += execution
                                .sellerAmount; // amount that needs to be sent *to* the order maker
                            price =
                                execution.sellerAmount +
                                execution.protocolFeeAmount +
                                execution.makerFeeAmount;
                        } else {
                            fungibleTransfers.makerTransfers[execution.makerId] +=
                                execution.protocolFeeAmount +
                                execution.makerFeeAmount +
                                execution.takerFeeAmount +
                                execution.sellerAmount; // amount that needs to be taken *from* the order maker
                            price =
                                execution.sellerAmount +
                                execution.protocolFeeAmount +
                                execution.takerFeeAmount;
                        }
                        fungibleTransfers.totalSellerTransfer += execution.sellerAmount; // only for bids
                        fungibleTransfers.totalProtocolFee += execution.protocolFeeAmount;
                        fungibleTransfers.totalTakerFee += execution.takerFeeAmount;
                        fungibleTransfers.feeTransfers[execution.makerFeeRecipientId] += execution
                            .makerFeeAmount;
                        makerFee = FeeRate(
                            fungibleTransfers.feeRecipients[execution.makerFeeRecipientId],
                            uint16((execution.makerFeeAmount * _BASIS_POINTS) / price)
                        );
                    }

                    /* Commit state updates. */
                    StateUpdate memory stateUpdate = fungibleTransfers.executions[i].stateUpdate;
                    {
                        address trader = stateUpdate.trader;
                        bytes32 hash = stateUpdate.hash;
                        uint256 index = stateUpdate.index;
                        uint256 _amountTaken = amountTaken[trader][hash][index];
                        uint256 newAmountTaken = _amountTaken + stateUpdate.value;

                        /* Overfulfilled Listings should be caught prior to inserting into the batch, but this check prevents any misuse. */
                        if (newAmountTaken <= stateUpdate.maxAmount) {
                            amountTaken[trader][hash][index] = newAmountTaken;
                        } else {
                            revert OrderFulfilled();
                        }
                    }

                    _emitExecutionEventFromBatch(
                        executionBatch,
                        price,
                        makerFee,
                        fees,
                        stateUpdate,
                        orderType,
                        i
                    );
                }

                unchecked {
                    ++i;
                }
            }

            if (orderType == OrderType.ASK) {
                /* Transfer the payments to the sellers. */
                uint256 makersLength = fungibleTransfers.makerId + 1;
                for (uint256 i; i < makersLength; ) {
                    _transferETH(fungibleTransfers.makers[i], fungibleTransfers.makerTransfers[i]);
                    unchecked {
                        ++i;
                    }
                }

                /* Transfer the fees to the fee recipients. */
                uint256 feesLength = fungibleTransfers.feeRecipientId + 1;
                for (uint256 i; i < feesLength; ) {
                    _transferETH(
                        fungibleTransfers.feeRecipients[i],
                        fungibleTransfers.feeTransfers[i]
                    );
                    unchecked {
                        ++i;
                    }
                }

                /* Transfer the protocol fees. */
                _transferETH(fees.protocolFee.recipient, fungibleTransfers.totalProtocolFee);

                /* Transfer the taker fees. */
                _transferETH(fees.takerFee.recipient, fungibleTransfers.totalTakerFee);
            } else {
                /* Take the pool funds from the buyers. */
                uint256 makersLength = fungibleTransfers.makerId + 1;
                for (uint256 i; i < makersLength; ) {
                    _transferPool(
                        fungibleTransfers.makers[i],
                        address(this),
                        fungibleTransfers.makerTransfers[i]
                    );
                    unchecked {
                        ++i;
                    }
                }

                /* Transfer the payment to the seller. */
                _transferPool(address(this), msg.sender, fungibleTransfers.totalSellerTransfer);

                /* Transfer the fees to the fee recipients. */
                uint256 feesLength = fungibleTransfers.feeRecipientId + 1;
                for (uint256 i; i < feesLength; ) {
                    _transferPool(
                        address(this),
                        fungibleTransfers.feeRecipients[i],
                        fungibleTransfers.feeTransfers[i]
                    );
                    unchecked {
                        ++i;
                    }
                }

                /* Transfer the protocol fees. */
                _transferPool(
                    address(this),
                    fees.protocolFee.recipient,
                    fungibleTransfers.totalProtocolFee
                );

                /* Transfer the taker fees. */
                _transferPool(
                    address(this),
                    fees.takerFee.recipient,
                    fungibleTransfers.totalTakerFee
                );
            }
        }
    }

    /**
     * @notice Attempt to execute a series of nonfungible transfers through the delegate; reverts will be skipped
     * @param executionBatch Execution batch struct
     * @param batchIndex Current available transfer slot in the batch
     * @return Array indicating which transfers were successful
     */
    function _executeNonfungibleTransfers(
        bytes memory executionBatch,
        uint256 batchIndex
    ) internal returns (bool[] memory) {
        address delegate = _DELEGATE;

        /* Initialize the memory space for the successful transfers array returned from the Delegate call. */
        uint256 successfulTransfersPointer;
        assembly {
            successfulTransfersPointer := mload(Memory_pointer)
            /* Need to shift the free memory pointer ahead one word to account for the array pointer returned from the call. */
            mstore(Memory_pointer, add(successfulTransfersPointer, One_word))
        }

        bool[] memory successfulTransfers = new bool[](batchIndex);
        assembly {
            let size := mload(executionBatch)
            let selectorPointer := add(executionBatch, ExecutionBatch_selector_offset)
            mstore(selectorPointer, shr(Bytes4_shift, Delegate_transfer_selector))
            let success := call(
                gas(),
                delegate,
                0,
                add(selectorPointer, Delegate_transfer_calldata_offset),
                sub(size, Delegate_transfer_calldata_offset),
                successfulTransfersPointer,
                add(0x40, mul(batchIndex, One_word))
            )
        }
        return successfulTransfers;
    }

    /*//////////////////////////////////////////////////////////////
                        TRANSFER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Transfer ETH
     * @param to Recipient address
     * @param amount Amount of ETH to send
     */
    function _transferETH(address to, uint256 amount) internal {
        if (amount > 0) {
            bool success;
            assembly {
                success := call(gas(), to, amount, 0, 0, 0, 0)
            }
            if (!success) {
                revert ETHTransferFailed();
            }
        }
    }

    /**
     * @notice Transfer pool funds on behalf of a user
     * @param from Sender address
     * @param to Recipient address
     * @param amount Amount to send
     */
    function _transferPool(address from, address to, uint256 amount) internal {
        if (amount > 0) {
            bool success;
            address pool = _POOL;
            assembly {
                let x := mload(Memory_pointer)
                mstore(x, ERC20_transferFrom_selector)
                mstore(add(x, ERC20_transferFrom_from_offset), from)
                mstore(add(x, ERC20_transferFrom_to_offset), to)
                mstore(add(x, ERC20_transferFrom_amount_offset), amount)
                success := call(gas(), pool, 0, x, ERC20_transferFrom_size, 0, 0)
            }
            if (!success) {
                revert PoolTransferFailed();
            }
        }
    }

    /**
     * @notice Deposit ETH to user's pool funds
     * @param to Recipient address
     * @param amount Amount of ETH to deposit
     */
    function _depositPool(address to, uint256 amount) internal {
        bool success;
        address pool = _POOL;
        assembly {
            let x := mload(Memory_pointer)
            mstore(x, Pool_deposit_selector)
            mstore(add(x, Pool_deposit_user_offset), to)
            success := call(gas(), pool, amount, x, Pool_deposit_size, 0, 0)
        }
        if (!success) {
            revert PoolDepositFailed();
        }
    }

    /**
     * @notice Withdraw ETH from user's pool funds
     * @param from Address to withdraw from
     * @param amount Amount of ETH to withdraw
     */
    function _withdrawFromPool(address from, uint256 amount) internal {
        bool success;
        address pool = _POOL;
        assembly {
            let x := mload(Memory_pointer)
            mstore(x, Pool_withdrawFrom_selector)
            mstore(add(x, Pool_withdrawFrom_from_offset), from)
            mstore(add(x, Pool_withdrawFrom_to_offset), address())
            mstore(add(x, Pool_withdrawFrom_amount_offset), amount)
            success := call(gas(), pool, 0, x, Pool_withdrawFrom_size, 0, 0)
        }
        if (!success) {
            revert PoolWithdrawFromFailed();
        }
    }

    /*//////////////////////////////////////////////////////////////
                          EVENT EMITTERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Emit Execution event from a single execution
     * @param executionBatch Execution batch struct
     * @param price Price of the token purchased
     * @param fees Protocol, maker, and taker fees taken
     * @param stateUpdate Fulfillment to be recorded with a successful execution
     * @param orderType Order type
     * @param transferIndex Index of the transfer corresponding to the execution
     */
    function _emitExecutionEventFromBatch(
        bytes memory executionBatch,
        uint256 price,
        FeeRate memory makerFee,
        Fees memory fees,
        StateUpdate memory stateUpdate,
        OrderType orderType,
        uint256 transferIndex
    ) internal {
        Transfer memory transfer;
        assembly {
            let calldataPointer := add(executionBatch, ExecutionBatch_calldata_offset)
            let transfersOffset := mload(add(calldataPointer, ExecutionBatch_transfers_pointer_offset))
            transfer := add(
                add(calldataPointer, add(transfersOffset, One_word)),
                mul(transferIndex, Transfer_size)
            )
        }

        _emitOptimalExecutionEvent(
            transfer,
            stateUpdate.hash,
            stateUpdate.index,
            price,
            makerFee,
            fees,
            orderType
        );
    }

    /**
     * @notice Emit the Execution event that minimizes the number of bytes in the log
     * @param transfer The nft transfer
     * @param orderHash Order hash
     * @param listingIndex Index of the listing being fulfilled within the order
     * @param price Price of the token purchased
     * @param makerFee Maker fees taken
     * @param fees Protocol, and taker fees taken
     * @param orderType Order type
     */
    function _emitOptimalExecutionEvent(
        Transfer memory transfer,
        bytes32 orderHash,
        uint256 listingIndex,
        uint256 price,
        FeeRate memory makerFee,
        Fees memory fees,
        OrderType orderType
    ) internal {
        if (
            // see _insertNonfungibleTransfer; ERC721 transfers don't set the transfer amount,
            // so we can assume the transfer amount and not check it
            transfer.assetType == AssetType.ERC721 &&
            fees.protocolFee.rate == 0 &&
            transfer.id < 1 << (11 * 8) &&
            listingIndex < 1 << (1 * 8) &&
            price < 1 << (11 * 8)
        ) {
            if (makerFee.rate == 0 && fees.takerFee.rate == 0) {
                emit Execution721Packed(
                    orderHash,
                    packTokenIdListingIndexTrader(transfer.id, listingIndex, transfer.trader),
                    packTypePriceCollection(orderType, price, transfer.collection)
                );
                return;
            } else if (makerFee.rate == 0) {
                emit Execution721TakerFeePacked(
                    orderHash,
                    packTokenIdListingIndexTrader(transfer.id, listingIndex, transfer.trader),
                    packTypePriceCollection(orderType, price, transfer.collection),
                    packFee(fees.takerFee)
                );
                return;
            } else if (fees.takerFee.rate == 0) {
                emit Execution721MakerFeePacked(
                    orderHash,
                    packTokenIdListingIndexTrader(transfer.id, listingIndex, transfer.trader),
                    packTypePriceCollection(orderType, price, transfer.collection),
                    packFee(makerFee)
                );
                return;
            }
        }

        emit Execution({
            transfer: transfer,
            orderHash: orderHash,
            listingIndex: listingIndex,
            price: price,
            makerFee: makerFee,
            fees: fees,
            orderType: orderType
        });
    }

    /**
     * @notice Emit Execution event from a single execution
     * @param executionBatch Execution batch struct
     * @param order Order being fulfilled
     * @param listingIndex Index of the listing being fulfilled within the order
     * @param price Price of the token purchased
     * @param fees Protocol, and taker fees taken
     * @param orderType Order type
     */
    function _emitExecutionEvent(
        bytes memory executionBatch,
        Order memory order,
        uint256 listingIndex,
        uint256 price,
        Fees memory fees,
        OrderType orderType
    ) internal {
        Transfer memory transfer;
        assembly {
            let calldataPointer := add(executionBatch, ExecutionBatch_calldata_offset)
            let transfersOffset := mload(add(calldataPointer, ExecutionBatch_transfers_pointer_offset))
            transfer := add(calldataPointer, add(transfersOffset, One_word))
        }

        _emitOptimalExecutionEvent(
            transfer,
            bytes32(order.salt),
            listingIndex,
            price,
            order.makerFee,
            fees,
            orderType
        );
    }

    function packTokenIdListingIndexTrader(
        uint256 tokenId,
        uint256 listingIndex,
        address trader
    ) private pure returns (uint256) {
        return (tokenId << (21 * 8)) | (listingIndex << (20 * 8)) | uint160(trader);
    }

    function packTypePriceCollection(
        OrderType orderType,
        uint256 price,
        address collection
    ) private pure returns (uint256) {
        return (uint256(orderType) << (31 * 8)) | (price << (20 * 8)) | uint160(collection);
    }

    function packFee(FeeRate memory fee) private pure returns (uint256) {
        return (uint256(fee.rate) << (20 * 8)) | uint160(fee.recipient);
    }

    uint256[50] private __gap;
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

uint256 constant Bytes1_shift = 0xf8;
uint256 constant Bytes4_shift = 0xe0;
uint256 constant Bytes20_shift = 0x60;
uint256 constant One_word = 0x20;

uint256 constant Memory_pointer = 0x40;

uint256 constant AssetType_ERC721 = 0;
uint256 constant AssetType_ERC1155 = 1;

uint256 constant OrderType_ASK = 0;
uint256 constant OrderType_BID = 1;

uint256 constant Pool_withdrawFrom_selector = 0x9555a94200000000000000000000000000000000000000000000000000000000;
uint256 constant Pool_withdrawFrom_from_offset = 0x04;
uint256 constant Pool_withdrawFrom_to_offset = 0x24;
uint256 constant Pool_withdrawFrom_amount_offset = 0x44;
uint256 constant Pool_withdrawFrom_size = 0x64;

uint256 constant Pool_deposit_selector = 0xf340fa0100000000000000000000000000000000000000000000000000000000;
uint256 constant Pool_deposit_user_offset = 0x04;
uint256 constant Pool_deposit_size = 0x24;

uint256 constant ERC20_transferFrom_selector = 0x23b872dd00000000000000000000000000000000000000000000000000000000;
uint256 constant ERC721_safeTransferFrom_selector = 0x42842e0e00000000000000000000000000000000000000000000000000000000;
uint256 constant ERC1155_safeTransferFrom_selector = 0xf242432a00000000000000000000000000000000000000000000000000000000;
uint256 constant ERC20_transferFrom_size = 0x64;
uint256 constant ERC721_safeTransferFrom_size = 0x64;
uint256 constant ERC1155_safeTransferFrom_size = 0xc4;

uint256 constant OracleSignatures_size = 0x59;
uint256 constant OracleSignatures_s_offset = 0x20;
uint256 constant OracleSignatures_v_offset = 0x40;
uint256 constant OracleSignatures_blockNumber_offset = 0x41;
uint256 constant OracleSignatures_oracle_offset = 0x45;

uint256 constant Signatures_size = 0x41;
uint256 constant Signatures_s_offset = 0x20;
uint256 constant Signatures_v_offset = 0x40;

uint256 constant ERC20_transferFrom_from_offset = 0x4;
uint256 constant ERC20_transferFrom_to_offset = 0x24;
uint256 constant ERC20_transferFrom_amount_offset = 0x44;

uint256 constant ERC721_safeTransferFrom_from_offset = 0x4;
uint256 constant ERC721_safeTransferFrom_to_offset = 0x24;
uint256 constant ERC721_safeTransferFrom_id_offset = 0x44;

uint256 constant ERC1155_safeTransferFrom_from_offset = 0x4;
uint256 constant ERC1155_safeTransferFrom_to_offset = 0x24;
uint256 constant ERC1155_safeTransferFrom_id_offset = 0x44;
uint256 constant ERC1155_safeTransferFrom_amount_offset = 0x64;
uint256 constant ERC1155_safeTransferFrom_data_pointer_offset = 0x84;
uint256 constant ERC1155_safeTransferFrom_data_offset = 0xa4;

uint256 constant Delegate_transfer_selector = 0xa1ccb98e00000000000000000000000000000000000000000000000000000000;
uint256 constant Delegate_transfer_calldata_offset = 0x1c;

uint256 constant Order_size = 0x100;
uint256 constant Order_trader_offset = 0x00;
uint256 constant Order_collection_offset = 0x20;
uint256 constant Order_listingsRoot_offset = 0x40;
uint256 constant Order_numberOfListings_offset = 0x60;
uint256 constant Order_expirationTime_offset = 0x80;
uint256 constant Order_assetType_offset = 0xa0;
uint256 constant Order_makerFee_offset = 0xc0;
uint256 constant Order_salt_offset = 0xe0;

uint256 constant Exchange_size = 0x80;
uint256 constant Exchange_askIndex_offset = 0x00;
uint256 constant Exchange_proof_offset = 0x20;
uint256 constant Exchange_maker_offset = 0x40;
uint256 constant Exchange_taker_offset = 0x60;

uint256 constant BidExchange_size = 0x80;
uint256 constant BidExchange_askIndex_offset = 0x00;
uint256 constant BidExchange_proof_offset = 0x20;
uint256 constant BidExchange_maker_offset = 0x40;
uint256 constant BidExchange_taker_offset = 0x60;

uint256 constant Listing_size = 0x80;
uint256 constant Listing_index_offset = 0x00;
uint256 constant Listing_tokenId_offset = 0x20;
uint256 constant Listing_amount_offset = 0x40;
uint256 constant Listing_price_offset = 0x60;

uint256 constant Taker_size = 0x40;
uint256 constant Taker_tokenId_offset = 0x00;
uint256 constant Taker_amount_offset = 0x20;

uint256 constant StateUpdate_size = 0x80;
uint256 constant StateUpdate_salt_offset = 0x20;
uint256 constant StateUpdate_leaf_offset = 0x40;
uint256 constant StateUpdate_value_offset = 0x60;

uint256 constant Transfer_size = 0xa0;
uint256 constant Transfer_trader_offset = 0x00;
uint256 constant Transfer_id_offset = 0x20;
uint256 constant Transfer_amount_offset = 0x40;
uint256 constant Transfer_collection_offset = 0x60;
uint256 constant Transfer_assetType_offset = 0x80;

uint256 constant ExecutionBatch_selector_offset = 0x20;
uint256 constant ExecutionBatch_calldata_offset = 0x40;
uint256 constant ExecutionBatch_base_size = 0xa0; // size of the executionBatch without the flattened dynamic elements
uint256 constant ExecutionBatch_taker_offset = 0x00;
uint256 constant ExecutionBatch_orderType_offset = 0x20;
uint256 constant ExecutionBatch_transfers_pointer_offset = 0x40;
uint256 constant ExecutionBatch_length_offset = 0x60;
uint256 constant ExecutionBatch_transfers_offset = 0x80;

// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import "./lib/Constants.sol";
import {
    TakeAsk,
    TakeBid,
    TakeAskSingle,
    TakeBidSingle,
    FeeRate,
    Order,
    OrderType,
    AssetType,
    Listing
} from "./lib/Structs.sol";
import { ISignatures } from "./interfaces/ISignatures.sol";

abstract contract Signatures is ISignatures {
    string private constant _NAME = "Blur Exchange";
    string private constant _VERSION = "1.0";

    bytes32 private immutable _FEE_RATE_TYPEHASH;
    bytes32 private immutable _ORDER_TYPEHASH;
    bytes32 private immutable _DOMAIN_SEPARATOR;

    mapping(address => uint256) public oracles;
    mapping(address => uint256) public nonces;
    uint256 public blockRange;

    constructor(address proxy) {
        (_FEE_RATE_TYPEHASH, _ORDER_TYPEHASH, _DOMAIN_SEPARATOR) = _createTypehashes(proxy);
    }

    /**
     * @notice Verify the domain separator produced during deployment of the implementation matches that of the proxy
     */
    function verifyDomain() public view {
        bytes32 eip712DomainTypehash = keccak256(
            bytes.concat(
                "EIP712Domain(",
                "string name,",
                "string version,",
                "uint256 chainId,",
                "address verifyingContract",
                ")"
            )
        );

        bytes32 domainSeparator = _hashDomain(
            eip712DomainTypehash,
            keccak256(bytes(_NAME)),
            keccak256(bytes(_VERSION)),
            address(this)
        );
        if (_DOMAIN_SEPARATOR != domainSeparator) {
            revert InvalidDomain();
        }
    }

    /**
     * @notice Return version and domain separator
     */
    function information() external view returns (string memory version, bytes32 domainSeparator) {
        version = _VERSION;
        domainSeparator = _DOMAIN_SEPARATOR;
    }

    /**
     * @notice Create a hash of TakeAsk calldata with an approved caller
     * @param inputs TakeAsk inputs
     * @param _caller Address approved to execute the calldata
     * @return Calldata hash
     */
    function hashTakeAsk(TakeAsk memory inputs, address _caller) external pure returns (bytes32) {
        return _hashCalldata(_caller);
    }

    /**
     * @notice Create a hash of TakeBid calldata with an approved caller
     * @param inputs TakeBid inputs
     * @param _caller Address approved to execute the calldata
     * @return Calldata hash
     */
    function hashTakeBid(TakeBid memory inputs, address _caller) external pure returns (bytes32) {
        return _hashCalldata(_caller);
    }

    /**
     * @notice Create a hash of TakeAskSingle calldata with an approved caller
     * @param inputs TakeAskSingle inputs
     * @param _caller Address approved to execute the calldata
     * @return Calldata hash
     */
    function hashTakeAskSingle(
        TakeAskSingle memory inputs,
        address _caller
    ) external pure returns (bytes32) {
        return _hashCalldata(_caller);
    }

    /**
     * @notice Create a hash of TakeBidSingle calldata with an approved caller
     * @param inputs TakeBidSingle inputs
     * @param _caller Address approved to execute the calldata
     * @return Calldata hash
     */
    function hashTakeBidSingle(
        TakeBidSingle memory inputs,
        address _caller
    ) external pure returns (bytes32) {
        return _hashCalldata(_caller);
    }

    /**
     * @notice Create an EIP712 hash of an Order
     * @dev Includes two additional parameters not in the struct (orderType, nonce)
     * @param order Order to hash
     * @param orderType OrderType of the Order
     * @return Order EIP712 hash
     */
    function hashOrder(Order memory order, OrderType orderType) public view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    _ORDER_TYPEHASH,
                    order.trader,
                    order.collection,
                    order.listingsRoot,
                    order.numberOfListings,
                    order.expirationTime,
                    order.assetType,
                    _hashFeeRate(order.makerFee),
                    order.salt,
                    orderType,
                    nonces[order.trader]
                )
            );
    }

    /**
     * @notice Create a hash of a Listing struct
     * @param listing Listing to hash
     * @return Listing hash
     */
    function hashListing(Listing memory listing) public pure returns (bytes32) {
        return keccak256(abi.encode(listing.index, listing.tokenId, listing.amount, listing.price));
    }

    /**
     * @notice Create a hash of calldata with an approved caller
     * @param _caller Address approved to execute the calldata
     * @return hash Calldata hash
     */
    function _hashCalldata(address _caller) internal pure returns (bytes32 hash) {
        assembly {
            let nextPointer := mload(0x40)
            let size := add(sub(nextPointer, 0x80), 0x20)
            mstore(nextPointer, _caller)
            hash := keccak256(0x80, size)
        }
    }

    /**
     * @notice Create an EIP712 hash of a FeeRate struct
     * @param feeRate FeeRate to hash
     * @return FeeRate EIP712 hash
     */
    function _hashFeeRate(FeeRate memory feeRate) private view returns (bytes32) {
        return keccak256(abi.encode(_FEE_RATE_TYPEHASH, feeRate.recipient, feeRate.rate));
    }

    /**
     * @notice Create an EIP712 hash to sign
     * @param hash Primary EIP712 object hash
     * @return EIP712 hash
     */
    function _hashToSign(bytes32 hash) private view returns (bytes32) {
        return keccak256(bytes.concat(bytes2(0x1901), _DOMAIN_SEPARATOR, hash));
    }

    /**
     * @notice Generate all EIP712 Typehashes
     */
    function _createTypehashes(
        address proxy
    )
        private
        view
        returns (bytes32 feeRateTypehash, bytes32 orderTypehash, bytes32 domainSeparator)
    {
        bytes32 eip712DomainTypehash = keccak256(
            bytes.concat(
                "EIP712Domain(",
                "string name,",
                "string version,",
                "uint256 chainId,",
                "address verifyingContract",
                ")"
            )
        );

        bytes memory feeRateTypestring = "FeeRate(address recipient,uint16 rate)";

        orderTypehash = keccak256(
            bytes.concat(
                "Order(",
                "address trader,",
                "address collection,",
                "bytes32 listingsRoot,",
                "uint256 numberOfListings,",
                "uint256 expirationTime,",
                "uint8 assetType,",
                "FeeRate makerFee,",
                "uint256 salt,",
                "uint8 orderType,",
                "uint256 nonce",
                ")",
                feeRateTypestring
            )
        );

        feeRateTypehash = keccak256(feeRateTypestring);

        domainSeparator = _hashDomain(
            eip712DomainTypehash,
            keccak256(bytes(_NAME)),
            keccak256(bytes(_VERSION)),
            proxy
        );
    }

    /**
     * @notice Create an EIP712 domain separator
     * @param eip712DomainTypehash Typehash of the EIP712Domain struct
     * @param nameHash Hash of the contract name
     * @param versionHash Hash of the version string
     * @param proxy Address of the proxy this implementation will be behind
     * @return EIP712Domain hash
     */
    function _hashDomain(
        bytes32 eip712DomainTypehash,
        bytes32 nameHash,
        bytes32 versionHash,
        address proxy
    ) private view returns (bytes32) {
        return
            keccak256(
                abi.encode(eip712DomainTypehash, nameHash, versionHash, block.chainid, proxy)
            );
    }

    /**
     * @notice Verify EIP712 signature
     * @param signer Address of the alleged signer
     * @param hash EIP712 hash
     * @param signatures Packed bytes array of order signatures
     * @param index Index of the signature to verify
     * @return authorized Validity of the signature
     */
    function _verifyAuthorization(
        address signer,
        bytes32 hash,
        bytes memory signatures,
        uint256 index
    ) internal view returns (bool authorized) {
        bytes32 hashToSign = _hashToSign(hash);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            let signatureOffset := add(add(signatures, One_word), mul(Signatures_size, index))
            r := mload(signatureOffset)
            s := mload(add(signatureOffset, Signatures_s_offset))
            v := shr(Bytes1_shift, mload(add(signatureOffset, Signatures_v_offset)))
        }
        authorized = _verify(signer, hashToSign, v, r, s);
    }

    modifier verifyOracleSignature(bytes32 hash, bytes calldata oracleSignature) {
        bytes32 r;
        bytes32 s;
        uint8 v;
        uint32 blockNumber;
        address oracle;
        assembly {
            let signatureOffset := oracleSignature.offset
            r := calldataload(signatureOffset)
            s := calldataload(add(signatureOffset, OracleSignatures_s_offset))
            v := shr(Bytes1_shift, calldataload(add(signatureOffset, OracleSignatures_v_offset)))
            blockNumber := shr(
                Bytes4_shift,
                calldataload(add(signatureOffset, OracleSignatures_blockNumber_offset))
            )
            oracle := shr(
                Bytes20_shift,
                calldataload(add(signatureOffset, OracleSignatures_oracle_offset))
            )
        }
        if (blockNumber + blockRange < block.number) {
            revert ExpiredOracleSignature();
        }
        if (oracles[oracle] == 0) {
            revert UnauthorizedOracle();
        }
        if (!_verify(oracle, keccak256(abi.encodePacked(hash, blockNumber)), v, r, s)) {
            revert InvalidOracleSignature();
        }
        _;
    }

    /**
     * @notice Verify signature of digest
     * @param signer Address of expected signer
     * @param digest Signature digest
     * @param v v parameter
     * @param r r parameter
     * @param s s parameter
     */
    function _verify(
        address signer,
        bytes32 digest,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) private pure returns (bool valid) {
        address recoveredSigner = ecrecover(digest, v, r, s);
        if (recoveredSigner != address(0) && recoveredSigner == signer) {
            valid = true;
        }
    }

    uint256[47] private __gap;
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.8.3) (proxy/ERC1967/ERC1967Upgrade.sol)

pragma solidity ^0.8.2;

import "../beacon/IBeaconUpgradeable.sol";
import "../../interfaces/IERC1967Upgradeable.sol";
import "../../interfaces/draft-IERC1822Upgradeable.sol";
import "../../utils/AddressUpgradeable.sol";
import "../../utils/StorageSlotUpgradeable.sol";
import "../utils/Initializable.sol";

/**
 * @dev This abstract contract provides getters and event emitting update functions for
 * https://eips.ethereum.org/EIPS/eip-1967[EIP1967] slots.
 *
 * _Available since v4.1._
 *
 * @custom:oz-upgrades-unsafe-allow delegatecall
 */
abstract contract ERC1967UpgradeUpgradeable is Initializable, IERC1967Upgradeable {
    function __ERC1967Upgrade_init() internal onlyInitializing {
    }

    function __ERC1967Upgrade_init_unchained() internal onlyInitializing {
    }
    // This is the keccak-256 hash of "eip1967.proxy.rollback" subtracted by 1
    bytes32 private constant _ROLLBACK_SLOT = 0x4910fdfa16fed3260ed0e7147f7cc6da11a60208b5b9406d12a635614ffd9143;

    /**
     * @dev Storage slot with the address of the current implementation.
     * This is the keccak-256 hash of "eip1967.proxy.implementation" subtracted by 1, and is
     * validated in the constructor.
     */
    bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    /**
     * @dev Returns the current implementation address.
     */
    function _getImplementation() internal view returns (address) {
        return StorageSlotUpgradeable.getAddressSlot(_IMPLEMENTATION_SLOT).value;
    }

    /**
     * @dev Stores a new address in the EIP1967 implementation slot.
     */
    function _setImplementation(address newImplementation) private {
        require(AddressUpgradeable.isContract(newImplementation), "ERC1967: new implementation is not a contract");
        StorageSlotUpgradeable.getAddressSlot(_IMPLEMENTATION_SLOT).value = newImplementation;
    }

    /**
     * @dev Perform implementation upgrade
     *
     * Emits an {Upgraded} event.
     */
    function _upgradeTo(address newImplementation) internal {
        _setImplementation(newImplementation);
        emit Upgraded(newImplementation);
    }

    /**
     * @dev Perform implementation upgrade with additional setup call.
     *
     * Emits an {Upgraded} event.
     */
    function _upgradeToAndCall(
        address newImplementation,
        bytes memory data,
        bool forceCall
    ) internal {
        _upgradeTo(newImplementation);
        if (data.length > 0 || forceCall) {
            _functionDelegateCall(newImplementation, data);
        }
    }

    /**
     * @dev Perform implementation upgrade with security checks for UUPS proxies, and additional setup call.
     *
     * Emits an {Upgraded} event.
     */
    function _upgradeToAndCallUUPS(
        address newImplementation,
        bytes memory data,
        bool forceCall
    ) internal {
        // Upgrades from old implementations will perform a rollback test. This test requires the new
        // implementation to upgrade back to the old, non-ERC1822 compliant, implementation. Removing
        // this special case will break upgrade paths from old UUPS implementation to new ones.
        if (StorageSlotUpgradeable.getBooleanSlot(_ROLLBACK_SLOT).value) {
            _setImplementation(newImplementation);
        } else {
            try IERC1822ProxiableUpgradeable(newImplementation).proxiableUUID() returns (bytes32 slot) {
                require(slot == _IMPLEMENTATION_SLOT, "ERC1967Upgrade: unsupported proxiableUUID");
            } catch {
                revert("ERC1967Upgrade: new implementation is not UUPS");
            }
            _upgradeToAndCall(newImplementation, data, forceCall);
        }
    }

    /**
     * @dev Storage slot with the admin of the contract.
     * This is the keccak-256 hash of "eip1967.proxy.admin" subtracted by 1, and is
     * validated in the constructor.
     */
    bytes32 internal constant _ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    /**
     * @dev Returns the current admin.
     */
    function _getAdmin() internal view returns (address) {
        return StorageSlotUpgradeable.getAddressSlot(_ADMIN_SLOT).value;
    }

    /**
     * @dev Stores a new address in the EIP1967 admin slot.
     */
    function _setAdmin(address newAdmin) private {
        require(newAdmin != address(0), "ERC1967: new admin is the zero address");
        StorageSlotUpgradeable.getAddressSlot(_ADMIN_SLOT).value = newAdmin;
    }

    /**
     * @dev Changes the admin of the proxy.
     *
     * Emits an {AdminChanged} event.
     */
    function _changeAdmin(address newAdmin) internal {
        emit AdminChanged(_getAdmin(), newAdmin);
        _setAdmin(newAdmin);
    }

    /**
     * @dev The storage slot of the UpgradeableBeacon contract which defines the implementation for this proxy.
     * This is bytes32(uint256(keccak256('eip1967.proxy.beacon')) - 1)) and is validated in the constructor.
     */
    bytes32 internal constant _BEACON_SLOT = 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50;

    /**
     * @dev Returns the current beacon.
     */
    function _getBeacon() internal view returns (address) {
        return StorageSlotUpgradeable.getAddressSlot(_BEACON_SLOT).value;
    }

    /**
     * @dev Stores a new beacon in the EIP1967 beacon slot.
     */
    function _setBeacon(address newBeacon) private {
        require(AddressUpgradeable.isContract(newBeacon), "ERC1967: new beacon is not a contract");
        require(
            AddressUpgradeable.isContract(IBeaconUpgradeable(newBeacon).implementation()),
            "ERC1967: beacon implementation is not a contract"
        );
        StorageSlotUpgradeable.getAddressSlot(_BEACON_SLOT).value = newBeacon;
    }

    /**
     * @dev Perform beacon upgrade with additional setup call. Note: This upgrades the address of the beacon, it does
     * not upgrade the implementation contained in the beacon (see {UpgradeableBeacon-_setImplementation} for that).
     *
     * Emits a {BeaconUpgraded} event.
     */
    function _upgradeBeaconToAndCall(
        address newBeacon,
        bytes memory data,
        bool forceCall
    ) internal {
        _setBeacon(newBeacon);
        emit BeaconUpgraded(newBeacon);
        if (data.length > 0 || forceCall) {
            _functionDelegateCall(IBeaconUpgradeable(newBeacon).implementation(), data);
        }
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],
     * but performing a delegate call.
     *
     * _Available since v3.4._
     */
    function _functionDelegateCall(address target, bytes memory data) private returns (bytes memory) {
        require(AddressUpgradeable.isContract(target), "Address: delegate call to non-contract");

        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory returndata) = target.delegatecall(data);
        return AddressUpgradeable.verifyCallResult(success, returndata, "Address: low-level delegate call failed");
    }

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[50] private __gap;
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.7.0) (access/Ownable.sol)

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
     * `onlyOwner` functions anymore. Can only be called by the current owner.
     *
     * NOTE: Renouncing ownership will leave the contract without an owner,
     * thereby removing any functionality that is only available to the owner.
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
pragma solidity 0.8.17;

import {
    TakeAsk,
    TakeBid,
    TakeAskSingle,
    TakeBidSingle,
    Order,
    Exchange,
    Fees,
    FeeRate,
    AssetType,
    OrderType,
    Transfer,
    FungibleTransfers,
    StateUpdate,
    Cancel,
    Listing
} from "../lib/Structs.sol";

interface IBlurExchangeV2 {
    error InsufficientFunds();
    error TokenTransferFailed();
    error InvalidOrder();
    error ProtocolFeeTooHigh();

    event NewProtocolFee(address indexed recipient, uint16 indexed rate);
    event NewGovernor(address indexed governor);
    event NewBlockRange(uint256 blockRange);
    event CancelTrade(address indexed user, bytes32 hash, uint256 index, uint256 amount);
    event NonceIncremented(address indexed user, uint256 newNonce);
    event SetOracle(address indexed user, bool approved);

    function initialize() external;

    function setProtocolFee(address recipient, uint16 rate) external;
    function setGovernor(address _governor) external;
    function setOracle(address oracle, bool approved) external;
    function setBlockRange(uint256 _blockRange) external;
    function cancelTrades(Cancel[] memory cancels) external;
    function incrementNonce() external;

    /*//////////////////////////////////////////////////////////////
                          EXECUTION WRAPPERS
    //////////////////////////////////////////////////////////////*/

    function takeAsk(TakeAsk memory inputs, bytes calldata oracleSignature) external payable;
    function takeBid(TakeBid memory inputs, bytes calldata oracleSignature) external;
    function takeAskSingle(TakeAskSingle memory inputs, bytes calldata oracleSignature) external payable;
    function takeBidSingle(TakeBidSingle memory inputs, bytes calldata oracleSignature) external;

    /*//////////////////////////////////////////////////////////////
                        EXECUTION POOL WRAPPERS
    //////////////////////////////////////////////////////////////*/

    function takeAskSinglePool(
        TakeAskSingle memory inputs,
        bytes calldata oracleSignature,
        uint256 amountToWithdraw
    ) external payable;

    function takeAskPool(
        TakeAsk memory inputs,
        bytes calldata oracleSignature,
        uint256 amountToWithdraw
    ) external payable;
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.8.0) (access/Ownable2Step.sol)

pragma solidity ^0.8.0;

import "./OwnableUpgradeable.sol";
import "../proxy/utils/Initializable.sol";

/**
 * @dev Contract module which provides access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * By default, the owner account will be the one that deploys the contract. This
 * can later be changed with {transferOwnership} and {acceptOwnership}.
 *
 * This module is used through inheritance. It will make available all functions
 * from parent (Ownable).
 */
abstract contract Ownable2StepUpgradeable is Initializable, OwnableUpgradeable {
    function __Ownable2Step_init() internal onlyInitializing {
        __Ownable_init_unchained();
    }

    function __Ownable2Step_init_unchained() internal onlyInitializing {
    }
    address private _pendingOwner;

    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Returns the address of the pending owner.
     */
    function pendingOwner() public view virtual returns (address) {
        return _pendingOwner;
    }

    /**
     * @dev Starts the ownership transfer of the contract to a new account. Replaces the pending transfer if there is one.
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual override onlyOwner {
        _pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner(), newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`) and deletes any pending owner.
     * Internal function without access restriction.
     */
    function _transferOwnership(address newOwner) internal virtual override {
        delete _pendingOwner;
        super._transferOwnership(newOwner);
    }

    /**
     * @dev The new owner accepts the ownership transfer.
     */
    function acceptOwnership() external {
        address sender = _msgSender();
        require(pendingOwner() == sender, "Ownable2Step: caller is not the new owner");
        _transferOwnership(sender);
    }

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[49] private __gap;
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.8.0) (utils/Address.sol)

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
     * https://diligence.consensys.net/posts/2019/09/stop-using-soliditys-transfer-now/[Learn more].
     *
     * IMPORTANT: because control is transferred to `recipient`, care must be
     * taken to not create reentrancy vulnerabilities. Consider using
     * {ReentrancyGuard} or the
     * https://solidity.readthedocs.io/en/v0.5.11/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].
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
    function functionCallWithValue(
        address target,
        bytes memory data,
        uint256 value
    ) internal returns (bytes memory) {
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
pragma solidity ^0.8.17;

struct TakeAsk {
    Order[] orders;
    Exchange[] exchanges;
    FeeRate takerFee;
    bytes signatures;
    address tokenRecipient;
}

struct TakeAskSingle {
    Order order;
    Exchange exchange;
    FeeRate takerFee;
    bytes signature;
    address tokenRecipient;
}

struct TakeBid {
    Order[] orders;
    Exchange[] exchanges;
    FeeRate takerFee;
    bytes signatures;
}

struct TakeBidSingle {
    Order order;
    Exchange exchange;
    FeeRate takerFee;
    bytes signature;
}

enum AssetType {
    ERC721,
    ERC1155
}

enum OrderType {
    ASK,
    BID
}

struct Exchange { // Size: 0x80
    uint256 index; // 0x00
    bytes32[] proof; // 0x20
    Listing listing; // 0x40
    Taker taker; // 0x60
}

struct Listing { // Size: 0x80
    uint256 index; // 0x00
    uint256 tokenId; // 0x20
    uint256 amount; // 0x40
    uint256 price; // 0x60
}

struct Taker { // Size: 0x40
    uint256 tokenId; // 0x00
    uint256 amount; // 0x20
}

struct Order { // Size: 0x100
    address trader; // 0x00
    address collection; // 0x20
    bytes32 listingsRoot; // 0x40
    uint256 numberOfListings; // 0x60
    uint256 expirationTime; // 0x80
    AssetType assetType; // 0xa0
    FeeRate makerFee; // 0xc0
    uint256 salt; // 0xe0
}

/*
Reference only; struct is composed manually using calldata formatting in execution
struct ExecutionBatch { // Size: 0x80
    address taker; // 0x00
    OrderType orderType; // 0x20
    Transfer[] transfers; // 0x40
    uint256 length; // 0x60
}
*/

struct Transfer { // Size: 0xa0
    address trader; // 0x00
    uint256 id; // 0x20
    uint256 amount; // 0x40
    address collection; // 0x60
    AssetType assetType; // 0x80
}

struct FungibleTransfers {
    uint256 totalProtocolFee;
    uint256 totalSellerTransfer;
    uint256 totalTakerFee;
    uint256 feeRecipientId;
    uint256 makerId;
    address[] feeRecipients;
    address[] makers;
    uint256[] makerTransfers;
    uint256[] feeTransfers;
    AtomicExecution[] executions;
}

struct AtomicExecution { // Size: 0xe0
    uint256 makerId; // 0x00
    uint256 sellerAmount; // 0x20
    uint256 makerFeeRecipientId; // 0x40
    uint256 makerFeeAmount; // 0x60
    uint256 takerFeeAmount; // 0x80
    uint256 protocolFeeAmount; // 0xa0
    StateUpdate stateUpdate; // 0xc0
}

struct StateUpdate { // Size: 0xa0
    address trader; // 0x00
    bytes32 hash; // 0x20
    uint256 index; // 0x40
    uint256 value; // 0x60
    uint256 maxAmount; // 0x80
}

struct Fees { // Size: 0x40
    FeeRate protocolFee; // 0x00
    FeeRate takerFee; // 0x20
}

struct FeeRate { // Size: 0x40
    address recipient; // 0x00
    uint16 rate; // 0x20
}

struct Cancel {
    bytes32 hash;
    uint256 index;
    uint256 amount;
}

