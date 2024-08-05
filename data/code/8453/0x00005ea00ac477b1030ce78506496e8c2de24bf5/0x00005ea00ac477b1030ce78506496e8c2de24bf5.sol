
pragma solidity >=0.8.0;
abstract contract ReentrancyGuard {
    uint256 private locked = 1;
    modifier nonReentrant() virtual {
        require(locked == 1, "REENTRANCY");
        locked = 2;
        _;
        locked = 1;
    }
}
pragma solidity ^0.8.0;
interface IERC165 {
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}
pragma solidity 0.8.17;
import { PublicDrop, TokenGatedDropStage, SignedMintValidationParams } from "./SeaDropStructs.sol";
interface SeaDropErrorsAndEvents {
    error NotActive(
        uint256 currentTimestamp,
        uint256 startTimestamp,
        uint256 endTimestamp
    );
    error MintQuantityCannotBeZero();
    error MintQuantityExceedsMaxMintedPerWallet(uint256 total, uint256 allowed);
    error MintQuantityExceedsMaxSupply(uint256 total, uint256 maxSupply);
    error MintQuantityExceedsMaxTokenSupplyForStage(
        uint256 total, 
        uint256 maxTokenSupplyForStage
    );
    error FeeRecipientCannotBeZeroAddress();
    error FeeRecipientNotPresent();
     error InvalidFeeBps(uint256 feeBps);
    error DuplicateFeeRecipient();
    error FeeRecipientNotAllowed();
    error CreatorPayoutAddressCannotBeZeroAddress();
    error IncorrectPayment(uint256 got, uint256 want);
    error InvalidProof();
    error SignerCannotBeZeroAddress();
    error InvalidSignature(address recoveredSigner);
    error SignerNotPresent();
    error PayerNotPresent();
    error DuplicatePayer();
    error PayerNotAllowed();
    error PayerCannotBeZeroAddress();
    error OnlyINonFungibleSeaDropToken(address sender);
    error TokenGatedNotTokenOwner(
        address nftContract,
        address allowedNftToken,
        uint256 allowedNftTokenId
    );
    error TokenGatedTokenIdAlreadyRedeemed(
        address nftContract,
        address allowedNftToken,
        uint256 allowedNftTokenId
    );
     error TokenGatedDropStageNotPresent();
     error TokenGatedDropAllowedNftTokenCannotBeZeroAddress();
     error TokenGatedDropAllowedNftTokenCannotBeDropToken();
    error InvalidSignedMintPrice(uint256 got, uint256 minimum);
    error InvalidSignedMaxTotalMintableByWallet(uint256 got, uint256 maximum);
    error InvalidSignedStartTime(uint256 got, uint256 minimum);
    error InvalidSignedEndTime(uint256 got, uint256 maximum);
     error InvalidSignedMaxTokenSupplyForStage(uint256 got, uint256 maximum);
    error InvalidSignedFeeBps(uint256 got, uint256 minimumOrMaximum);
    error SignedMintsMustRestrictFeeRecipients();
    error SignatureAlreadyUsed();
    event SeaDropMint(
        address indexed nftContract,
        address indexed minter,
        address indexed feeRecipient,
        address payer,
        uint256 quantityMinted,
        uint256 unitMintPrice,
        uint256 feeBps,
        uint256 dropStageIndex
    );
    event PublicDropUpdated(
        address indexed nftContract,
        PublicDrop publicDrop
    );
    event TokenGatedDropStageUpdated(
        address indexed nftContract,
        address indexed allowedNftToken,
        TokenGatedDropStage dropStage
    );
    event AllowListUpdated(
        address indexed nftContract,
        bytes32 indexed previousMerkleRoot,
        bytes32 indexed newMerkleRoot,
        string[] publicKeyURI,
        string allowListURI
    );
    event DropURIUpdated(address indexed nftContract, string newDropURI);
    event CreatorPayoutAddressUpdated(
        address indexed nftContract,
        address indexed newPayoutAddress
    );
    event AllowedFeeRecipientUpdated(
        address indexed nftContract,
        address indexed feeRecipient,
        bool indexed allowed
    );
    event SignedMintValidationParamsUpdated(
        address indexed nftContract,
        address indexed signer,
        SignedMintValidationParams signedMintValidationParams
    );   
    event PayerUpdated(
        address indexed nftContract,
        address indexed payer,
        bool indexed allowed
    );
}
pragma solidity ^0.8.0;
library MerkleProof {
    function verify(
        bytes32[] memory proof,
        bytes32 root,
        bytes32 leaf
    ) internal pure returns (bool) {
        return processProof(proof, leaf) == root;
    }
    function verifyCalldata(
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 leaf
    ) internal pure returns (bool) {
        return processProofCalldata(proof, leaf) == root;
    }
    function processProof(bytes32[] memory proof, bytes32 leaf) internal pure returns (bytes32) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computedHash = _hashPair(computedHash, proof[i]);
        }
        return computedHash;
    }
    function processProofCalldata(bytes32[] calldata proof, bytes32 leaf) internal pure returns (bytes32) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computedHash = _hashPair(computedHash, proof[i]);
        }
        return computedHash;
    }
    function multiProofVerify(
        bytes32[] memory proof,
        bool[] memory proofFlags,
        bytes32 root,
        bytes32[] memory leaves
    ) internal pure returns (bool) {
        return processMultiProof(proof, proofFlags, leaves) == root;
    }
    function multiProofVerifyCalldata(
        bytes32[] calldata proof,
        bool[] calldata proofFlags,
        bytes32 root,
        bytes32[] memory leaves
    ) internal pure returns (bool) {
        return processMultiProofCalldata(proof, proofFlags, leaves) == root;
    }
    function processMultiProof(
        bytes32[] memory proof,
        bool[] memory proofFlags,
        bytes32[] memory leaves
    ) internal pure returns (bytes32 merkleRoot) {
        uint256 leavesLen = leaves.length;
        uint256 totalHashes = proofFlags.length;
        require(leavesLen + proof.length - 1 == totalHashes, "MerkleProof: invalid multiproof");
        bytes32[] memory hashes = new bytes32[](totalHashes);
        uint256 leafPos = 0;
        uint256 hashPos = 0;
        uint256 proofPos = 0;
        for (uint256 i = 0; i < totalHashes; i++) {
            bytes32 a = leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++];
            bytes32 b = proofFlags[i] ? leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++] : proof[proofPos++];
            hashes[i] = _hashPair(a, b);
        }
        if (totalHashes > 0) {
            return hashes[totalHashes - 1];
        } else if (leavesLen > 0) {
            return leaves[0];
        } else {
            return proof[0];
        }
    }
    function processMultiProofCalldata(
        bytes32[] calldata proof,
        bool[] calldata proofFlags,
        bytes32[] memory leaves
    ) internal pure returns (bytes32 merkleRoot) {
        uint256 leavesLen = leaves.length;
        uint256 totalHashes = proofFlags.length;
        require(leavesLen + proof.length - 1 == totalHashes, "MerkleProof: invalid multiproof");
        bytes32[] memory hashes = new bytes32[](totalHashes);
        uint256 leafPos = 0;
        uint256 hashPos = 0;
        uint256 proofPos = 0;
        for (uint256 i = 0; i < totalHashes; i++) {
            bytes32 a = leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++];
            bytes32 b = proofFlags[i] ? leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++] : proof[proofPos++];
            hashes[i] = _hashPair(a, b);
        }
        if (totalHashes > 0) {
            return hashes[totalHashes - 1];
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
        assembly {
            mstore(0x00, a)
            mstore(0x20, b)
            value := keccak256(0x00, 0x40)
        }
    }
}
pragma solidity 0.8.17;
import {
    ISeaDropTokenContractMetadata
} from "../interfaces/ISeaDropTokenContractMetadata.sol";
import {
    AllowListData,
    PublicDrop,
    TokenGatedDropStage,
    SignedMintValidationParams
} from "../lib/SeaDropStructs.sol";
import {
    IERC165
} from "openzeppelin-contracts/contracts/utils/introspection/IERC165.sol";
interface INonFungibleSeaDropToken is ISeaDropTokenContractMetadata, IERC165 {
    error OnlyAllowedSeaDrop();
    event AllowedSeaDropUpdated(address[] allowedSeaDrop);
    function updateAllowedSeaDrop(address[] calldata allowedSeaDrop) external;
    function mintSeaDrop(address minter, uint256 quantity) external payable;
    function getMintStats(address minter)
        external
        view
        returns (
            uint256 minterNumMinted,
            uint256 currentTotalSupply,
            uint256 maxSupply
        );
    function updatePublicDrop(
        address seaDropImpl,
        PublicDrop calldata publicDrop
    ) external;
    function updateAllowList(
        address seaDropImpl,
        AllowListData calldata allowListData
    ) external;
    function updateTokenGatedDrop(
        address seaDropImpl,
        address allowedNftToken,
        TokenGatedDropStage calldata dropStage
    ) external;
    function updateDropURI(address seaDropImpl, string calldata dropURI)
        external;
    function updateCreatorPayoutAddress(
        address seaDropImpl,
        address payoutAddress
    ) external;
    function updateAllowedFeeRecipient(
        address seaDropImpl,
        address feeRecipient,
        bool allowed
    ) external;
    function updateSignedMintValidationParams(
        address seaDropImpl,
        address signer,
        SignedMintValidationParams memory signedMintValidationParams
    ) external;
    function updatePayer(
        address seaDropImpl,
        address payer,
        bool allowed
    ) external;
}
pragma solidity >=0.8.0;
abstract contract ERC20 {
    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);
    string public name;
    string public symbol;
    uint8 public immutable decimals;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 internal immutable INITIAL_CHAIN_ID;
    bytes32 internal immutable INITIAL_DOMAIN_SEPARATOR;
    mapping(address => uint256) public nonces;
    constructor(
        string memory _name,
        string memory _symbol,
        uint8 _decimals
    ) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
        INITIAL_CHAIN_ID = block.chainid;
        INITIAL_DOMAIN_SEPARATOR = computeDomainSeparator();
    }
    function approve(address spender, uint256 amount) public virtual returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }
    function transfer(address to, uint256 amount) public virtual returns (bool) {
        balanceOf[msg.sender] -= amount;
        unchecked {
            balanceOf[to] += amount;
        }
        emit Transfer(msg.sender, to, amount);
        return true;
    }
    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) public virtual returns (bool) {
        uint256 allowed = allowance[from][msg.sender]; 
        if (allowed != type(uint256).max) allowance[from][msg.sender] = allowed - amount;
        balanceOf[from] -= amount;
        unchecked {
            balanceOf[to] += amount;
        }
        emit Transfer(from, to, amount);
        return true;
    }
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public virtual {
        require(deadline >= block.timestamp, "PERMIT_DEADLINE_EXPIRED");
        unchecked {
            address recoveredAddress = ecrecover(
                keccak256(
                    abi.encodePacked(
                        "\x19\x01",
                        DOMAIN_SEPARATOR(),
                        keccak256(
                            abi.encode(
                                keccak256(
                                    "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
                                ),
                                owner,
                                spender,
                                value,
                                nonces[owner]++,
                                deadline
                            )
                        )
                    )
                ),
                v,
                r,
                s
            );
            require(recoveredAddress != address(0) && recoveredAddress == owner, "INVALID_SIGNER");
            allowance[recoveredAddress][spender] = value;
        }
        emit Approval(owner, spender, value);
    }
    function DOMAIN_SEPARATOR() public view virtual returns (bytes32) {
        return block.chainid == INITIAL_CHAIN_ID ? INITIAL_DOMAIN_SEPARATOR : computeDomainSeparator();
    }
    function computeDomainSeparator() internal view virtual returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                    keccak256(bytes(name)),
                    keccak256("1"),
                    block.chainid,
                    address(this)
                )
            );
    }
    function _mint(address to, uint256 amount) internal virtual {
        totalSupply += amount;
        unchecked {
            balanceOf[to] += amount;
        }
        emit Transfer(address(0), to, amount);
    }
    function _burn(address from, uint256 amount) internal virtual {
        balanceOf[from] -= amount;
        unchecked {
            totalSupply -= amount;
        }
        emit Transfer(from, address(0), amount);
    }
}
pragma solidity 0.8.17;
import {
    AllowListData,
    MintParams,
    PublicDrop,
    TokenGatedDropStage,
    TokenGatedMintParams,
    SignedMintValidationParams
} from "../lib/SeaDropStructs.sol";
import { SeaDropErrorsAndEvents } from "../lib/SeaDropErrorsAndEvents.sol";
interface ISeaDrop is SeaDropErrorsAndEvents {
    function mintPublic(
        address nftContract,
        address feeRecipient,
        address minterIfNotPayer,
        uint256 quantity
    ) external payable;
    function mintAllowList(
        address nftContract,
        address feeRecipient,
        address minterIfNotPayer,
        uint256 quantity,
        MintParams calldata mintParams,
        bytes32[] calldata proof
    ) external payable;
    function mintSigned(
        address nftContract,
        address feeRecipient,
        address minterIfNotPayer,
        uint256 quantity,
        MintParams calldata mintParams,
        uint256 salt,
        bytes calldata signature
    ) external payable;
    function mintAllowedTokenHolder(
        address nftContract,
        address feeRecipient,
        address minterIfNotPayer,
        TokenGatedMintParams calldata mintParams
    ) external payable;
    function getPublicDrop(address nftContract)
        external
        view
        returns (PublicDrop memory);
    function getCreatorPayoutAddress(address nftContract)
        external
        view
        returns (address);
    function getAllowListMerkleRoot(address nftContract)
        external
        view
        returns (bytes32);
    function getFeeRecipientIsAllowed(address nftContract, address feeRecipient)
        external
        view
        returns (bool);
    function getAllowedFeeRecipients(address nftContract)
        external
        view
        returns (address[] memory);
    function getSigners(address nftContract)
        external
        view
        returns (address[] memory);
    function getSignedMintValidationParams(address nftContract, address signer)
        external
        view
        returns (SignedMintValidationParams memory);
    function getPayers(address nftContract)
        external
        view
        returns (address[] memory);
    function getPayerIsAllowed(address nftContract, address payer)
        external
        view
        returns (bool);
    function getTokenGatedAllowedTokens(address nftContract)
        external
        view
        returns (address[] memory);
    function getTokenGatedDrop(address nftContract, address allowedNftToken)
        external
        view
        returns (TokenGatedDropStage memory);
    function getAllowedNftTokenIdIsRedeemed(
        address nftContract,
        address allowedNftToken,
        uint256 allowedNftTokenId
    ) external view returns (bool);
    function updateDropURI(string calldata dropURI) external;
    function updatePublicDrop(PublicDrop calldata publicDrop) external;
    function updateAllowList(AllowListData calldata allowListData) external;
    function updateTokenGatedDrop(
        address allowedNftToken,
        TokenGatedDropStage calldata dropStage
    ) external;
    function updateCreatorPayoutAddress(address payoutAddress) external;
    function updateAllowedFeeRecipient(address feeRecipient, bool allowed)
        external;
    function updateSignedMintValidationParams(
        address signer,
        SignedMintValidationParams calldata signedMintValidationParams
    ) external;
    function updatePayer(address payer, bool allowed) external;
}
pragma solidity 0.8.17;
interface ISeaDropTokenContractMetadata {
    event MaxSupplyUpdated(uint256 newMaxSupply);
    event ProvenanceHashUpdated(bytes32 previousHash, bytes32 newHash);
    event ContractURIUpdated(string newContractURI);
    event TokenURIUpdated(
        uint256 indexed startTokenId,
        uint256 indexed endTokenId
    );
    event BaseURIUpdated(string baseURI);
    function contractURI() external view returns (string memory);
    function setContractURI(string calldata newContractURI) external;
    function baseURI() external view returns (string memory);
    function setBaseURI(string calldata tokenURI) external;
    function maxSupply() external view returns (uint256);
    function setMaxSupply(uint256 newMaxSupply) external;
    function provenanceHash() external view returns (bytes32);
    function setProvenanceHash(bytes32 newProvenanceHash) external;
    error ProvenanceHashCannotBeSetAfterMintStarted();
}
pragma solidity ^0.8.0;
import "../../utils/introspection/IERC165.sol";
interface IERC721 is IERC165 {
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);
    function balanceOf(address owner) external view returns (uint256 balance);
    function ownerOf(uint256 tokenId) external view returns (address owner);
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes calldata data
    ) external;
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId
    ) external;
    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) external;
    function approve(address to, uint256 tokenId) external;
    function setApprovalForAll(address operator, bool _approved) external;
    function getApproved(uint256 tokenId) external view returns (address operator);
    function isApprovedForAll(address owner, address operator) external view returns (bool);
}
pragma solidity ^0.8.0;
import "./math/Math.sol";
library Strings {
    bytes16 private constant _SYMBOLS = "0123456789abcdef";
    uint8 private constant _ADDRESS_LENGTH = 20;
    function toString(uint256 value) internal pure returns (string memory) {
        unchecked {
            uint256 length = Math.log10(value) + 1;
            string memory buffer = new string(length);
            uint256 ptr;
            assembly {
                ptr := add(buffer, add(32, length))
            }
            while (true) {
                ptr--;
                assembly {
                    mstore8(ptr, byte(mod(value, 10), _SYMBOLS))
                }
                value /= 10;
                if (value == 0) break;
            }
            return buffer;
        }
    }
    function toHexString(uint256 value) internal pure returns (string memory) {
        unchecked {
            return toHexString(value, Math.log256(value) + 1);
        }
    }
    function toHexString(uint256 value, uint256 length) internal pure returns (string memory) {
        bytes memory buffer = new bytes(2 * length + 2);
        buffer[0] = "0";
        buffer[1] = "x";
        for (uint256 i = 2 * length + 1; i > 1; --i) {
            buffer[i] = _SYMBOLS[value & 0xf];
            value >>= 4;
        }
        require(value == 0, "Strings: hex length insufficient");
        return string(buffer);
    }
    function toHexString(address addr) internal pure returns (string memory) {
        return toHexString(uint256(uint160(addr)), _ADDRESS_LENGTH);
    }
}
pragma solidity ^0.8.0;
import "../Strings.sol";
library ECDSA {
    enum RecoverError {
        NoError,
        InvalidSignature,
        InvalidSignatureLength,
        InvalidSignatureS,
        InvalidSignatureV 
    }
    function _throwError(RecoverError error) private pure {
        if (error == RecoverError.NoError) {
            return; 
        } else if (error == RecoverError.InvalidSignature) {
            revert("ECDSA: invalid signature");
        } else if (error == RecoverError.InvalidSignatureLength) {
            revert("ECDSA: invalid signature length");
        } else if (error == RecoverError.InvalidSignatureS) {
            revert("ECDSA: invalid signature 's' value");
        }
    }
    function tryRecover(bytes32 hash, bytes memory signature) internal pure returns (address, RecoverError) {
        if (signature.length == 65) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            assembly {
                r := mload(add(signature, 0x20))
                s := mload(add(signature, 0x40))
                v := byte(0, mload(add(signature, 0x60)))
            }
            return tryRecover(hash, v, r, s);
        } else {
            return (address(0), RecoverError.InvalidSignatureLength);
        }
    }
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        (address recovered, RecoverError error) = tryRecover(hash, signature);
        _throwError(error);
        return recovered;
    }
    function tryRecover(
        bytes32 hash,
        bytes32 r,
        bytes32 vs
    ) internal pure returns (address, RecoverError) {
        bytes32 s = vs & bytes32(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
        uint8 v = uint8((uint256(vs) >> 255) + 27);
        return tryRecover(hash, v, r, s);
    }
    function recover(
        bytes32 hash,
        bytes32 r,
        bytes32 vs
    ) internal pure returns (address) {
        (address recovered, RecoverError error) = tryRecover(hash, r, vs);
        _throwError(error);
        return recovered;
    }
    function tryRecover(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (address, RecoverError) {
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return (address(0), RecoverError.InvalidSignatureS);
        }
        address signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) {
            return (address(0), RecoverError.InvalidSignature);
        }
        return (signer, RecoverError.NoError);
    }
    function recover(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (address) {
        (address recovered, RecoverError error) = tryRecover(hash, v, r, s);
        _throwError(error);
        return recovered;
    }
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }
    function toEthSignedMessageHash(bytes memory s) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(s.length), s));
    }
    function toTypedDataHash(bytes32 domainSeparator, bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}
pragma solidity >=0.8.0;
import {ERC20} from "../tokens/ERC20.sol";
library SafeTransferLib {
    function safeTransferETH(address to, uint256 amount) internal {
        bool success;
        assembly {
            success := call(gas(), to, amount, 0, 0, 0, 0)
        }
        require(success, "ETH_TRANSFER_FAILED");
    }
    function safeTransferFrom(
        ERC20 token,
        address from,
        address to,
        uint256 amount
    ) internal {
        bool success;
        assembly {
            let freeMemoryPointer := mload(0x40)
            mstore(freeMemoryPointer, 0x23b872dd00000000000000000000000000000000000000000000000000000000)
            mstore(add(freeMemoryPointer, 4), from) 
            mstore(add(freeMemoryPointer, 36), to) 
            mstore(add(freeMemoryPointer, 68), amount) 
            success := and(
                or(and(eq(mload(0), 1), gt(returndatasize(), 31)), iszero(returndatasize())),
                call(gas(), token, 0, freeMemoryPointer, 100, 0, 32)
            )
        }
        require(success, "TRANSFER_FROM_FAILED");
    }
    function safeTransfer(
        ERC20 token,
        address to,
        uint256 amount
    ) internal {
        bool success;
        assembly {
            let freeMemoryPointer := mload(0x40)
            mstore(freeMemoryPointer, 0xa9059cbb00000000000000000000000000000000000000000000000000000000)
            mstore(add(freeMemoryPointer, 4), to) 
            mstore(add(freeMemoryPointer, 36), amount) 
            success := and(
                or(and(eq(mload(0), 1), gt(returndatasize(), 31)), iszero(returndatasize())),
                call(gas(), token, 0, freeMemoryPointer, 68, 0, 32)
            )
        }
        require(success, "TRANSFER_FAILED");
    }
    function safeApprove(
        ERC20 token,
        address to,
        uint256 amount
    ) internal {
        bool success;
        assembly {
            let freeMemoryPointer := mload(0x40)
            mstore(freeMemoryPointer, 0x095ea7b300000000000000000000000000000000000000000000000000000000)
            mstore(add(freeMemoryPointer, 4), to) 
            mstore(add(freeMemoryPointer, 36), amount) 
            success := and(
                or(and(eq(mload(0), 1), gt(returndatasize(), 31)), iszero(returndatasize())),
                call(gas(), token, 0, freeMemoryPointer, 68, 0, 32)
            )
        }
        require(success, "APPROVE_FAILED");
    }
}
pragma solidity 0.8.17;
import { ISeaDrop } from "./interfaces/ISeaDrop.sol";
import {
    INonFungibleSeaDropToken
} from "./interfaces/INonFungibleSeaDropToken.sol";
import {
    AllowListData,
    MintParams,
    PublicDrop,
    TokenGatedDropStage,
    TokenGatedMintParams,
    SignedMintValidationParams
} from "./lib/SeaDropStructs.sol";
import { SafeTransferLib } from "solmate/utils/SafeTransferLib.sol";
import { ReentrancyGuard } from "solmate/utils/ReentrancyGuard.sol";
import {
    IERC721
} from "openzeppelin-contracts/contracts/token/ERC721/IERC721.sol";
import {
    IERC165
} from "openzeppelin-contracts/contracts/utils/introspection/IERC165.sol";
import {
    ECDSA
} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {
    MerkleProof
} from "openzeppelin-contracts/contracts/utils/cryptography/MerkleProof.sol";
contract SeaDrop is ISeaDrop, ReentrancyGuard {
    using ECDSA for bytes32;
    mapping(address => PublicDrop) private _publicDrops;
    mapping(address => address) private _creatorPayoutAddresses;
    mapping(address => bytes32) private _allowListMerkleRoots;
    mapping(address => mapping(address => bool)) private _allowedFeeRecipients;
    mapping(address => address[]) private _enumeratedFeeRecipients;
    mapping(address => mapping(address => SignedMintValidationParams))
        private _signedMintValidationParams;
    mapping(address => address[]) private _enumeratedSigners;
    mapping(bytes32 => bool) private _usedDigests;
    mapping(address => mapping(address => bool)) private _allowedPayers;
    mapping(address => address[]) private _enumeratedPayers;
    mapping(address => mapping(address => TokenGatedDropStage))
        private _tokenGatedDrops;
    mapping(address => address[]) private _enumeratedTokenGatedTokens;
    mapping(address => mapping(address => mapping(uint256 => bool)))
        private _tokenGatedRedeemed;
    bytes32 internal constant _SIGNED_MINT_TYPEHASH =
        keccak256(
             "SignedMint("
                "address nftContract,"
                "address minter,"
                "address feeRecipient,"
                "MintParams mintParams,"
                "uint256 salt"
            ")"
            "MintParams("
                "uint256 mintPrice,"
                "uint256 maxTotalMintableByWallet,"
                "uint256 startTime,"
                "uint256 endTime,"
                "uint256 dropStageIndex,"
                "uint256 maxTokenSupplyForStage,"
                "uint256 feeBps,"
                "bool restrictFeeRecipients"
            ")"
        );
    bytes32 internal constant _MINT_PARAMS_TYPEHASH =
        keccak256(
            "MintParams("
                "uint256 mintPrice,"
                "uint256 maxTotalMintableByWallet,"
                "uint256 startTime,"
                "uint256 endTime,"
                "uint256 dropStageIndex,"
                "uint256 maxTokenSupplyForStage,"
                "uint256 feeBps,"
                "bool restrictFeeRecipients"
            ")"
        );
    bytes32 internal constant _EIP_712_DOMAIN_TYPEHASH =
        keccak256(
            "EIP712Domain("
                "string name,"
                "string version,"
                "uint256 chainId,"
                "address verifyingContract"
            ")"
        );
    bytes32 internal constant _NAME_HASH = keccak256("SeaDrop");
    bytes32 internal constant _VERSION_HASH = keccak256("1.0");
    uint256 internal immutable _CHAIN_ID = block.chainid;
    bytes32 internal immutable _DOMAIN_SEPARATOR;
    uint256 internal constant _UNLIMITED_MAX_TOKEN_SUPPLY_FOR_STAGE =
        type(uint256).max;
    uint256 internal constant _PUBLIC_DROP_STAGE_INDEX = 0;
    modifier onlyINonFungibleSeaDropToken() virtual {
        if (
            !IERC165(msg.sender).supportsInterface(
                type(INonFungibleSeaDropToken).interfaceId
            )
        ) {
            revert OnlyINonFungibleSeaDropToken(msg.sender);
        }
        _;
    }
    constructor() {
        _DOMAIN_SEPARATOR = _deriveDomainSeparator();
    }
    function mintPublic(
        address nftContract,
        address feeRecipient,
        address minterIfNotPayer,
        uint256 quantity
    ) external payable override {
        PublicDrop memory publicDrop = _publicDrops[nftContract];
        _checkActive(publicDrop.startTime, publicDrop.endTime);
        uint256 mintPrice = publicDrop.mintPrice;
        _checkCorrectPayment(quantity, mintPrice);
        address minter = minterIfNotPayer != address(0)
            ? minterIfNotPayer
            : msg.sender;
        if (minter != msg.sender) {
            if (!_allowedPayers[nftContract][msg.sender]) {
                revert PayerNotAllowed();
            }
        }
        _checkMintQuantity(
            nftContract,
            minter,
            quantity,
            publicDrop.maxTotalMintableByWallet,
            _UNLIMITED_MAX_TOKEN_SUPPLY_FOR_STAGE
        );
        _checkFeeRecipientIsAllowed(
            nftContract,
            feeRecipient,
            publicDrop.restrictFeeRecipients
        );
        _mintAndPay(
            nftContract,
            minter,
            quantity,
            mintPrice,
            _PUBLIC_DROP_STAGE_INDEX,
            publicDrop.feeBps,
            feeRecipient
        );
    }
    function mintAllowList(
        address nftContract,
        address feeRecipient,
        address minterIfNotPayer,
        uint256 quantity,
        MintParams calldata mintParams,
        bytes32[] calldata proof
    ) external payable override {
        _checkActive(mintParams.startTime, mintParams.endTime);
        uint256 mintPrice = mintParams.mintPrice;
        _checkCorrectPayment(quantity, mintPrice);
        address minter = minterIfNotPayer != address(0)
            ? minterIfNotPayer
            : msg.sender;
        if (minter != msg.sender) {
            if (!_allowedPayers[nftContract][msg.sender]) {
                revert PayerNotAllowed();
            }
        }
        _checkMintQuantity(
            nftContract,
            minter,
            quantity,
            mintParams.maxTotalMintableByWallet,
            mintParams.maxTokenSupplyForStage
        );
        _checkFeeRecipientIsAllowed(
            nftContract,
            feeRecipient,
            mintParams.restrictFeeRecipients
        );
        if (
            !MerkleProof.verify(
                proof,
                _allowListMerkleRoots[nftContract],
                keccak256(abi.encode(minter, mintParams))
            )
        ) {
            revert InvalidProof();
        }
        _mintAndPay(
            nftContract,
            minter,
            quantity,
            mintPrice,
            mintParams.dropStageIndex,
            mintParams.feeBps,
            feeRecipient
        );
    }
    function mintSigned(
        address nftContract,
        address feeRecipient,
        address minterIfNotPayer,
        uint256 quantity,
        MintParams calldata mintParams,
        uint256 salt,
        bytes calldata signature
    ) external payable override {
        _checkActive(mintParams.startTime, mintParams.endTime);
        _checkCorrectPayment(quantity, mintParams.mintPrice);
        address minter = minterIfNotPayer != address(0)
            ? minterIfNotPayer
            : msg.sender;
        if (minter != msg.sender) {
            if (!_allowedPayers[nftContract][msg.sender]) {
                revert PayerNotAllowed();
            }
        }
        _checkMintQuantity(
            nftContract,
            minter,
            quantity,
            mintParams.maxTotalMintableByWallet,
            mintParams.maxTokenSupplyForStage
        );
        _checkFeeRecipientIsAllowed(
            nftContract,
            feeRecipient,
            mintParams.restrictFeeRecipients
        );
        {
            bytes32 digest = _getDigest(
                nftContract,
                minter,
                feeRecipient,
                mintParams,
                salt
            );
            if (_usedDigests[digest]) {
                revert SignatureAlreadyUsed();
            }
            _usedDigests[digest] = true;
            address recoveredAddress = digest.recover(signature);
            _validateSignerAndParams(nftContract, mintParams, recoveredAddress);
        }
        _mintAndPay(
            nftContract,
            minter,
            quantity,
            mintParams.mintPrice,
            mintParams.dropStageIndex,
            mintParams.feeBps,
            feeRecipient
        );
    }
    function _validateSignerAndParams(
        address nftContract,
        MintParams memory mintParams,
        address signer
    ) internal view {
        SignedMintValidationParams
            memory signedMintValidationParams = _signedMintValidationParams[
                nftContract
            ][signer];
        if (signedMintValidationParams.maxMaxTotalMintableByWallet == 0) {
            revert InvalidSignature(signer);
        }
        if (mintParams.mintPrice < signedMintValidationParams.minMintPrice) {
            revert InvalidSignedMintPrice(
                mintParams.mintPrice,
                signedMintValidationParams.minMintPrice
            );
        }
        if (
            mintParams.maxTotalMintableByWallet >
            signedMintValidationParams.maxMaxTotalMintableByWallet
        ) {
            revert InvalidSignedMaxTotalMintableByWallet(
                mintParams.maxTotalMintableByWallet,
                signedMintValidationParams.maxMaxTotalMintableByWallet
            );
        }
        if (mintParams.startTime < signedMintValidationParams.minStartTime) {
            revert InvalidSignedStartTime(
                mintParams.startTime,
                signedMintValidationParams.minStartTime
            );
        }
        if (mintParams.endTime > signedMintValidationParams.maxEndTime) {
            revert InvalidSignedEndTime(
                mintParams.endTime,
                signedMintValidationParams.maxEndTime
            );
        }
        if (
            mintParams.maxTokenSupplyForStage >
            signedMintValidationParams.maxMaxTokenSupplyForStage
        ) {
            revert InvalidSignedMaxTokenSupplyForStage(
                mintParams.maxTokenSupplyForStage,
                signedMintValidationParams.maxMaxTokenSupplyForStage
            );
        }
        if (mintParams.feeBps > signedMintValidationParams.maxFeeBps) {
            revert InvalidSignedFeeBps(
                mintParams.feeBps,
                signedMintValidationParams.maxFeeBps
            );
        }
        if (mintParams.feeBps < signedMintValidationParams.minFeeBps) {
            revert InvalidSignedFeeBps(
                mintParams.feeBps,
                signedMintValidationParams.minFeeBps
            );
        }
        if (!mintParams.restrictFeeRecipients) {
            revert SignedMintsMustRestrictFeeRecipients();
        }
    }
    function mintAllowedTokenHolder(
        address nftContract,
        address feeRecipient,
        address minterIfNotPayer,
        TokenGatedMintParams calldata mintParams
    ) external payable override {
        address minter = minterIfNotPayer != address(0)
            ? minterIfNotPayer
            : msg.sender;
        if (minter != msg.sender) {
            if (!_allowedPayers[nftContract][msg.sender]) {
                revert PayerNotAllowed();
            }
        }
        address allowedNftToken = mintParams.allowedNftToken;
        TokenGatedDropStage memory dropStage = _tokenGatedDrops[nftContract][
            allowedNftToken
        ];
        _checkActive(dropStage.startTime, dropStage.endTime);
        _checkFeeRecipientIsAllowed(
            nftContract,
            feeRecipient,
            dropStage.restrictFeeRecipients
        );
        uint256 mintQuantity = mintParams.allowedNftTokenIds.length;
        _checkCorrectPayment(mintQuantity, dropStage.mintPrice);
        _checkMintQuantity(
            nftContract,
            minter,
            mintQuantity,
            dropStage.maxTotalMintableByWallet,
            dropStage.maxTokenSupplyForStage
        );
        for (uint256 i = 0; i < mintQuantity; ) {
            uint256 tokenId = mintParams.allowedNftTokenIds[i];
            if (IERC721(allowedNftToken).ownerOf(tokenId) != minter) {
                revert TokenGatedNotTokenOwner(
                    nftContract,
                    allowedNftToken,
                    tokenId
                );
            }
            mapping(uint256 => bool)
                storage redeemedTokenIds = _tokenGatedRedeemed[nftContract][
                    allowedNftToken
                ];
            if (redeemedTokenIds[tokenId]) {
                revert TokenGatedTokenIdAlreadyRedeemed(
                    nftContract,
                    allowedNftToken,
                    tokenId
                );
            }
            redeemedTokenIds[tokenId] = true;
            unchecked {
                ++i;
            }
        }
        _mintAndPay(
            nftContract,
            minter,
            mintQuantity,
            dropStage.mintPrice,
            dropStage.dropStageIndex,
            dropStage.feeBps,
            feeRecipient
        );
    }
    function _checkActive(uint256 startTime, uint256 endTime) internal view {
        if (block.timestamp < startTime || block.timestamp > endTime) {
            revert NotActive(block.timestamp, startTime, endTime);
        }
    }
    function _checkFeeRecipientIsAllowed(
        address nftContract,
        address feeRecipient,
        bool restrictFeeRecipients
    ) internal view {
        if (feeRecipient == address(0)) {
            revert FeeRecipientCannotBeZeroAddress();
        }
        if (restrictFeeRecipients)
            if (!_allowedFeeRecipients[nftContract][feeRecipient]) {
                revert FeeRecipientNotAllowed();
            }
    }
    function _checkMintQuantity(
        address nftContract,
        address minter,
        uint256 quantity,
        uint256 maxTotalMintableByWallet,
        uint256 maxTokenSupplyForStage
    ) internal view {
        if (quantity == 0) {
            revert MintQuantityCannotBeZero();
        }
        (
            uint256 minterNumMinted,
            uint256 currentTotalSupply,
            uint256 maxSupply
        ) = INonFungibleSeaDropToken(nftContract).getMintStats(minter);
        if (quantity + minterNumMinted > maxTotalMintableByWallet) {
            revert MintQuantityExceedsMaxMintedPerWallet(
                quantity + minterNumMinted,
                maxTotalMintableByWallet
            );
        }
        if (quantity + currentTotalSupply > maxSupply) {
            revert MintQuantityExceedsMaxSupply(
                quantity + currentTotalSupply,
                maxSupply
            );
        }
        if (quantity + currentTotalSupply > maxTokenSupplyForStage) {
            revert MintQuantityExceedsMaxTokenSupplyForStage(
                quantity + currentTotalSupply,
                maxTokenSupplyForStage
            );
        }
    }
    function _checkCorrectPayment(uint256 quantity, uint256 mintPrice)
        internal
        view
    {
        if (msg.value != quantity * mintPrice) {
            revert IncorrectPayment(msg.value, quantity * mintPrice);
        }
    }
    function _splitPayout(
        address nftContract,
        address feeRecipient,
        uint256 feeBps
    ) internal {
        if (feeBps > 10_000) {
            revert InvalidFeeBps(feeBps);
        }
        address creatorPayoutAddress = _creatorPayoutAddresses[nftContract];
        if (creatorPayoutAddress == address(0)) {
            revert CreatorPayoutAddressCannotBeZeroAddress();
        }
        if (feeBps == 0) {
            SafeTransferLib.safeTransferETH(creatorPayoutAddress, msg.value);
            return;
        }
        uint256 feeAmount = (msg.value * feeBps) / 10_000;
        uint256 payoutAmount;
        unchecked {
            payoutAmount = msg.value - feeAmount;
        }
        if (feeAmount > 0) {
            SafeTransferLib.safeTransferETH(feeRecipient, feeAmount);
        }
        SafeTransferLib.safeTransferETH(creatorPayoutAddress, payoutAmount);
    }
    function _mintAndPay(
        address nftContract,
        address minter,
        uint256 quantity,
        uint256 mintPrice,
        uint256 dropStageIndex,
        uint256 feeBps,
        address feeRecipient
    ) internal nonReentrant {
        INonFungibleSeaDropToken(nftContract).mintSeaDrop(minter, quantity);
        if (mintPrice != 0) {
            _splitPayout(nftContract, feeRecipient, feeBps);
        }
        emit SeaDropMint(
            nftContract,
            minter,
            feeRecipient,
            msg.sender,
            quantity,
            mintPrice,
            feeBps,
            dropStageIndex
        );
    }
    function _domainSeparator() internal view returns (bytes32) {
        return block.chainid == _CHAIN_ID
            ? _DOMAIN_SEPARATOR
            : _deriveDomainSeparator();
    }
    function _deriveDomainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                _EIP_712_DOMAIN_TYPEHASH,
                _NAME_HASH,
                _VERSION_HASH,
                block.chainid,
                address(this)
            )
        );
    }
    function getPublicDrop(address nftContract)
        external
        view
        returns (PublicDrop memory)
    {
        return _publicDrops[nftContract];
    }
    function getCreatorPayoutAddress(address nftContract)
        external
        view
        returns (address)
    {
        return _creatorPayoutAddresses[nftContract];
    }
    function getAllowListMerkleRoot(address nftContract)
        external
        view
        returns (bytes32)
    {
        return _allowListMerkleRoots[nftContract];
    }
    function getFeeRecipientIsAllowed(address nftContract, address feeRecipient)
        external
        view
        returns (bool)
    {
        return _allowedFeeRecipients[nftContract][feeRecipient];
    }
    function getAllowedFeeRecipients(address nftContract)
        external
        view
        returns (address[] memory)
    {
        return _enumeratedFeeRecipients[nftContract];
    }
    function getSigners(address nftContract)
        external
        view
        returns (address[] memory)
    {
        return _enumeratedSigners[nftContract];
    }
    function getSignedMintValidationParams(address nftContract, address signer)
        external
        view
        returns (SignedMintValidationParams memory)
    {
        return _signedMintValidationParams[nftContract][signer];
    }
    function getPayers(address nftContract)
        external
        view
        returns (address[] memory)
    {
        return _enumeratedPayers[nftContract];
    }
    function getPayerIsAllowed(address nftContract, address payer)
        external
        view
        returns (bool)
    {
        return _allowedPayers[nftContract][payer];
    }
    function getTokenGatedAllowedTokens(address nftContract)
        external
        view
        returns (address[] memory)
    {
        return _enumeratedTokenGatedTokens[nftContract];
    }
    function getTokenGatedDrop(address nftContract, address allowedNftToken)
        external
        view
        returns (TokenGatedDropStage memory)
    {
        return _tokenGatedDrops[nftContract][allowedNftToken];
    }
    function getAllowedNftTokenIdIsRedeemed(
        address nftContract,
        address allowedNftToken,
        uint256 allowedNftTokenId
    ) external view returns (bool) {
        return
            _tokenGatedRedeemed[nftContract][allowedNftToken][
                allowedNftTokenId
            ];
    }
    function updateDropURI(string calldata dropURI)
        external
        onlyINonFungibleSeaDropToken
    {
        emit DropURIUpdated(msg.sender, dropURI);
    }
    function updatePublicDrop(PublicDrop calldata publicDrop)
        external
        override
        onlyINonFungibleSeaDropToken
    {
        if (publicDrop.feeBps > 10_000) {
            revert InvalidFeeBps(publicDrop.feeBps);
        }
        _publicDrops[msg.sender] = publicDrop;
        emit PublicDropUpdated(msg.sender, publicDrop);
    }
    function updateAllowList(AllowListData calldata allowListData)
        external
        override
        onlyINonFungibleSeaDropToken
    {
        bytes32 prevRoot = _allowListMerkleRoots[msg.sender];
        _allowListMerkleRoots[msg.sender] = allowListData.merkleRoot;
        emit AllowListUpdated(
            msg.sender,
            prevRoot,
            allowListData.merkleRoot,
            allowListData.publicKeyURIs,
            allowListData.allowListURI
        );
    }
    function updateTokenGatedDrop(
        address allowedNftToken,
        TokenGatedDropStage calldata dropStage
    ) external override onlyINonFungibleSeaDropToken {
        if (allowedNftToken == address(0)) {
            revert TokenGatedDropAllowedNftTokenCannotBeZeroAddress();
        }
        if (allowedNftToken == msg.sender) {
            revert TokenGatedDropAllowedNftTokenCannotBeDropToken();
        }
        if (dropStage.feeBps > 10_000) {
            revert InvalidFeeBps(dropStage.feeBps);
        }
        bool addOrUpdateDropStage = dropStage.maxTotalMintableByWallet != 0;
        TokenGatedDropStage storage existingDropStageData = _tokenGatedDrops[
            msg.sender
        ][allowedNftToken];
        address[] storage enumeratedTokens = _enumeratedTokenGatedTokens[
            msg.sender
        ];
        bool dropStageDoesNotExist;
        assembly {
            dropStageDoesNotExist := iszero(sload(existingDropStageData.slot))
        }
        if (addOrUpdateDropStage) {
            _tokenGatedDrops[msg.sender][allowedNftToken] = dropStage;
            if (dropStageDoesNotExist) {
                enumeratedTokens.push(allowedNftToken);
            }
        } else {
            if (dropStageDoesNotExist) {
                revert TokenGatedDropStageNotPresent();
            }
            delete _tokenGatedDrops[msg.sender][allowedNftToken];
            _removeFromEnumeration(allowedNftToken, enumeratedTokens);
        }
        emit TokenGatedDropStageUpdated(msg.sender, allowedNftToken, dropStage);
    }
    function updateCreatorPayoutAddress(address _payoutAddress)
        external
        onlyINonFungibleSeaDropToken
    {
        if (_payoutAddress == address(0)) {
            revert CreatorPayoutAddressCannotBeZeroAddress();
        }
        _creatorPayoutAddresses[msg.sender] = _payoutAddress;
        emit CreatorPayoutAddressUpdated(msg.sender, _payoutAddress);
    }
    function updateAllowedFeeRecipient(address feeRecipient, bool allowed)
        external
        onlyINonFungibleSeaDropToken
    {
        if (feeRecipient == address(0)) {
            revert FeeRecipientCannotBeZeroAddress();
        }
        address[] storage enumeratedStorage = _enumeratedFeeRecipients[
            msg.sender
        ];
        mapping(address => bool)
            storage feeRecipientsMap = _allowedFeeRecipients[msg.sender];
        if (allowed) {
            if (feeRecipientsMap[feeRecipient]) {
                revert DuplicateFeeRecipient();
            }
            feeRecipientsMap[feeRecipient] = true;
            enumeratedStorage.push(feeRecipient);
        } else {
            if (!feeRecipientsMap[feeRecipient]) {
                revert FeeRecipientNotPresent();
            }
            delete _allowedFeeRecipients[msg.sender][feeRecipient];
            _removeFromEnumeration(feeRecipient, enumeratedStorage);
        }
        emit AllowedFeeRecipientUpdated(msg.sender, feeRecipient, allowed);
    }
    function updateSignedMintValidationParams(
        address signer,
        SignedMintValidationParams calldata signedMintValidationParams
    ) external onlyINonFungibleSeaDropToken {
        if (signer == address(0)) {
            revert SignerCannotBeZeroAddress();
        }
        if (signedMintValidationParams.minFeeBps > 10_000) {
            revert InvalidFeeBps(signedMintValidationParams.minFeeBps);
        }
        if (signedMintValidationParams.maxFeeBps > 10_000) {
            revert InvalidFeeBps(signedMintValidationParams.maxFeeBps);
        }
        address[] storage enumeratedStorage = _enumeratedSigners[msg.sender];
        mapping(address => SignedMintValidationParams)
            storage signedMintValidationParamsMap = _signedMintValidationParams[
                msg.sender
            ];
        SignedMintValidationParams
            storage existingSignedMintValidationParams = signedMintValidationParamsMap[
                signer
            ];
        bool signedMintValidationParamsDoNotExist;
        assembly {
            signedMintValidationParamsDoNotExist := iszero(
                sload(existingSignedMintValidationParams.slot)
            )
        }
        bool addOrUpdate = signedMintValidationParams
            .maxMaxTotalMintableByWallet > 0;
        if (addOrUpdate) {
            signedMintValidationParamsMap[signer] = signedMintValidationParams;
            if (signedMintValidationParamsDoNotExist) {
                enumeratedStorage.push(signer);
            }
        } else {
            if (
                existingSignedMintValidationParams
                    .maxMaxTotalMintableByWallet == 0
            ) {
                revert SignerNotPresent();
            }
            delete _signedMintValidationParams[msg.sender][signer];
            _removeFromEnumeration(signer, enumeratedStorage);
        }
        emit SignedMintValidationParamsUpdated(
            msg.sender,
            signer,
            signedMintValidationParams
        );
    }
    function updatePayer(address payer, bool allowed)
        external
        onlyINonFungibleSeaDropToken
    {
        if (payer == address(0)) {
            revert PayerCannotBeZeroAddress();
        }
        address[] storage enumeratedStorage = _enumeratedPayers[msg.sender];
        mapping(address => bool) storage payersMap = _allowedPayers[msg.sender];
        if (allowed) {
            if (payersMap[payer]) {
                revert DuplicatePayer();
            }
            payersMap[payer] = true;
            enumeratedStorage.push(payer);
        } else {
            if (!payersMap[payer]) {
                revert PayerNotPresent();
            }
            delete _allowedPayers[msg.sender][payer];
            _removeFromEnumeration(payer, enumeratedStorage);
        }
        emit PayerUpdated(msg.sender, payer, allowed);
    }
    function _removeFromEnumeration(
        address toRemove,
        address[] storage enumeration
    ) internal {
        uint256 enumerationLength = enumeration.length;
        for (uint256 i = 0; i < enumerationLength; ) {
            if (enumeration[i] == toRemove) {
                enumeration[i] = enumeration[enumerationLength - 1];
                enumeration.pop();
                break;
            }
            unchecked {
                ++i;
            }
        }
    }
    function _getDigest(
        address nftContract,
        address minter,
        address feeRecipient,
        MintParams memory mintParams,
        uint256 salt
    ) internal view returns (bytes32 digest) {
        bytes32 mintParamsHashStruct = keccak256(
            abi.encode(
                _MINT_PARAMS_TYPEHASH,
                mintParams.mintPrice,
                mintParams.maxTotalMintableByWallet,
                mintParams.startTime,
                mintParams.endTime,
                mintParams.dropStageIndex,
                mintParams.maxTokenSupplyForStage,
                mintParams.feeBps,
                mintParams.restrictFeeRecipients
            )
        );
        digest = keccak256(
            bytes.concat(
                bytes2(0x1901),
                _domainSeparator(),
                keccak256(
                    abi.encode(
                        _SIGNED_MINT_TYPEHASH,
                        nftContract,
                        minter,
                        feeRecipient,
                        mintParamsHashStruct,
                        salt
                    )
                )
            )
        );
    }
}
pragma solidity ^0.8.0;
library Math {
    enum Rounding {
        Down, 
        Up, 
        Zero 
    }
    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
    function average(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a & b) + (a ^ b) / 2;
    }
    function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        return a == 0 ? 0 : (a - 1) / b + 1;
    }
    function mulDiv(
        uint256 x,
        uint256 y,
        uint256 denominator
    ) internal pure returns (uint256 result) {
        unchecked {
            uint256 prod0; 
            uint256 prod1; 
            assembly {
                let mm := mulmod(x, y, not(0))
                prod0 := mul(x, y)
                prod1 := sub(sub(mm, prod0), lt(mm, prod0))
            }
            if (prod1 == 0) {
                return prod0 / denominator;
            }
            require(denominator > prod1);
            uint256 remainder;
            assembly {
                remainder := mulmod(x, y, denominator)
                prod1 := sub(prod1, gt(remainder, prod0))
                prod0 := sub(prod0, remainder)
            }
            uint256 twos = denominator & (~denominator + 1);
            assembly {
                denominator := div(denominator, twos)
                prod0 := div(prod0, twos)
                twos := add(div(sub(0, twos), twos), 1)
            }
            prod0 |= prod1 * twos;
            uint256 inverse = (3 * denominator) ^ 2;
            inverse *= 2 - denominator * inverse; 
            inverse *= 2 - denominator * inverse; 
            inverse *= 2 - denominator * inverse; 
            inverse *= 2 - denominator * inverse; 
            inverse *= 2 - denominator * inverse; 
            inverse *= 2 - denominator * inverse; 
            result = prod0 * inverse;
            return result;
        }
    }
    function mulDiv(
        uint256 x,
        uint256 y,
        uint256 denominator,
        Rounding rounding
    ) internal pure returns (uint256) {
        uint256 result = mulDiv(x, y, denominator);
        if (rounding == Rounding.Up && mulmod(x, y, denominator) > 0) {
            result += 1;
        }
        return result;
    }
    function sqrt(uint256 a) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }
        uint256 result = 1 << (log2(a) >> 1);
        unchecked {
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            return min(result, a / result);
        }
    }
    function sqrt(uint256 a, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = sqrt(a);
            return result + (rounding == Rounding.Up && result * result < a ? 1 : 0);
        }
    }
    function log2(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >> 128 > 0) {
                value >>= 128;
                result += 128;
            }
            if (value >> 64 > 0) {
                value >>= 64;
                result += 64;
            }
            if (value >> 32 > 0) {
                value >>= 32;
                result += 32;
            }
            if (value >> 16 > 0) {
                value >>= 16;
                result += 16;
            }
            if (value >> 8 > 0) {
                value >>= 8;
                result += 8;
            }
            if (value >> 4 > 0) {
                value >>= 4;
                result += 4;
            }
            if (value >> 2 > 0) {
                value >>= 2;
                result += 2;
            }
            if (value >> 1 > 0) {
                result += 1;
            }
        }
        return result;
    }
    function log2(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log2(value);
            return result + (rounding == Rounding.Up && 1 << result < value ? 1 : 0);
        }
    }
    function log10(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >= 10**64) {
                value /= 10**64;
                result += 64;
            }
            if (value >= 10**32) {
                value /= 10**32;
                result += 32;
            }
            if (value >= 10**16) {
                value /= 10**16;
                result += 16;
            }
            if (value >= 10**8) {
                value /= 10**8;
                result += 8;
            }
            if (value >= 10**4) {
                value /= 10**4;
                result += 4;
            }
            if (value >= 10**2) {
                value /= 10**2;
                result += 2;
            }
            if (value >= 10**1) {
                result += 1;
            }
        }
        return result;
    }
    function log10(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log10(value);
            return result + (rounding == Rounding.Up && 10**result < value ? 1 : 0);
        }
    }
    function log256(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >> 128 > 0) {
                value >>= 128;
                result += 16;
            }
            if (value >> 64 > 0) {
                value >>= 64;
                result += 8;
            }
            if (value >> 32 > 0) {
                value >>= 32;
                result += 4;
            }
            if (value >> 16 > 0) {
                value >>= 16;
                result += 2;
            }
            if (value >> 8 > 0) {
                result += 1;
            }
        }
        return result;
    }
    function log256(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log256(value);
            return result + (rounding == Rounding.Up && 1 << (result * 8) < value ? 1 : 0);
        }
    }
}
pragma solidity 0.8.17;
struct PublicDrop {
    uint80 mintPrice; 
    uint48 startTime; 
    uint48 endTime; 
    uint16 maxTotalMintableByWallet; 
    uint16 feeBps; 
    bool restrictFeeRecipients; 
}
struct TokenGatedDropStage {
    uint80 mintPrice; 
    uint16 maxTotalMintableByWallet; 
    uint48 startTime; 
    uint48 endTime; 
    uint8 dropStageIndex; 
    uint32 maxTokenSupplyForStage; 
    uint16 feeBps; 
    bool restrictFeeRecipients; 
}
struct MintParams {
    uint256 mintPrice; 
    uint256 maxTotalMintableByWallet;
    uint256 startTime;
    uint256 endTime;
    uint256 dropStageIndex; 
    uint256 maxTokenSupplyForStage;
    uint256 feeBps;
    bool restrictFeeRecipients;
}
struct TokenGatedMintParams {
    address allowedNftToken;
    uint256[] allowedNftTokenIds;
}
struct AllowListData {
    bytes32 merkleRoot;
    string[] publicKeyURIs;
    string allowListURI;
}
struct SignedMintValidationParams {
    uint80 minMintPrice; 
    uint24 maxMaxTotalMintableByWallet; 
    uint40 minStartTime; 
    uint40 maxEndTime; 
    uint40 maxMaxTokenSupplyForStage; 
    uint16 minFeeBps; 
    uint16 maxFeeBps; 
}
