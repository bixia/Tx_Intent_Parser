
pragma solidity ^0.8.25;
import {IERC2981} from "openzeppelin/contracts/interfaces/IERC2981.sol";
import {IERC4907} from "./IERC4907.sol";
import {IERC5192} from "./IERC5192.sol";
import {IERC7496} from "./IERC7496.sol";
import {IERC7572} from "./IERC7572.sol";
import {IN2MCommonStorage} from "./IN2MCommonStorage.sol";
interface IN2MCommon is IN2MCommonStorage, IERC2981, IERC4907, IERC5192, IERC7496, IERC7572 {
    event AffiliateSell(address indexed affiliate);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event BatchMetadataUpdate(uint256 fromTokenId, uint256 toTokenId);
    event ImmutableTrait(bytes32 indexed traitKey, uint256 indexed tokenId, bytes32 value);
    error InvalidInputSizesDontMatch();
    error InvalidTokenId();
    error InvalidAmount();
    error CollectionSoldOut();
    error PresaleNotOpen();
    error PublicSaleNotOpen();
    error SaleFinished();
    error NotEnoughAmountToMint();
    error InvalidMintFee();
    error InvadlidCollectionSize();
    error NonTransferrableSoulboundNFT();
    error InvalidRevenuePercentage();
    error WaitUntilDropDate();
    error PresaleInvalidMintingType();
    error MetadataAlreadyFixed();
    error InvalidMintingType();
    error MaxPerAddressExceeded();
    error SignatureMismatch();
    error InvalidSignature();
    error ReentrancyGuard();
    error NewBaseURICantBeEmpty();    
    error InvalidPercentageOrDiscountValues();
    error CantLowerCurrentPercentages();
    error InvalidPhaseWithoutDate();
    error PendingAffiliatesBalance();
    error OperatorNotAllowed(address operator);
    error NotAllowlisted();
    error InvalidInitialization();
    error OnlyOnceTrait();
    error NonEditableTraitByTokenOwner();
    error OwnableUnauthorizedAccount(address account);
    error PlacerholderCantFreezeMetadata();
    error ApprovalCallerNotOwnerNorApproved();
    error ApprovalQueryForNonexistentToken();
    error BalanceQueryForZeroAddress();
    error MintToZeroAddress();
    error MintZeroQuantity();
    error OwnerQueryForNonexistentToken();
    error TransferCallerNotOwnerNorApproved();
    error TransferFromIncorrectOwner();
    error TransferToNonERC721ReceiverImplementer();
    error TransferToZeroAddress();
    error TransferFromFailed();
    function initialize008joDSK
    (
        string calldata name,
        string calldata symbol,
        uint256 mintPrice,
        bytes32 baseURIorPlaceholderCIDHash,
        bytes32 packedData,
        bytes calldata extraCollectionInformation
    ) external payable;
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function mintWhitelist(
        bytes32 toWihtExtra,
        uint256 customFee,
        bytes calldata signature,
        uint256[] calldata tokenIds) payable external;
    function merkleRoot() external view returns (bytes32);
    function setMerkleRoot(bytes32 merkleRoot_) external payable;
    function allowListed(address _wallet, bytes32[] calldata _proof) external view returns (bool);
    function mintAllowlist(uint256 amount, bytes32[] calldata _proof) external payable;
    function mintFee(uint256 amount) external view returns (uint256);
    function protocolFee() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function burnedTokens() external view returns (uint256);
    function maxPerAddress() external view returns (uint256);
    function isMetadataFixed() external view returns (bool);
    function setBaseURI(string memory baseURIString, bytes32 baseURICIDHash, bool isPlaceholder, bool freezeMetadata) external payable;
    function changeMintFee(uint256 newMintFee, bool isDynamic) external payable;
    function contractURI() external view returns (string calldata);
    function setContractURI(bytes32 newContractURIMetadataCIDHash) external payable;
    function setAffiliatesPercentageAndDiscount(uint16 userDiscount, uint16 affiliatePercentage, address affiliateAddress) external;
    function affiliateWithdraw(address affiliate) external payable;
    function withdrawERC20(address erc20Address) external payable;
    function withdraw() external payable;
    function setPhase(SalePhase newPhase) external payable;
    function setDropAndEndDate(uint256 dropDateTimestamp, uint256 endDateTimestamp) external payable;
    function setMaxPerAddress(uint16 newMaxPerAddress) external payable;
    function isOperatorFilterRegistryEnabled() external view returns (bool);
    function whitelistOperators(address[] calldata operators) external payable;
    function disableOperatorFilterRegistry() external payable;
    function reserveTokens(uint16 amount) external payable;
    function unreserveTokens(uint16 amount) external payable;
    function reservedTokens() external view returns (uint256);
    function collectionSize() external view returns (uint256);
    function affiliatesInfo(address affiliate) external view returns (bool enabled, uint16 affiliatePercentage, uint16 userDiscount);
    function changeRoyaltyFee(uint16 newFee) external payable;
    function royaltyFee() external view returns (uint256);
    function changeERC20PaymentAddress(address newErc20PaymentAddress) external payable;
    function currentPhase() external view returns (SalePhase);
    function mintingType() external view returns (MintingType);
    function saleDates() external view returns (uint256 dropDateTimestamp, uint256 endDateTimestamp);
    function isOpen() external view returns (bool);
    function ownershipTransferred(address from, address to) external payable;
    function ownerMaxRevenue() external view returns (uint256);
    function removeProtocolFee(bytes calldata signature, uint256 fee, address feeReceiver) external payable;
    function setTraitsPermissions(bytes32[] calldata ownerCanUpdateTraitKeys, bytes32[] calldata notOnlyOnceTraitKeys) external payable;
    function setTraitMetadataURI(string calldata uri) external payable;
    function withdrawnAmount() external view returns (uint256);
    function pendingTotalAffiliatesBalance() external view returns (uint256);
    function erc20PaymentAddress() external view returns (address);
    function owner() external view returns (address collectionOwner);
    function transferOwnership(address to) external payable;
    function reduceCollectionSize(uint32 newCollectionSize) external payable;
}
pragma solidity ^0.8.25;
interface DynamicPrice {
    function initMintPrice(bytes calldata initData) external payable;
    function mintPrice(address minter, uint256 amount) external view returns (uint256);
}
pragma solidity ^0.8.25;
import "./IN2MCommon.sol";
interface IN2MSequential is IN2MCommon {
    function mint() external payable;
    function mintEfficientN2M_001Z5BWH() external payable;
    function mint(uint256 amount) external payable;
    function mint(uint256 amount, address affiliate) external payable;
    function mintTo(address to, uint256 amount) external payable;
    function mintTo(address to, uint256 amount, address affiliate) external payable;
    function airdropSequential(bytes32[] calldata toAndAmount, bool soulbound) external payable;
}
pragma solidity ^0.8.25;
import "./important/README.sol";
abstract contract N2MVersion is Readme {
    function n2mVersion() virtual external pure returns (uint256) {
        return 2030;
    }
}
pragma solidity ^0.8.20;
interface IERC165 {
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}
pragma solidity ^0.8.25;
import {IERC20} from "openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IN2MCrossFactory} from "./interfaces/IN2MCrossFactory.sol";
import {N2MCommonStorage, IN2MCommonStorage, DynamicNFT} from "./Storage.sol";
import {DynamicPrice} from "./interfaces/DynamicPrice.sol";
import {IN2MCommon, IERC4907, IERC5192, IERC7496} from "./interfaces/IN2MCommon.sol";
import {LibString} from "solady/utils/LibString.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {MerkleProofLib} from "solady/utils/MerkleProofLib.sol";
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
abstract contract Common is IN2MCommon, N2MCommonStorage {
    constructor(address payable factoryAddress_, uint256 protocolFee_) N2MCommonStorage(factoryAddress_, protocolFee_) {
        _currentPhase = SalePhase.CLOSED;
    }
    modifier initializer() {
        uint256 packedData;
        assembly {
            packedData := sload(_availableCollectionSize.slot)
        }        
        if (packedData > 0) {
            _revert(InvalidInitialization.selector);
        }
        _;
    }
    modifier onlyOwner() {
        _checkOwner();
        _;
    }
    function _checkOwner() internal view virtual {
        if (msg.sender != FACTORY) {
            if (owner() != msg.sender) {
                revert OwnableUnauthorizedAccount(msg.sender);
            }
        }
    }
    function owner() public view override returns (address collectionOwner) {
        return IN2MCrossFactory(FACTORY).ownerOf(uint256(uint160(address(this))));
    }
    function transferOwnership(address to) external payable override onlyOwner {
        IN2MCrossFactory(FACTORY).transferCollectionOwnership(to);
    }
    function ownershipTransferred(address from, address to) external payable {
        if (msg.sender != FACTORY) revert();
        emit OwnershipTransferred(from, to);
    }
    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }
    function _nonReentrantBefore() private {
        if (_reentrancyStatus == REENTRANCY_ENTERED) {
            _revert(ReentrancyGuard.selector);
        }
        _reentrancyStatus = REENTRANCY_ENTERED;
    }
    function _nonReentrantAfter() private {
        _reentrancyStatus = REENTRANCY_NOT_ENTERED;
    }
    function _checkAuthorized(address owner, address spender, uint256 tokenId) internal view virtual;
    function _ownerOf(uint256 tokenId) internal view virtual returns (address);
    function _requireTokenOwned(uint256 tokenId) internal view virtual;
    function _setSoulbound(uint256 tokenId) internal {
        _soulbound[tokenId] = true;
        emit Locked(tokenId);
    }
    function locked(uint256 tokenId) external view override returns (bool) {
        _requireTokenOwned(tokenId);
        return (_soulbound[tokenId] || _soulboundCollection);
    }
    function totalSupply() public virtual view returns (uint256) {
        return _actualSoldTokens() - uint256(_burnedTokens);
    }
    function burnedTokens() external view returns (uint256) {
        return uint256(_burnedTokens);
    }
    function collectionSize() external view override returns (uint256 size) {
        size = _actualCollectionSize();
        if (size == type(uint32).max) {
            return 0;
        } else {
            return size - _burnedTokens;
        }
    }
    function _actualCollectionSize() internal view returns (uint256) {
        return uint256(_availableCollectionSize) + uint256(_reservedTokens);
    }
    function maxPerAddress() external view override returns (uint256) {
        return _maxPerAddress;
    }
    function _revert(bytes4 errorSelector) internal pure {
        assembly {
            mstore(0x00, errorSelector)
            revert(0x00, 0x04)
        }
    }
    function _getIPFSURI(bytes32 CIDHash) internal view returns (string memory) {
        return IN2MCrossFactory(FACTORY).getIPFSURI(CIDHash);
    }
    function mintingType() external virtual view returns (MintingType) {
        return _mintingType;        
    }
    function _reduceCollectionSize(uint32 newAvailableCollectionSize) internal {
        if (newAvailableCollectionSize == 0 || newAvailableCollectionSize >= _availableCollectionSize || newAvailableCollectionSize < _actualSoldTokens()) _revert(InvadlidCollectionSize.selector);
        _availableCollectionSize = newAvailableCollectionSize;
    }
    function reserveTokens(uint16 amount) external payable override onlyOwner {
        if ((uint256(amount) + _actualSoldTokens()) > uint256(_availableCollectionSize)) _revert(InvalidAmount.selector);
        if ((uint256(amount) + _reservedTokens) > type(uint16).max) _revert(InvalidAmount.selector);
        _reservedTokens += amount;
        _availableCollectionSize -= amount;
    }
    function unreserveTokens(uint16 amount) external payable override onlyOwner {
        if (amount > _reservedTokens) _revert(InvalidAmount.selector);
        _reservedTokens -= amount;
        _availableCollectionSize += amount;
    }
    function reservedTokens() external view override returns (uint256) {
        return _reservedTokens;
    }
    function _actualSoldTokens() internal view virtual returns (uint32);
    function _nextTokenId() internal view virtual returns (uint32);
    function merkleRoot() external view override returns (bytes32) {
        return _merkleRoot;
    }
    function setMerkleRoot(bytes32 merkleRoot_) external payable override onlyOwner {
        _merkleRoot = merkleRoot_;
    }
    function allowListed(address _wallet, bytes32[] calldata _proof)
      public
      view
      override
      returns (bool)
    {
      return
          MerkleProofLib.verify(
              _proof,
              _merkleRoot,
              keccak256(abi.encodePacked(_wallet))
          );
    }
    function mintFee(uint256 amount) external view override returns (uint256) {
        return _creatorMintFee(amount);
    }
    function protocolFee() public view override returns (uint256) {
        if (_feesRemoved) return 0;
        return PROTOCOL_FEE;
    }
    function _protocolFee() internal view returns (uint256) {
        return PROTOCOL_FEE;
    }
    function _creatorMintFee() internal view returns (uint256) {
        if (!_hasDynamicPrice) {
            return _mintPrice;
        }
        return DynamicPrice(address(this)).mintPrice(msg.sender, 1);
    }
    function _creatorMintFee(uint256 amount) internal view returns (uint256) {
        if (!_hasDynamicPrice) {
            return _mintPrice * amount;
        }
        return DynamicPrice(address(this)).mintPrice(msg.sender, amount);
    }
    function changeMintFee(uint256 newMintPrice, bool isDynamic) external payable override onlyOwner {
        _mintPrice = newMintPrice;
        if (isDynamic != _hasDynamicPrice) _hasDynamicPrice = isDynamic;
    }
    function _requirePaymentWithAffiliates(uint256 amount, address affiliate) internal {
        uint256 currentUserDiscount;
        uint256 currentAffiliatePercentage;
        if (_affiliatesInfo[affiliate].enabled) {
            currentUserDiscount = _affiliatesInfo[affiliate].userDiscount;
            currentAffiliatePercentage = _affiliatesInfo[affiliate].affiliatePercentage;
        } else {
            currentUserDiscount = _affiliatesInfo[address(0)].userDiscount;
            currentAffiliatePercentage = _affiliatesInfo[address(0)].affiliatePercentage;
        }
        uint256 discountTotalMintPrice = ((100_00 - currentUserDiscount) * _creatorMintFee(amount)) / 100_00;
        _requireFeesPayment(discountTotalMintPrice, _protocolFee()*amount);
        if (affiliate != address(0)) {
            uint256 affiliateAmount = (currentAffiliatePercentage * discountTotalMintPrice) / 100_00;
            _pendingTotalAffiliatesBalance += affiliateAmount;
            pendingAffiliateBalance[affiliate] += affiliateAmount;
            emit AffiliateSell(affiliate);
        }
    }
    function removeProtocolFee(bytes calldata signature, uint256 fee, address feeReceiver) external payable override {
        address signer = ECDSA.recoverCalldata(
            ECDSA.toEthSignedMessageHash(
                keccak256(
                    abi.encodePacked(
                        this.removeProtocolFee.selector,                       
                        fee,                                                 
                        feeReceiver,                                         
                        address(this),                                         
                        block.chainid                                          
                    )
                )
            ),
            signature
        );
        if (signer != N2M_SIGNER) _revert(SignatureMismatch.selector);
        _feesRemoved = true;
        if (fee > 0) {
            if (msg.value < fee) _revert(InvalidAmount.selector);
            bool success;
            assembly {
                success := call(gas(), feeReceiver, fee, 0, 0, 0, 0)
            }
            if (success == false) revert();
        }
    }
    function _requireFee(uint256 amount) internal {
        _requireFeesPayment(_creatorMintFee(amount), _protocolFee()*amount);
    }
    function _requireFeesPayment(uint256 creatorMintFee, uint256 n2mFee) internal {
        uint256 pendingMsgValue = msg.value;
        if (creatorMintFee > 0) {
            if (_isERC20Payment == false) {
                if (pendingMsgValue < creatorMintFee) revert InvalidMintFee();
                pendingMsgValue -= creatorMintFee;
            } else {
                SafeTransferLib.safeTransferFrom(
                    _erc20PaymentAddress,
                    msg.sender,
                    address(this),
                    creatorMintFee
                );
            }
        }
        if (_feesRemoved == false) {
            if (pendingMsgValue < n2mFee) revert InvalidMintFee();
            bool success;
            assembly {
                success := call(gas(), PROTOCOL_FEE_RECIPIENT, pendingMsgValue, 0, 0, 0, 0)
            }
            if (success == false) revert InvalidMintFee();
        }
    }
    function changeERC20PaymentAddress(address newErc20PaymentAddress) external payable override onlyOwner {
        if (_pendingTotalAffiliatesBalance > 0) _revert(PendingAffiliatesBalance.selector);
        _erc20PaymentAddress = newErc20PaymentAddress;
        _isERC20Payment = (newErc20PaymentAddress != address(0));
    }
    function _erc20Transfer(address erc20Address, address to, uint256 amount) internal {
        IERC20(erc20Address).transfer(to, amount);
    }
    function withdrawERC20(address erc20Address)
        external
        payable
        override
        nonReentrant
        onlyOwner
    {
        uint256 availableBalance = SafeTransferLib.balanceOf(erc20Address, address(this));
        if (availableBalance == 0) return;
        if (_erc20PaymentAddress == erc20Address) {
            if (_pendingTotalAffiliatesBalance >= availableBalance) return;
            unchecked {
                availableBalance -= _pendingTotalAffiliatesBalance;
            }
        }
        uint256 withdrawn;
        uint256 amountToSend;
        uint256 revenuePercentageTotal;
        uint256 revenueAddressesLength = _revenueInfo.length;
        for (uint256 i; i < revenueAddressesLength; i++) {
            uint256 iPercentage = _revenueInfo[i].percentage;
            revenuePercentageTotal += iPercentage;
            amountToSend = ((availableBalance * iPercentage) / 100_00);
            try IERC20(erc20Address).transfer(_revenueInfo[i].to, amountToSend) {
                withdrawn += amountToSend;
            } catch {
            }
        }
        _erc20Transfer(erc20Address, owner(), (availableBalance - withdrawn));
        withdrawnERC20Amount[erc20Address] += availableBalance;
    }
    function withdraw() external payable override nonReentrant onlyOwner {
        uint256 availableBalance = address(this).balance;
        if (_erc20PaymentAddress == address(0)) {
            if (_pendingTotalAffiliatesBalance >= availableBalance) return;
            unchecked {
                availableBalance -= _pendingTotalAffiliatesBalance;
            }
        }
        uint256 withdrawn;
        bool success;
        uint256 amountToSend;
        uint256 revenuePercentageTotal;
        uint256 revenueAddressesLength = _revenueInfo.length;
        for (uint256 i; i < revenueAddressesLength; i++) {
            uint256 iPercentage = _revenueInfo[i].percentage;
            revenuePercentageTotal += iPercentage;
            amountToSend = ((availableBalance * iPercentage) / 100_00);
            if (_revenueInfo[i].to != address(0)) {
                address revenueReceiver = _revenueInfo[i].to;
                assembly {
                    success := call(gas(), revenueReceiver, amountToSend, 0, 0, 0, 0)
                }
                if (success) {
                    withdrawn += amountToSend;
                }
            }
        }
        address contractOwner = owner();
        amountToSend = (availableBalance - withdrawn);
        assembly {
            success := call(gas(), contractOwner, amountToSend, 0, 0, 0, 0)
        }
        if (success) {
            _withdrawnAmount += availableBalance;
        } else {
            _withdrawnAmount += withdrawn; 
        }
    }
    function affiliateWithdraw(address affiliate) external payable override nonReentrant {
        if (affiliate != msg.sender && PROTOCOL_FEE_RECIPIENT != msg.sender) revert OwnableUnauthorizedAccount(msg.sender);
        uint256 pending = pendingAffiliateBalance[affiliate];
        delete(pendingAffiliateBalance[affiliate]);
        if (pending > _pendingTotalAffiliatesBalance) pending = _pendingTotalAffiliatesBalance;
        unchecked {
            _pendingTotalAffiliatesBalance -= pending;
        }
        if (_erc20PaymentAddress == address(0)) { 
            assembly {
                pop(call(gas(), affiliate, pending, 0, 0, 0, 0))
            }
        } else {
            _erc20Transfer(_erc20PaymentAddress, affiliate, pending);
        }
    }
    function setAffiliatesPercentageAndDiscount(
        uint16 userDiscount,
        uint16 affiliatePercentage,
        address affiliateAddress
    ) external override onlyOwner {
        AffiliateInformation storage currentAffiliateInfo = _affiliatesInfo[affiliateAddress];
        if ((userDiscount > 100_00) || (affiliatePercentage > 100_00)) {
            _revert(InvalidPercentageOrDiscountValues.selector);
        }
        if ((userDiscount < currentAffiliateInfo.userDiscount) || (affiliatePercentage < currentAffiliateInfo.affiliatePercentage)) {
            _revert(CantLowerCurrentPercentages.selector);
        }
        currentAffiliateInfo.enabled = true;
        currentAffiliateInfo.userDiscount = userDiscount;
        currentAffiliateInfo.affiliatePercentage = affiliatePercentage;
    }
    function affiliatesInfo(address affiliate) external view returns (bool enabled, uint16 affiliatePercentage, uint16 userDiscount) {
        return (_affiliatesInfo[affiliate].enabled, _affiliatesInfo[affiliate].affiliatePercentage, _affiliatesInfo[affiliate].userDiscount);
    }    
    function ownerMaxRevenue() external view returns (uint256 maxRevenue) {
        unchecked {
            for (uint256 i; i<_revenueInfo.length; i++) {
                maxRevenue += _revenueInfo[i].percentage;
            }
            return (100_00 - maxRevenue);
        }
    }    
    function withdrawnAmount() external view returns (uint256) {
        return _withdrawnAmount;
    }
    function pendingTotalAffiliatesBalance() external view returns (uint256) {
        return _pendingTotalAffiliatesBalance;
    }
    function erc20PaymentAddress() external view returns (address) {
        return _erc20PaymentAddress;
    }
    function whitelistOperators(address[] calldata operators) external payable override onlyOwner {
        for (uint256 i = 0; i < operators.length; i++) {
            whitelistedOperators[operators[i]] = true;
        }
        _operatorFilterStatus = OperatorFilterStatus.ENABLED_ONLY_WHITELISTED;
    }
    function disableOperatorFilterRegistry() external payable onlyOwner {
        _operatorFilterStatus = OperatorFilterStatus.DISABLED;
    }
    function isOperatorFilterRegistryEnabled() external view returns (bool) {
        return (_operatorFilterStatus == OperatorFilterStatus.ENABLED_ONLY_WHITELISTED);
    }
    modifier onlyAllowedOperatorApproval(address operator) {
        _isOperatorAllowed(operator);
        _;
    }
    function _isOperatorAllowed(address operator) internal view {
        if (_operatorFilterStatus == OperatorFilterStatus.ENABLED_ONLY_WHITELISTED) {
            if (whitelistedOperators[operator] == false) {
                revert OperatorNotAllowed(operator);
            }
        }
    }
    function royaltyInfo(
        uint256, 
        uint256 salePrice
    ) external view virtual returns (address receiver, uint256 royaltyAmount) {
        return (address(this), uint256((salePrice * royaltyFee()) / 100_00));
    }
    function royaltyFee() public view returns (uint256) {
        return _royaltyFee;        
    }
    function changeRoyaltyFee(uint16 newFee) external payable onlyOwner {
        _royaltyFee = newFee;
    }
    function contractURI() public view returns (string memory) {
        if (_contractURIMetadataCIDHash != 0) {
            return _getIPFSURI(_contractURIMetadataCIDHash);
        }
        return
            string(
                abi.encodePacked(
                    "https:
                    LibString.toString(block.chainid),
                    "/",
                    LibString.toString(uint256(uint160(address(this)))),
                    "/"
                )
            );
    }
    function setContractURI(bytes32 newContractURIMetadataCIDHash) external payable override onlyOwner {
        _contractURIMetadataCIDHash = newContractURIMetadataCIDHash;
        emit ContractURIUpdated();
    }
    function isMetadataFixed() public view virtual override returns (bool);
    function tokenURI(uint256 tokenId) public view virtual returns (string memory);
    function setBaseURI(string memory baseURIString, bytes32 baseURICIDHash, bool isPlaceholder, bool freezeMetadata) external payable override onlyOwner {
        if (isMetadataFixed()) _revert(MetadataAlreadyFixed.selector);
        if (freezeMetadata) {
            if (isPlaceholder) _revert(PlacerholderCantFreezeMetadata.selector);
            _isMetadataEditable = false;
        }
        if (bytes(baseURIString).length == 0 && baseURICIDHash == 0) _revert(NewBaseURICantBeEmpty.selector);
        _hasPlaceholder = isPlaceholder;
        _baseURICIDHash = baseURICIDHash;
        _baseURIString = baseURIString;
        emit BatchMetadataUpdate(1, type(uint256).max);
    }
    function _checkPhase() internal {
        if (_currentPhase != SalePhase.PUBLIC) {
            if (_currentPhase == SalePhase.END_DATE) {
                if (block.timestamp > _endDateTimestamp) {
                    revert SaleFinished();
                }
            } else if (_currentPhase == SalePhase.DROP_DATE) {
                if (block.timestamp < _dropDateTimestamp) {
                    revert WaitUntilDropDate();
                }
                _currentPhase = SalePhase.PUBLIC;
                delete(_dropDateTimestamp); 
            } else if (_currentPhase == SalePhase.DROP_AND_END_DATE) {
                if (block.timestamp < _dropDateTimestamp) {
                    revert WaitUntilDropDate();
                }
                if (block.timestamp > _endDateTimestamp) {
                    revert SaleFinished();
                }
                _currentPhase = SalePhase.END_DATE;
                delete(_dropDateTimestamp); 
            } else {
                revert PublicSaleNotOpen();
            }
        }
    }
    function setPhase(SalePhase newPhase) external payable override onlyOwner {
        if (newPhase > SalePhase.PRESALE) _revert(InvalidPhaseWithoutDate.selector);
        delete(_dropDateTimestamp);
        delete(_endDateTimestamp);
        _currentPhase = newPhase;
    }
    function setDropAndEndDate(uint256 dropDateTimestamp, uint256 endDateTimestamp) external payable override onlyOwner {
        if (dropDateTimestamp == 0) {
            _currentPhase = SalePhase.END_DATE;
        } else if (endDateTimestamp == 0) {
            _currentPhase = SalePhase.DROP_DATE;
        } else {
            _currentPhase = SalePhase.DROP_AND_END_DATE;
        }
        _dropDateTimestamp = dropDateTimestamp;
        _endDateTimestamp = endDateTimestamp;
    }
    function saleDates() external view returns (uint256 dropDateTimestamp, uint256 endDateTimestamp) {
        return (_dropDateTimestamp, _endDateTimestamp);        
    }
    function setMaxPerAddress(uint16 newMaxPerAddress) external payable override onlyOwner {
        _maxPerAddress = newMaxPerAddress;
    }
    function currentPhase() external view override returns (SalePhase) {
        return _currentPhase;        
    }
    function isOpen() external view returns (bool) {
        if (_currentPhase == SalePhase.PUBLIC) return true;
        if (_currentPhase == SalePhase.END_DATE) {
            return (block.timestamp <= _endDateTimestamp);
        }
        if (_currentPhase == SalePhase.DROP_AND_END_DATE) {
            if (block.timestamp >= _dropDateTimestamp) {
                return (block.timestamp <= _endDateTimestamp);
            }
        }
        if (_currentPhase == SalePhase.DROP_DATE) {
            return (block.timestamp >= _dropDateTimestamp);
        }
        return false;
    }
    function setTraitMetadataURI(string calldata uri) external payable override onlyOwner {
        _traitMetadataURI = uri;
        emit TraitMetadataURIUpdated();
    }    
    function getTraitMetadataURI() external view override virtual returns (string memory labelsURI) {
        return _traitMetadataURI;
    }
    function setTraitsPermissions(bytes32[] calldata ownerCanUpdateTraitKeys, bytes32[] calldata onlyOnceTraitKeys) external payable override onlyOwner {
        for (uint256 i; i < ownerCanUpdateTraitKeys.length; i++) {
            _traitPermissions[ownerCanUpdateTraitKeys[i]].ownerCanUpdateValue = true;
        }
        for (uint256 i; i < onlyOnceTraitKeys.length; i++) {
            _traitPermissions[onlyOnceTraitKeys[i]].onlyOnce = true;
        }
    }
    function _setTrait(uint256 tokenId, bytes32 traitKey, bytes32 value) private {
        bytes32 existingValue = _traits[tokenId][traitKey];
        if (_traitPermissions[traitKey].onlyOnce==true) {
            if (existingValue > 0) {
                _revert(OnlyOnceTrait.selector);
            }
            emit ImmutableTrait(traitKey, tokenId, value);
        }
        _traits[tokenId][traitKey] = value;
    }
    function setTrait(uint256 tokenId, bytes32 traitKey, bytes32 value) external override {
        address tokenOwner = _ownerOf(tokenId);
        if (tokenOwner == msg.sender) {
            if (_traitPermissions[traitKey].ownerCanUpdateValue==false) revert NonEditableTraitByTokenOwner();
            _setTrait(tokenId, traitKey, value);
            emit TraitUpdated(traitKey, tokenId, value);
        } else if (tokenOwner == address(0)) {
            _checkOwner();
            _setTrait(tokenId, traitKey, value);
            if (tokenId == 0) {
                emit TraitUpdatedRangeUniformValue(traitKey, 1, _actualCollectionSize(), value);
            }
        } else {
            revert OwnableUnauthorizedAccount(msg.sender);
        }
    }
    function getTraitValue(uint256 tokenId, bytes32 traitKey)
        public
        view
        virtual
        override
        returns (bytes32 traitValue)
    {
        _requireTokenOwned(tokenId);
        traitValue = _traits[tokenId][traitKey];
        if (traitValue == 0) {
            traitValue = _traits[0][traitKey];
        }
    }
    function getTraitValues(uint256 tokenId, bytes32[] calldata traitKeys)
        public
        view
        virtual
        override
        returns (bytes32[] memory traitValues)
    {
        uint256 length = traitKeys.length;
        traitValues = new bytes32[](length);
        for (uint256 i; i < length; i++) {
            bytes32 traitKey = traitKeys[i];
            traitValues[i] = getTraitValue(tokenId, traitKey);
        }        
    }
    function setUser(
        uint256 tokenId,
        address user,
        uint64 expires
    ) public virtual override {
        address tokenOwner = _ownerOf(tokenId);
        _checkAuthorized(tokenOwner, msg.sender, tokenId);
        _packedUserInfo[tokenId] = (uint256(expires) << _BITPOS_RENTAL_EXPIRES) | uint256(uint160(user));
        emit UpdateUser(tokenId, user, expires);
    }
    function userOf(uint256 tokenId) public view virtual override returns (address) {
        uint256 packed = _packedUserInfo[tokenId];
        assembly {
            packed := mul(
                packed,
                lt(shl(_BITPOS_RENTAL_EXPIRES, timestamp()), packed)
            )
        }
        return address(uint160(packed));
    }
    function userExpires(uint256 tokenId) public view virtual override returns (uint256) {
        return _packedUserInfo[tokenId] >> _BITPOS_RENTAL_EXPIRES;
    }
    fallback() external payable
    {
        address dynamicNFTAddress;
        if (msg.sender == address(this) || bytes4(msg.data) == 0xc20768ab) {
            dynamicNFTAddress = address(uint160(_mintPrice));
        } else if (_isDynamicNFT) {
            dynamicNFTAddress = address(_dynamicNFT);
        }
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(
                gas(),
                dynamicNFTAddress,
                0,
                calldatasize(),
                0,
                0
            )
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 {
                revert(0, returndatasize())
            }
            default {
                return(0, returndatasize())
            }
        }
    }
    receive() external payable {}    
}
pragma solidity ^0.8.25;
import {IERC7496, IERC5192, ECDSA, Common, N2MCommonStorage, IN2MCommon, DynamicNFT, DynamicPrice} from "../Common.sol";
import {IN2MCrossFactory} from "../interfaces/IN2MCrossFactory.sol";
import {IN2MSequential} from "../interfaces/IN2MSequential.sol";
abstract contract ConsecutiveMinting is Common, IN2MSequential {
    function initialize008joDSK(
        string calldata name_,
        string calldata symbol_,
        uint256 mintPrice_,
        bytes32 baseURICIDHash,
        bytes32 packedData,
        bytes calldata extraCollectionInformation
    ) public payable override initializer {
        _name = name_;
        _symbol = symbol_;
        _currentIndex = 1;
        if (mintPrice_ > 0) _mintPrice = mintPrice_;
        uint32 collectionSize_ = uint32(uint256(packedData) >> _BITPOS_INIT_COLLECTION_SIZE);
        if (collectionSize_ == 0) _availableCollectionSize = type(uint32).max;
        else _availableCollectionSize = collectionSize_;
        _royaltyFee = uint16(uint256(packedData) >> _BITPOS_INIT_ROYALTY_FEE);
        if (MintingType(uint8(uint256(packedData) >> _BITPOS_INIT_MINTING_TYPE)) == MintingType.SEQUENTIAL_EDITIONS) {
            _isEditions = true;
        }
        if (baseURICIDHash != bytes32(0)) _baseURICIDHash = baseURICIDHash;
        uint256 extraCollectionInformationLength = extraCollectionInformation.length;
        if (extraCollectionInformationLength > 0) {
            uint8 bitmap = uint8(uint256(packedData) >> _BITPOS_INIT_BITMAP);
            bool isSoulbound = (bitmap & BIT1MASK) != 0;
            bool hasPlaceholder = (bitmap & BIT2MASK) != 0;
            bool hasDynamicPrice = (bitmap & BIT3MASK) != 0;
            bool hasEditableMetadata = bitmap & BIT4MASK != 0;
            uint16 reservedTokens_ = uint16(uint256(packedData) >> _BITPOS_INIT_RESERVED_TOKENS);
            if (isSoulbound) {
                _soulboundCollection = true;
            }
            if (hasPlaceholder) {
                _hasPlaceholder = true;
                _isMetadataEditable = true;
            }
            if (hasEditableMetadata) {
                _isMetadataEditable = true;
            }
            if (hasDynamicPrice) {
                _hasDynamicPrice = true;
            }
            if (reservedTokens_ > 0) {
                _reservedTokens = reservedTokens_;
                if (_actualCollectionSize() > type(uint32).max) _revert(InvadlidCollectionSize.selector);
            }
            if (extraCollectionInformationLength > 1) {
                bool hasStrings = bitmap & BIT5MASK != 0;
                bool hasDynamicNFTAddress = bitmap & BIT6MASK != 0;
                bool hasERC20PaymentAddress = bitmap & BIT7MASK != 0;
                bytes32[] memory bArray;
                if (hasStrings) {
                    string memory baseURIString_;
                    string memory collectionDescription_;
                    (bArray, baseURIString_, collectionDescription_) = abi.decode(extraCollectionInformation, (bytes32[], string, string));
                    if (bytes(baseURIString_).length > 0) _baseURIString = baseURIString_;
                    if (bytes(collectionDescription_).length > 0) _collectionDescription = collectionDescription_;
                } else {
                    (bArray) = abi.decode(extraCollectionInformation, (bytes32[]));
                }
                uint256 index;
                SalePhase initPhase = SalePhase(uint8(uint256(packedData >> _BITPOS_INIT_PHASE)));
                if (initPhase != SalePhase.PUBLIC) {
                    _currentPhase = initPhase;
                    if (initPhase > SalePhase.PRESALE) {
                        _dropDateTimestamp = uint256(bArray[index++]);
                        _endDateTimestamp = uint256(bArray[index++]);
                    }
                }
                if (hasDynamicNFTAddress) {
                    _isDynamicNFT = true;
                    _dynamicNFT = DynamicNFT(address(uint160(uint256(bArray[index++]))));
                }
                if (hasERC20PaymentAddress) {
                    _isERC20Payment = true;
                    _erc20PaymentAddress = address(uint160(uint256(bArray[index++])));
                }
                uint256 revenuePercentageTotal;
                for (uint256 bArrayLength = bArray.length; index < bArrayLength; index++) {
                    uint256 revenueInfo = uint256(bArray[index]);
                    uint16 percentage = uint16(revenueInfo >> 160);
                    revenuePercentageTotal += percentage;
                    _revenueInfo.push(RevenueAddress(address(uint160(revenueInfo)), percentage));
                }
                if (revenuePercentageTotal > 100_00) revert InvalidRevenuePercentage();
            }
        }
        emit OwnershipTransferred(address(0), address(uint160(uint256(packedData))));
    }
    function mintEfficientN2M_001Z5BWH() external payable override {
        _requireFeesPayment(_creatorMintFee(), _protocolFee());
        _checkPhase();
        if (_nextTokenId() > _availableCollectionSize) revert CollectionSoldOut();
        __mint(msg.sender, 1);
    }
    function mint() external payable override {
        _requireFeesPayment(_creatorMintFee(), _protocolFee());
        _checkPhase();
        if (_nextTokenId() > _availableCollectionSize) revert CollectionSoldOut();
        __mint(msg.sender, 1);
    }
    function mint(uint256 amount) external payable override {
        _requireFee(amount);
        _mintSequentialWithChecks(msg.sender, amount);
    }
    function mint(uint256 amount, address affiliate) external payable override {
        _requirePaymentWithAffiliates(amount, affiliate);
        _mintSequentialWithChecks(msg.sender, amount);
    }
    function mintTo(address to, uint256 amount) external payable override {
        _requireFee(amount);
        _mintSequentialWithChecks(to, amount);
    }
    function mintTo(address to, uint256 amount, address affiliate) external payable override {
        _requirePaymentWithAffiliates(amount, affiliate);
        _mintSequentialWithChecks(to, amount);
    }
    function _mintSequentialWithChecks(address to, uint256 amount) private {
        _checkPhase();
        if ((_actualSoldTokens() + amount) > _availableCollectionSize) revert CollectionSoldOut();
        _mintSequential(to, amount);
    }
    function _mintSequential(address to, uint256 amount, bool soulbound) private {
        if (soulbound && !_soulboundCollection) {
            for (uint256 i = 0; i < amount; i++) {
                _soulbound[_nextTokenId() + i] = true;
            }
        }
        _mintSequential(to, amount);
    }
    function _mintSequential(address to, uint256 amount) internal virtual {
        __mint(to, amount);
    }
    function airdropSequential(bytes32[] calldata toAndAmount, bool soulbound)
        external
        payable
        override
        onlyOwner
    {
        uint256 toLength = toAndAmount.length;
        for (uint256 i = 0; i < toLength; i++) {
            address to = address(uint160(uint256(toAndAmount[i])));
            uint256 amount = uint256(toAndAmount[i] >> 160);
            _mintSequential(to, amount, soulbound);
        }
        if (_actualSoldTokens() > _availableCollectionSize) revert CollectionSoldOut();
    }
    function mintWhitelist(
        bytes32 toWihtExtra,
        uint256 customFee,
        bytes calldata signature,
        uint256[] calldata tokenIds
    ) external payable override {
        uint16 amount = uint16(uint256(toWihtExtra));
        toWihtExtra = bytes32(toWihtExtra >> _BITPOS_PRESALE_ADDRESS);
        address to = address(uint160(uint256(toWihtExtra)));
        bool freeMinting = uint8(uint256(toWihtExtra) >> _BITPOS_PRESALE_FREE_MINTING) != 0;
        bool soulbound = uint8(uint256(toWihtExtra) >> _BITPOS_PRESALE_SOULBOUND) != 0;
        uint16 maxAmount = (uint16(uint256(toWihtExtra) >> _BITPOS_PRESALE_MAX_AMOUNT));
        if (amount == 0) _revert(InvalidAmount.selector);
        _usedAmountSignature[signature] += amount;
        if (_usedAmountSignature[signature] > maxAmount) revert NotEnoughAmountToMint();
        if (_actualSoldTokens() + amount > _availableCollectionSize) revert CollectionSoldOut();
        if (_currentPhase == SalePhase.CLOSED) revert PresaleNotOpen();
        address signer = ECDSA.recoverCalldata(
            ECDSA.toEthSignedMessageHash(
                keccak256(
                    abi.encodePacked(
                        this.mintWhitelist.selector,                             
                        address(this),                                         
                        block.chainid,                                         
                        toWihtExtra,
                        customFee
                    )
                )
            ),
            signature
        );
        if (signer != N2M_SIGNER && signer != owner()) _revert(SignatureMismatch.selector);
        if (freeMinting) {
            customFee = 0;
        } else if (customFee == 0) {
            customFee = _creatorMintFee(amount);
        } else {
            customFee *= amount;
        }
        _requireFeesPayment(customFee, _protocolFee()*amount);
        _mintSequential(to, amount, soulbound);
    }
    function mintAllowlist(uint256 amount, bytes32[] calldata _proof) external payable override {
        if (_currentPhase == SalePhase.CLOSED) revert PresaleNotOpen();
        if (!allowListed(msg.sender, _proof)) revert NotAllowlisted();
        _requireFee(amount);
        _currentIndex += uint32(amount);
        if (_actualSoldTokens() > _availableCollectionSize) revert CollectionSoldOut();
        __mint(msg.sender, amount);
    }
    function reduceCollectionSize(uint32 newCollectionSize) external payable override onlyOwner {
        _reduceCollectionSize(newCollectionSize);
    }
    function isMetadataFixed() public view override(Common, IN2MCommon) returns (bool) {
        return (_isMetadataEditable == false);
    }
    function mintingType() external pure override(Common, IN2MCommon) returns (MintingType) {
        return MintingType.SEQUENTIAL;
    }
    function _actualSoldTokens() internal view virtual override returns (uint32) {
        return _currentIndex - 1;
    }
    function _nextTokenId() internal view virtual override returns (uint32) {
        return _currentIndex;
    }    
    function __mint(address to, uint256 amount) internal virtual;
}
pragma solidity ^0.8.20;
import {IERC165} from "../utils/introspection/IERC165.sol";
interface IERC2981 is IERC165 {
    function royaltyInfo(
        uint256 tokenId,
        uint256 salePrice
    ) external view returns (address receiver, uint256 royaltyAmount);
}
pragma solidity ^0.8.25;
interface IERC4907 {
    event UpdateUser(uint256 indexed tokenId, address indexed user, uint64 expires);
    function setUser(uint256 tokenId, address user, uint64 expires) external ;
    function userOf(uint256 tokenId) external view returns(address);
    function userExpires(uint256 tokenId) external view returns(uint256);
}
pragma solidity ^0.8.4;
library Base64 {
    function encode(bytes memory data, bool fileSafe, bool noPadding)
        internal
        pure
        returns (string memory result)
    {
        assembly {
            let dataLength := mload(data)
            if dataLength {
                let encodedLength := shl(2, div(add(dataLength, 2), 3))
                result := mload(0x40)
                mstore(0x1f, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef")
                mstore(0x3f, xor("ghijklmnopqrstuvwxyz0123456789-_", mul(iszero(fileSafe), 0x0670)))
                let ptr := add(result, 0x20)
                let end := add(ptr, encodedLength)
                let dataEnd := add(add(0x20, data), dataLength)
                let dataEndValue := mload(dataEnd) 
                mstore(dataEnd, 0x00) 
                for {} 1 {} {
                    data := add(data, 3) 
                    let input := mload(data)
                    mstore8(0, mload(and(shr(18, input), 0x3F)))
                    mstore8(1, mload(and(shr(12, input), 0x3F)))
                    mstore8(2, mload(and(shr(6, input), 0x3F)))
                    mstore8(3, mload(and(input, 0x3F)))
                    mstore(ptr, mload(0x00))
                    ptr := add(ptr, 4) 
                    if iszero(lt(ptr, end)) { break }
                }
                mstore(dataEnd, dataEndValue) 
                mstore(0x40, add(end, 0x20)) 
                let o := div(2, mod(dataLength, 3))
                mstore(sub(ptr, o), shl(240, 0x3d3d))
                o := mul(iszero(iszero(noPadding)), o)
                mstore(sub(ptr, o), 0) 
                mstore(result, sub(encodedLength, o)) 
            }
        }
    }
    function encode(bytes memory data) internal pure returns (string memory result) {
        result = encode(data, false, false);
    }
    function encode(bytes memory data, bool fileSafe)
        internal
        pure
        returns (string memory result)
    {
        result = encode(data, fileSafe, false);
    }
    function decode(string memory data) internal pure returns (bytes memory result) {
        assembly {
            let dataLength := mload(data)
            if dataLength {
                let decodedLength := mul(shr(2, dataLength), 3)
                for {} 1 {} {
                    if iszero(and(dataLength, 3)) {
                        let t := xor(mload(add(data, dataLength)), 0x3d3d)
                        decodedLength := sub(
                            decodedLength,
                            add(iszero(byte(30, t)), iszero(byte(31, t)))
                        )
                        break
                    }
                    decodedLength := add(decodedLength, sub(and(dataLength, 3), 1))
                    break
                }
                result := mload(0x40)
                mstore(result, decodedLength)
                let ptr := add(result, 0x20)
                let end := add(ptr, decodedLength)
                let m := 0xfc000000fc00686c7074787c8084888c9094989ca0a4a8acb0b4b8bcc0c4c8cc
                mstore(0x5b, m)
                mstore(0x3b, 0x04080c1014181c2024282c3034383c4044484c5054585c6064)
                mstore(0x1a, 0xf8fcf800fcd0d4d8dce0e4e8ecf0f4)
                for {} 1 {} {
                    data := add(data, 4)
                    let input := mload(data)
                    mstore(ptr, or(
                        and(m, mload(byte(28, input))),
                        shr(6, or(
                            and(m, mload(byte(29, input))),
                            shr(6, or(
                                and(m, mload(byte(30, input))),
                                shr(6, mload(byte(31, input)))
                            ))
                        ))
                    ))
                    ptr := add(ptr, 3)
                    if iszero(lt(ptr, end)) { break }
                }
                mstore(0x40, add(end, 0x20)) 
                mstore(end, 0) 
                mstore(0x60, 0) 
            }
        }
    }
}
pragma solidity ^0.8.25;
interface IERC7572 {
  function contractURI() external view returns (string memory);
  event ContractURIUpdated();
}
pragma solidity ^0.8.25;
interface Readme {
    function n2mVersion() external pure returns (uint256);
 }
pragma solidity ^0.8.4;
library SafeTransferLib {
    error ETHTransferFailed();
    error TransferFromFailed();
    error TransferFailed();
    error ApproveFailed();
    error Permit2Failed();
    error Permit2AmountOverflow();
    uint256 internal constant GAS_STIPEND_NO_STORAGE_WRITES = 2300;
    uint256 internal constant GAS_STIPEND_NO_GRIEF = 100000;
    bytes32 internal constant DAI_DOMAIN_SEPARATOR =
        0xdbb8cf42e1ecb028be3f3dbc922e1d878b963f411dc388ced501601c60f7c6f7;
    address internal constant WETH9 = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address internal constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;
    function safeTransferETH(address to, uint256 amount) internal {
        assembly {
            if iszero(call(gas(), to, amount, codesize(), 0x00, codesize(), 0x00)) {
                mstore(0x00, 0xb12d13eb) 
                revert(0x1c, 0x04)
            }
        }
    }
    function safeTransferAllETH(address to) internal {
        assembly {
            if iszero(call(gas(), to, selfbalance(), codesize(), 0x00, codesize(), 0x00)) {
                mstore(0x00, 0xb12d13eb) 
                revert(0x1c, 0x04)
            }
        }
    }
    function forceSafeTransferETH(address to, uint256 amount, uint256 gasStipend) internal {
        assembly {
            if lt(selfbalance(), amount) {
                mstore(0x00, 0xb12d13eb) 
                revert(0x1c, 0x04)
            }
            if iszero(call(gasStipend, to, amount, codesize(), 0x00, codesize(), 0x00)) {
                mstore(0x00, to) 
                mstore8(0x0b, 0x73) 
                mstore8(0x20, 0xff) 
                if iszero(create(amount, 0x0b, 0x16)) { revert(codesize(), codesize()) } 
            }
        }
    }
    function forceSafeTransferAllETH(address to, uint256 gasStipend) internal {
        assembly {
            if iszero(call(gasStipend, to, selfbalance(), codesize(), 0x00, codesize(), 0x00)) {
                mstore(0x00, to) 
                mstore8(0x0b, 0x73) 
                mstore8(0x20, 0xff) 
                if iszero(create(selfbalance(), 0x0b, 0x16)) { revert(codesize(), codesize()) } 
            }
        }
    }
    function forceSafeTransferETH(address to, uint256 amount) internal {
        assembly {
            if lt(selfbalance(), amount) {
                mstore(0x00, 0xb12d13eb) 
                revert(0x1c, 0x04)
            }
            if iszero(call(GAS_STIPEND_NO_GRIEF, to, amount, codesize(), 0x00, codesize(), 0x00)) {
                mstore(0x00, to) 
                mstore8(0x0b, 0x73) 
                mstore8(0x20, 0xff) 
                if iszero(create(amount, 0x0b, 0x16)) { revert(codesize(), codesize()) } 
            }
        }
    }
    function forceSafeTransferAllETH(address to) internal {
        assembly {
            if iszero(call(GAS_STIPEND_NO_GRIEF, to, selfbalance(), codesize(), 0x00, codesize(), 0x00)) {
                mstore(0x00, to) 
                mstore8(0x0b, 0x73) 
                mstore8(0x20, 0xff) 
                if iszero(create(selfbalance(), 0x0b, 0x16)) { revert(codesize(), codesize()) } 
            }
        }
    }
    function trySafeTransferETH(address to, uint256 amount, uint256 gasStipend)
        internal
        returns (bool success)
    {
        assembly {
            success := call(gasStipend, to, amount, codesize(), 0x00, codesize(), 0x00)
        }
    }
    function trySafeTransferAllETH(address to, uint256 gasStipend)
        internal
        returns (bool success)
    {
        assembly {
            success := call(gasStipend, to, selfbalance(), codesize(), 0x00, codesize(), 0x00)
        }
    }
    function safeTransferFrom(address token, address from, address to, uint256 amount) internal {
        assembly {
            let m := mload(0x40) 
            mstore(0x60, amount) 
            mstore(0x40, to) 
            mstore(0x2c, shl(96, from)) 
            mstore(0x0c, 0x23b872dd000000000000000000000000) 
            if iszero(
                and( 
                    or(eq(mload(0x00), 1), iszero(returndatasize())), 
                    call(gas(), token, 0, 0x1c, 0x64, 0x00, 0x20)
                )
            ) {
                mstore(0x00, 0x7939f424) 
                revert(0x1c, 0x04)
            }
            mstore(0x60, 0) 
            mstore(0x40, m) 
        }
    }
    function trySafeTransferFrom(address token, address from, address to, uint256 amount)
        internal
        returns (bool success)
    {
        assembly {
            let m := mload(0x40) 
            mstore(0x60, amount) 
            mstore(0x40, to) 
            mstore(0x2c, shl(96, from)) 
            mstore(0x0c, 0x23b872dd000000000000000000000000) 
            success :=
                and( 
                    or(eq(mload(0x00), 1), iszero(returndatasize())), 
                    call(gas(), token, 0, 0x1c, 0x64, 0x00, 0x20)
                )
            mstore(0x60, 0) 
            mstore(0x40, m) 
        }
    }
    function safeTransferAllFrom(address token, address from, address to)
        internal
        returns (uint256 amount)
    {
        assembly {
            let m := mload(0x40) 
            mstore(0x40, to) 
            mstore(0x2c, shl(96, from)) 
            mstore(0x0c, 0x70a08231000000000000000000000000) 
            if iszero(
                and( 
                    gt(returndatasize(), 0x1f), 
                    staticcall(gas(), token, 0x1c, 0x24, 0x60, 0x20)
                )
            ) {
                mstore(0x00, 0x7939f424) 
                revert(0x1c, 0x04)
            }
            mstore(0x00, 0x23b872dd) 
            amount := mload(0x60) 
            if iszero(
                and( 
                    or(eq(mload(0x00), 1), iszero(returndatasize())), 
                    call(gas(), token, 0, 0x1c, 0x64, 0x00, 0x20)
                )
            ) {
                mstore(0x00, 0x7939f424) 
                revert(0x1c, 0x04)
            }
            mstore(0x60, 0) 
            mstore(0x40, m) 
        }
    }
    function safeTransfer(address token, address to, uint256 amount) internal {
        assembly {
            mstore(0x14, to) 
            mstore(0x34, amount) 
            mstore(0x00, 0xa9059cbb000000000000000000000000) 
            if iszero(
                and( 
                    or(eq(mload(0x00), 1), iszero(returndatasize())), 
                    call(gas(), token, 0, 0x10, 0x44, 0x00, 0x20)
                )
            ) {
                mstore(0x00, 0x90b8ec18) 
                revert(0x1c, 0x04)
            }
            mstore(0x34, 0) 
        }
    }
    function safeTransferAll(address token, address to) internal returns (uint256 amount) {
        assembly {
            mstore(0x00, 0x70a08231) 
            mstore(0x20, address()) 
            if iszero(
                and( 
                    gt(returndatasize(), 0x1f), 
                    staticcall(gas(), token, 0x1c, 0x24, 0x34, 0x20)
                )
            ) {
                mstore(0x00, 0x90b8ec18) 
                revert(0x1c, 0x04)
            }
            mstore(0x14, to) 
            amount := mload(0x34) 
            mstore(0x00, 0xa9059cbb000000000000000000000000) 
            if iszero(
                and( 
                    or(eq(mload(0x00), 1), iszero(returndatasize())), 
                    call(gas(), token, 0, 0x10, 0x44, 0x00, 0x20)
                )
            ) {
                mstore(0x00, 0x90b8ec18) 
                revert(0x1c, 0x04)
            }
            mstore(0x34, 0) 
        }
    }
    function safeApprove(address token, address to, uint256 amount) internal {
        assembly {
            mstore(0x14, to) 
            mstore(0x34, amount) 
            mstore(0x00, 0x095ea7b3000000000000000000000000) 
            if iszero(
                and( 
                    or(eq(mload(0x00), 1), iszero(returndatasize())), 
                    call(gas(), token, 0, 0x10, 0x44, 0x00, 0x20)
                )
            ) {
                mstore(0x00, 0x3e3f8f73) 
                revert(0x1c, 0x04)
            }
            mstore(0x34, 0) 
        }
    }
    function safeApproveWithRetry(address token, address to, uint256 amount) internal {
        assembly {
            mstore(0x14, to) 
            mstore(0x34, amount) 
            mstore(0x00, 0x095ea7b3000000000000000000000000) 
            if iszero(
                and( 
                    or(eq(mload(0x00), 1), iszero(returndatasize())), 
                    call(gas(), token, 0, 0x10, 0x44, 0x00, 0x20)
                )
            ) {
                mstore(0x34, 0) 
                mstore(0x00, 0x095ea7b3000000000000000000000000) 
                pop(call(gas(), token, 0, 0x10, 0x44, codesize(), 0x00)) 
                mstore(0x34, amount) 
                if iszero(
                    and(
                        or(eq(mload(0x00), 1), iszero(returndatasize())), 
                        call(gas(), token, 0, 0x10, 0x44, 0x00, 0x20)
                    )
                ) {
                    mstore(0x00, 0x3e3f8f73) 
                    revert(0x1c, 0x04)
                }
            }
            mstore(0x34, 0) 
        }
    }
    function balanceOf(address token, address account) internal view returns (uint256 amount) {
        assembly {
            mstore(0x14, account) 
            mstore(0x00, 0x70a08231000000000000000000000000) 
            amount :=
                mul( 
                    mload(0x20),
                    and( 
                        gt(returndatasize(), 0x1f), 
                        staticcall(gas(), token, 0x10, 0x24, 0x20, 0x20)
                    )
                )
        }
    }
    function safeTransferFrom2(address token, address from, address to, uint256 amount) internal {
        if (!trySafeTransferFrom(token, from, to, amount)) {
            permit2TransferFrom(token, from, to, amount);
        }
    }
    function permit2TransferFrom(address token, address from, address to, uint256 amount)
        internal
    {
        assembly {
            let m := mload(0x40)
            mstore(add(m, 0x74), shr(96, shl(96, token)))
            mstore(add(m, 0x54), amount)
            mstore(add(m, 0x34), to)
            mstore(add(m, 0x20), shl(96, from))
            mstore(m, 0x36c78516000000000000000000000000)
            let p := mul(PERMIT2, iszero(shr(160, amount)))
            if iszero(mul(call(gas(), p, 0, add(m, 0x10), 0x84, codesize(), 0x00), extcodesize(p)))
            {
                mstore(0x00, 0x7939f4248757f0fd) 
                revert(add(0x18, shl(2, iszero(p))), 0x04)
            }
        }
    }
    function permit2(
        address token,
        address owner,
        address spender,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal {
        bool success;
        assembly {
            for {} shl(96, xor(token, WETH9)) {} {
                mstore(0x00, 0x3644e515) 
                if iszero(
                    and( 
                        lt(iszero(mload(0x00)), eq(returndatasize(), 0x20)), 
                        staticcall(5000, token, 0x1c, 0x04, 0x00, 0x20)
                    )
                ) { break }
                let m := mload(0x40)
                mstore(add(m, 0x34), spender)
                mstore(add(m, 0x20), shl(96, owner))
                mstore(add(m, 0x74), deadline)
                if eq(mload(0x00), DAI_DOMAIN_SEPARATOR) {
                    mstore(0x14, owner)
                    mstore(0x00, 0x7ecebe00000000000000000000000000) 
                    mstore(add(m, 0x94), staticcall(gas(), token, 0x10, 0x24, add(m, 0x54), 0x20))
                    mstore(m, 0x8fcbaf0c000000000000000000000000) 
                    mstore(add(m, 0xb4), and(0xff, v))
                    mstore(add(m, 0xd4), r)
                    mstore(add(m, 0xf4), s)
                    success := call(gas(), token, 0, add(m, 0x10), 0x104, codesize(), 0x00)
                    break
                }
                mstore(m, 0xd505accf000000000000000000000000) 
                mstore(add(m, 0x54), amount)
                mstore(add(m, 0x94), and(0xff, v))
                mstore(add(m, 0xb4), r)
                mstore(add(m, 0xd4), s)
                success := call(gas(), token, 0, add(m, 0x10), 0xe4, codesize(), 0x00)
                break
            }
        }
        if (!success) simplePermit2(token, owner, spender, amount, deadline, v, r, s);
    }
    function simplePermit2(
        address token,
        address owner,
        address spender,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal {
        assembly {
            let m := mload(0x40)
            mstore(m, 0x927da105) 
            {
                let addressMask := shr(96, not(0))
                mstore(add(m, 0x20), and(addressMask, owner))
                mstore(add(m, 0x40), and(addressMask, token))
                mstore(add(m, 0x60), and(addressMask, spender))
                mstore(add(m, 0xc0), and(addressMask, spender))
            }
            let p := mul(PERMIT2, iszero(shr(160, amount)))
            if iszero(
                and( 
                    gt(returndatasize(), 0x5f), 
                    staticcall(gas(), p, add(m, 0x1c), 0x64, add(m, 0x60), 0x60)
                )
            ) {
                mstore(0x00, 0x6b836e6b8757f0fd) 
                revert(add(0x18, shl(2, iszero(p))), 0x04)
            }
            mstore(m, 0x2b67b570) 
            mstore(add(m, 0x60), amount)
            mstore(add(m, 0x80), 0xffffffffffff) 
            mstore(add(m, 0xe0), deadline)
            mstore(add(m, 0x100), 0x100) 
            mstore(add(m, 0x120), 0x41) 
            mstore(add(m, 0x140), r)
            mstore(add(m, 0x160), s)
            mstore(add(m, 0x180), shl(248, v))
            if iszero(call(gas(), p, 0, add(m, 0x1c), 0x184, codesize(), 0x00)) {
                mstore(0x00, 0x6b836e6b) 
                revert(0x1c, 0x04)
            }
        }
    }
}
pragma solidity ^0.8.25;
interface DynamicNFT {
    function dynamicTokenURI(uint256 tokenId) external view returns (string memory);
    function tokenUpdate(address from, address to, uint256 tokenId) external payable;
    function tokenBulkUpdate(address from, address to, uint256 startTokenId, uint256 quantity) external payable;
}
pragma solidity ^0.8.25;
interface IERC721A {
    struct TokenOwnership {
        address addr;
        uint64 startTimestamp;
        bool burned;
        uint24 extraData;
    }
    function totalSupply() external view returns (uint256);
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
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
    ) external payable;
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId
    ) external payable;
    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) external payable;
    function approve(address to, uint256 tokenId) external payable;
    function setApprovalForAll(address operator, bool _approved) external;
    function getApproved(uint256 tokenId) external view returns (address operator);
    function isApprovedForAll(address owner, address operator) external view returns (bool);
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function tokenURI(uint256 tokenId) external view returns (string memory);
    event ConsecutiveTransfer(uint256 indexed fromTokenId, uint256 toTokenId, address indexed from, address indexed to);
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
pragma solidity ^0.8.4;
library ECDSA {
    error InvalidSignature();
    function recover(bytes32 hash, bytes memory signature) internal view returns (address result) {
        assembly {
            result := 1
            let m := mload(0x40) 
            for {} 1 {} {
                mstore(0x00, hash)
                mstore(0x40, mload(add(signature, 0x20))) 
                if eq(mload(signature), 64) {
                    let vs := mload(add(signature, 0x40))
                    mstore(0x20, add(shr(255, vs), 27)) 
                    mstore(0x60, shr(1, shl(1, vs))) 
                    break
                }
                if eq(mload(signature), 65) {
                    mstore(0x20, byte(0, mload(add(signature, 0x60)))) 
                    mstore(0x60, mload(add(signature, 0x40))) 
                    break
                }
                result := 0
                break
            }
            result :=
                mload(
                    staticcall(
                        gas(), 
                        result, 
                        0x00, 
                        0x80, 
                        0x01, 
                        0x20 
                    )
                )
            if iszero(returndatasize()) {
                mstore(0x00, 0x8baa579f) 
                revert(0x1c, 0x04)
            }
            mstore(0x60, 0) 
            mstore(0x40, m) 
        }
    }
    function recoverCalldata(bytes32 hash, bytes calldata signature)
        internal
        view
        returns (address result)
    {
        assembly {
            result := 1
            let m := mload(0x40) 
            mstore(0x00, hash)
            for {} 1 {} {
                if eq(signature.length, 64) {
                    let vs := calldataload(add(signature.offset, 0x20))
                    mstore(0x20, add(shr(255, vs), 27)) 
                    mstore(0x40, calldataload(signature.offset)) 
                    mstore(0x60, shr(1, shl(1, vs))) 
                    break
                }
                if eq(signature.length, 65) {
                    mstore(0x20, byte(0, calldataload(add(signature.offset, 0x40)))) 
                    calldatacopy(0x40, signature.offset, 0x40) 
                    break
                }
                result := 0
                break
            }
            result :=
                mload(
                    staticcall(
                        gas(), 
                        result, 
                        0x00, 
                        0x80, 
                        0x01, 
                        0x20 
                    )
                )
            if iszero(returndatasize()) {
                mstore(0x00, 0x8baa579f) 
                revert(0x1c, 0x04)
            }
            mstore(0x60, 0) 
            mstore(0x40, m) 
        }
    }
    function recover(bytes32 hash, bytes32 r, bytes32 vs) internal view returns (address result) {
        assembly {
            let m := mload(0x40) 
            mstore(0x00, hash)
            mstore(0x20, add(shr(255, vs), 27)) 
            mstore(0x40, r)
            mstore(0x60, shr(1, shl(1, vs))) 
            result :=
                mload(
                    staticcall(
                        gas(), 
                        1, 
                        0x00, 
                        0x80, 
                        0x01, 
                        0x20 
                    )
                )
            if iszero(returndatasize()) {
                mstore(0x00, 0x8baa579f) 
                revert(0x1c, 0x04)
            }
            mstore(0x60, 0) 
            mstore(0x40, m) 
        }
    }
    function recover(bytes32 hash, uint8 v, bytes32 r, bytes32 s)
        internal
        view
        returns (address result)
    {
        assembly {
            let m := mload(0x40) 
            mstore(0x00, hash)
            mstore(0x20, and(v, 0xff))
            mstore(0x40, r)
            mstore(0x60, s)
            result :=
                mload(
                    staticcall(
                        gas(), 
                        1, 
                        0x00, 
                        0x80, 
                        0x01, 
                        0x20 
                    )
                )
            if iszero(returndatasize()) {
                mstore(0x00, 0x8baa579f) 
                revert(0x1c, 0x04)
            }
            mstore(0x60, 0) 
            mstore(0x40, m) 
        }
    }
    function tryRecover(bytes32 hash, bytes memory signature)
        internal
        view
        returns (address result)
    {
        assembly {
            result := 1
            let m := mload(0x40) 
            for {} 1 {} {
                mstore(0x00, hash)
                mstore(0x40, mload(add(signature, 0x20))) 
                if eq(mload(signature), 64) {
                    let vs := mload(add(signature, 0x40))
                    mstore(0x20, add(shr(255, vs), 27)) 
                    mstore(0x60, shr(1, shl(1, vs))) 
                    break
                }
                if eq(mload(signature), 65) {
                    mstore(0x20, byte(0, mload(add(signature, 0x60)))) 
                    mstore(0x60, mload(add(signature, 0x40))) 
                    break
                }
                result := 0
                break
            }
            pop(
                staticcall(
                    gas(), 
                    result, 
                    0x00, 
                    0x80, 
                    0x40, 
                    0x20 
                )
            )
            mstore(0x60, 0) 
            result := mload(xor(0x60, returndatasize()))
            mstore(0x40, m) 
        }
    }
    function tryRecoverCalldata(bytes32 hash, bytes calldata signature)
        internal
        view
        returns (address result)
    {
        assembly {
            result := 1
            let m := mload(0x40) 
            mstore(0x00, hash)
            for {} 1 {} {
                if eq(signature.length, 64) {
                    let vs := calldataload(add(signature.offset, 0x20))
                    mstore(0x20, add(shr(255, vs), 27)) 
                    mstore(0x40, calldataload(signature.offset)) 
                    mstore(0x60, shr(1, shl(1, vs))) 
                    break
                }
                if eq(signature.length, 65) {
                    mstore(0x20, byte(0, calldataload(add(signature.offset, 0x40)))) 
                    calldatacopy(0x40, signature.offset, 0x40) 
                    break
                }
                result := 0
                break
            }
            pop(
                staticcall(
                    gas(), 
                    result, 
                    0x00, 
                    0x80, 
                    0x40, 
                    0x20 
                )
            )
            mstore(0x60, 0) 
            result := mload(xor(0x60, returndatasize()))
            mstore(0x40, m) 
        }
    }
    function tryRecover(bytes32 hash, bytes32 r, bytes32 vs)
        internal
        view
        returns (address result)
    {
        assembly {
            let m := mload(0x40) 
            mstore(0x00, hash)
            mstore(0x20, add(shr(255, vs), 27)) 
            mstore(0x40, r)
            mstore(0x60, shr(1, shl(1, vs))) 
            pop(
                staticcall(
                    gas(), 
                    1, 
                    0x00, 
                    0x80, 
                    0x40, 
                    0x20 
                )
            )
            mstore(0x60, 0) 
            result := mload(xor(0x60, returndatasize()))
            mstore(0x40, m) 
        }
    }
    function tryRecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s)
        internal
        view
        returns (address result)
    {
        assembly {
            let m := mload(0x40) 
            mstore(0x00, hash)
            mstore(0x20, and(v, 0xff))
            mstore(0x40, r)
            mstore(0x60, s)
            pop(
                staticcall(
                    gas(), 
                    1, 
                    0x00, 
                    0x80, 
                    0x40, 
                    0x20 
                )
            )
            mstore(0x60, 0) 
            result := mload(xor(0x60, returndatasize()))
            mstore(0x40, m) 
        }
    }
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32 result) {
        assembly {
            mstore(0x20, hash) 
            mstore(0x00, "\x00\x00\x00\x00\x19Ethereum Signed Message:\n32") 
            result := keccak256(0x04, 0x3c) 
        }
    }
    function toEthSignedMessageHash(bytes memory s) internal pure returns (bytes32 result) {
        assembly {
            let sLength := mload(s)
            let o := 0x20
            mstore(o, "\x19Ethereum Signed Message:\n") 
            mstore(0x00, 0x00)
            for { let temp := sLength } 1 {} {
                o := sub(o, 1)
                mstore8(o, add(48, mod(temp, 10)))
                temp := div(temp, 10)
                if iszero(temp) { break }
            }
            let n := sub(0x3a, o) 
            returndatacopy(returndatasize(), returndatasize(), gt(n, 0x20))
            mstore(s, or(mload(0x00), mload(n))) 
            result := keccak256(add(s, sub(0x20, n)), add(n, sLength))
            mstore(s, sLength) 
        }
    }
    function emptySignature() internal pure returns (bytes calldata signature) {
        assembly {
            signature.length := 0
        }
    }
}
pragma solidity ^0.8.25;
import {ERC721A, IERC7496, IERC5192, Common, DynamicNFT} from "./ERC721A/ERC721A.sol";
import {IERC165, IERC2981} from "openzeppelin/contracts/interfaces/IERC2981.sol";
import {Address} from "openzeppelin/contracts/utils/Address.sol";
import {LibString} from "solady/utils/LibString.sol";
import {Base64} from "solady/utils/Base64.sol";
contract N2MERC721A is ERC721A {
    constructor(address payable factoryAddress, uint256 protocolFee_) Common(factoryAddress, protocolFee_) ERC721A() payable {}
    function _requireTokenOwned(uint256 tokenId) internal view virtual override {
        if (!_exists(tokenId)) revert OwnerQueryForNonexistentToken();
    }
    function _checkAuthorized(address owner, address spender, uint256 tokenId) internal view override(ERC721A) {
       return ERC721A._checkAuthorized(owner, spender, tokenId);
    }
    function totalSupply() public view override(ERC721A) returns (uint256) {
        return ERC721A.totalSupply();
    }
    function tokenURI(uint256 tokenId)
        public
        view
        override(ERC721A)
        returns (string memory)
    {
        _requireTokenOwned(tokenId);
        if (_isDynamicNFT) {
            return DynamicNFT(address(this)).dynamicTokenURI(tokenId);
        }
        string memory stringTokenId = LibString.toString(tokenId);
        string memory baseURI;
        if (_baseURICIDHash != 0) {
            baseURI = _getIPFSURI(_baseURICIDHash);
        } else {
            baseURI = _baseURIString;
        }
        string memory nameString;
        string memory descriptionString;
        {
            bool isInline;
            if (_hasPlaceholder) {
                isInline = true;
                nameString = 'Unrevealed Token';
            } else if (_isEditions) {
                isInline = true;
                nameString = LibString.escapeJSON(_name);
                if (bytes(_collectionDescription).length != 0) {
                    descriptionString = string(abi.encodePacked('","description":"', LibString.escapeJSON(_collectionDescription)));
                }
                if (_baseURICIDHash != 0 && bytes(_baseURIString).length != 0) {
                    descriptionString = string(abi.encodePacked(descriptionString, '","animation_url":"', _baseURIString));
                }
            }
            if (isInline) {
                return string(
                    abi.encodePacked(
                        'data:application/json;base64,',
                        Base64.encode(
                            abi.encodePacked(
                                '{"name":"',
                                nameString,
                                ' #' ,
                                stringTokenId,
                                descriptionString,
                                '","image":"',
                                baseURI,
                                '"}'
                            )
                        )
                    )
                );
            } 
        }
        return
            string(
                abi.encodePacked(
                    baseURI,
                    "/",
                    stringTokenId,
                    ".json"
                )
            );
    }
    function __mint(address to, uint256 amount)
        internal
        override
    {
        _mint(to, uint32(amount));
    }
    function name()
        public
        view
        override(ERC721A)
        returns (string memory)
    {
        return _name;
    }
    function _beforeTokenTransfers(
        address from,
        address,
        uint256 startTokenId,
        uint256 quantity
    ) internal override virtual {
        if (
            from != address(0) &&
            (_soulbound[startTokenId] || _soulbound[startTokenId + quantity - 1] || _soulboundCollection)
        ) _revert(NonTransferrableSoulboundNFT.selector);
    }
    function _afterTokenTransfers(
        address from,
        address to,
        uint256 startTokenId,
        uint256 quantity
    ) internal override virtual {
        if (to != address(0)) {
            if (_maxPerAddress != 0) {
                if (_balanceOfData[to] > _maxPerAddress) _revert(MaxPerAddressExceeded.selector);
            }
        }
        if (_isDynamicNFT) {
            Address.functionDelegateCall(address(_dynamicNFT), abi.encodeWithSelector(DynamicNFT.tokenBulkUpdate.selector, from, to, startTokenId, quantity));
        }      
    }
    function supportsInterface(bytes4 interfaceId)
        public
        pure
        override(ERC721A)
        returns (bool)
    {
        if (interfaceId == IERC165_INTERFACE_ID) return true;         
        if (interfaceId == IERC173_INTERFACE_ID) return true;         
        if (interfaceId == IERC721_INTERFACE_ID) return true;         
        if (interfaceId == IERC721METADATA_INTERFACE_ID) return true; 
        if (interfaceId == IERC2981_INTERFACE_ID) return true;        
        if (interfaceId == IERC4907_INTERFACE_ID) return true;        
        if (interfaceId == IERC7496_INTERFACE_ID) return true;        
        return (interfaceId == IERC5192_INTERFACE_ID);                
    }
    function symbol()
        public
        view
        virtual
        override(ERC721A)
        returns (string memory)
    {
        return _symbol;
    }
    function setApprovalForAll(address operator, bool approved) public override(ERC721A) onlyAllowedOperatorApproval(operator) {
        super.setApprovalForAll(operator, approved);
    }
    function approve(address operator, uint256 tokenId) public override(ERC721A) payable onlyAllowedOperatorApproval(operator) {
        super.approve(operator, tokenId);
    }
    function isApprovedForAll(address owner_, address operator)
    public
    view
    virtual
    override(ERC721A)
    returns (bool)
    {
        if (operator == OPENSEA_CONDUIT && _operatorFilterStatus == OperatorFilterStatus.DISABLED) return true;
        if (operator == N2M_CONDUIT) return true;
        return super.isApprovedForAll(owner_, operator);
    }
    function burn(uint256 tokenId) external payable {
        _burn(tokenId, true);
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
pragma solidity ^0.8.25;
import {IERC721A} from "./IERC721A.sol";
import {IERC165} from "openzeppelin/contracts/interfaces/IERC2981.sol"; 
import {IERC7496, IERC5192, ConsecutiveMinting, Common, IN2MCommon, DynamicNFT} from "../ConsecutiveMinting.sol";
interface ERC721A__IERC721Receiver {
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}
abstract contract ERC721A is IERC721A, ConsecutiveMinting {
    uint256 private constant _BITMASK_BURNED = 1 << 224;
    uint256 private constant _BITPOS_NEXT_INITIALIZED = 225;
    uint256 private constant _BITMASK_NEXT_INITIALIZED = 1 << 225;
    uint256 private constant _BITPOS_EXTRA_DATA = 232;
    uint256 private constant _BITMASK_ADDRESS = (1 << 160) - 1;
    bytes32 private constant _TRANSFER_EVENT_SIGNATURE =
        0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef;
    function _startTokenId() internal pure virtual returns (uint32) {
        return 1;
    }
    function totalSupply() public view virtual override(Common, IERC721A, IN2MCommon) returns (uint256) {
        unchecked {
            return _currentIndex - _burnedTokens - _startTokenId();
        }
    }
    function balanceOf(address owner) public view virtual override returns (uint256) {
        if (owner == address(0)) _revert(BalanceQueryForZeroAddress.selector);
        return _balanceOfData[owner];
    }
    function supportsInterface(bytes4 interfaceId) public view virtual override(IERC165, IERC721A) returns (bool) {
        return
            interfaceId == 0x01ffc9a7 || 
            interfaceId == 0x80ac58cd || 
            interfaceId == 0x5b5e139f; 
    }
    function name() public view virtual override(IERC721A, IN2MCommon) returns (string memory) {
        return _name;
    }
    function symbol() public view virtual override(IERC721A, IN2MCommon) returns (string memory) {
        return _symbol;
    }
    function tokenURI(uint256 tokenId) public view virtual override(Common, IERC721A) returns (string memory) {
    }
    function ownerOf(uint256 tokenId) public view virtual override returns (address) {
        return address(uint160(_packedOwnershipOf(tokenId)));
    }
    function _packedOwnershipOf(uint256 tokenId) private view returns (uint256 packed) {
        if (_startTokenId() <= tokenId) {
            packed = _packedOwnerships[tokenId];
            if (packed == 0) {
                if (tokenId >= _currentIndex) _revert(OwnerQueryForNonexistentToken.selector);
                for (;;) {
                    unchecked {
                        packed = _packedOwnerships[--tokenId];
                    }
                    if (packed == 0) continue;
                    if (packed & _BITMASK_BURNED == 0) return packed;
                    _revert(OwnerQueryForNonexistentToken.selector);
                }
            }
            if (packed & _BITMASK_BURNED == 0) return packed;
        }
        _revert(OwnerQueryForNonexistentToken.selector);
    }
    function _ownerOf(uint256 tokenId) internal view virtual override(Common) returns (address owner) {
        if (_exists(tokenId)) return ownerOf(tokenId);
    }
    function _packOwnershipData(address owner, uint256 flags) private pure returns (uint256 result) {
        assembly {
            owner := and(owner, _BITMASK_ADDRESS)
            result := or(owner, flags)
        }
    }
    function _nextInitializedFlag(uint256 quantity) private pure returns (uint256 result) {
        assembly {
            result := shl(_BITPOS_NEXT_INITIALIZED, eq(quantity, 1))
        }
    }
    function approve(address to, uint256 tokenId) public payable virtual override {
        _approve(to, tokenId, true);
    }
    function getApproved(uint256 tokenId) public view virtual override returns (address) {
        if (!_exists(tokenId)) _revert(ApprovalQueryForNonexistentToken.selector);
        return _tokenApprovals[tokenId].value;
    }
    function setApprovalForAll(address operator, bool approved) public virtual override {
        _operatorApprovals[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }
    function isApprovedForAll(address owner, address operator) public view virtual override returns (bool) {
        return _operatorApprovals[owner][operator];
    }
    function _exists(uint256 tokenId) internal view virtual returns (bool result) {
        if (_startTokenId() <= tokenId) {
            if (tokenId < _currentIndex) {
                uint256 packed;
                while ((packed = _packedOwnerships[tokenId]) == 0) --tokenId;
                result = packed & _BITMASK_BURNED == 0;
            }
        }
    }
    function _isSenderApprovedOrOwner(
        address approvedAddress,
        address owner,
        address msgSender
    ) private view returns (bool result) {
        _isOperatorAllowed(msgSender);
        assembly {
            owner := and(owner, _BITMASK_ADDRESS)
            msgSender := and(msgSender, _BITMASK_ADDRESS)
            result := or(eq(msgSender, owner), eq(msgSender, approvedAddress))
        }
    }
    function _getApprovedSlotAndAddress(uint256 tokenId)
        private
        view
        returns (uint256 approvedAddressSlot, address approvedAddress)
    {
        TokenApprovalRef storage tokenApproval = _tokenApprovals[tokenId];
        assembly {
            approvedAddressSlot := tokenApproval.slot
            approvedAddress := sload(approvedAddressSlot)
        }
    }
    function _checkAuthorized(address owner, address spender, uint256 tokenId) internal view virtual override {
        (, address approvedAddress) = _getApprovedSlotAndAddress(tokenId); 
        if (!_isSenderApprovedOrOwner(approvedAddress, owner, spender))
            if (!isApprovedForAll(owner, spender)) _revert(TransferCallerNotOwnerNorApproved.selector);
    }
    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public payable virtual override {
        uint256 prevOwnershipPacked = _packedOwnershipOf(tokenId);
        from = address(uint160(uint256(uint160(from)) & _BITMASK_ADDRESS));
        if (address(uint160(prevOwnershipPacked)) != from) _revert(TransferFromIncorrectOwner.selector);
        (uint256 approvedAddressSlot, address approvedAddress) = _getApprovedSlotAndAddress(tokenId);
        if (!_isSenderApprovedOrOwner(approvedAddress, from, msg.sender))
            if (!isApprovedForAll(from, msg.sender)) _revert(TransferCallerNotOwnerNorApproved.selector);
        _beforeTokenTransfers(from, to, tokenId, 1);
        assembly {
            if approvedAddress {
                sstore(approvedAddressSlot, 0)
            }
        }
        unchecked {
            --_balanceOfData[from]; 
            ++_balanceOfData[to]; 
            _packedOwnerships[tokenId] = _packOwnershipData(
                to,
                _BITMASK_NEXT_INITIALIZED | _nextExtraData(from, to, prevOwnershipPacked)
            );
            if (prevOwnershipPacked & _BITMASK_NEXT_INITIALIZED == 0) {
                uint256 nextTokenId = tokenId + 1;
                if (_packedOwnerships[nextTokenId] == 0) {
                    if (nextTokenId != _currentIndex) {
                        _packedOwnerships[nextTokenId] = prevOwnershipPacked;
                    }
                }
            }
        }
        uint256 toMasked = uint256(uint160(to)) & _BITMASK_ADDRESS;
        assembly {
            log4(
                0, 
                0, 
                _TRANSFER_EVENT_SIGNATURE, 
                from, 
                toMasked, 
                tokenId 
            )
        }
        if (toMasked == 0) _revert(TransferToZeroAddress.selector);
        _afterTokenTransfers(from, to, tokenId, 1);
    }
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public payable virtual override {
        safeTransferFrom(from, to, tokenId, '');
    }
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) public payable virtual override {
        transferFrom(from, to, tokenId);
        if (to.code.length != 0)
            if (!_checkContractOnERC721Received(from, to, tokenId, _data)) {
                _revert(TransferToNonERC721ReceiverImplementer.selector);
            }
    }
    function _beforeTokenTransfers(
        address from,
        address to,
        uint256 startTokenId,
        uint256 quantity
    ) internal virtual {}
    function _afterTokenTransfers(
        address from,
        address to,
        uint256 startTokenId,
        uint256 quantity
    ) internal virtual {}
    function _checkContractOnERC721Received(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) private returns (bool) {
        try ERC721A__IERC721Receiver(to).onERC721Received(msg.sender, from, tokenId, _data) returns (
            bytes4 retval
        ) {
            return retval == ERC721A__IERC721Receiver(to).onERC721Received.selector;
        } catch (bytes memory reason) {
            if (reason.length == 0) {
                _revert(TransferToNonERC721ReceiverImplementer.selector);
            }
            assembly {
                revert(add(32, reason), mload(reason))
            }
        }
    }
    function _mint(address to, uint32 quantity) internal virtual {
        uint32 startTokenId = _currentIndex;
        if (quantity == 0) _revert(MintZeroQuantity.selector);
        _beforeTokenTransfers(address(0), to, startTokenId, quantity);
        unchecked {
            _packedOwnerships[startTokenId] = _packOwnershipData(
                to,
                _nextInitializedFlag(quantity) | _nextExtraData(address(0), to, 0)
            );
            _balanceOfData[to] += quantity;
            uint256 toMasked = uint256(uint160(to)) & _BITMASK_ADDRESS;
            if (toMasked == 0) _revert(MintToZeroAddress.selector);
            uint32 end = startTokenId + quantity;
            uint256 tokenId = startTokenId;
            do {
                assembly {
                    log4(
                        0, 
                        0, 
                        _TRANSFER_EVENT_SIGNATURE, 
                        0, 
                        toMasked, 
                        tokenId 
                    )
                }
            } while (++tokenId != end);
            _currentIndex = end;
        }
        _afterTokenTransfers(address(0), to, startTokenId, quantity);
    }
    function _approve(address to, uint256 tokenId) internal virtual {
        _approve(to, tokenId, false);
    }
    function _approve(
        address to,
        uint256 tokenId,
        bool approvalCheck
    ) internal virtual {
        address owner = ownerOf(tokenId);
        if (approvalCheck && msg.sender != owner)
            if (!isApprovedForAll(owner, msg.sender)) {
                _revert(ApprovalCallerNotOwnerNorApproved.selector);
            }
        _tokenApprovals[tokenId].value = to;
        emit Approval(owner, to, tokenId);
    }
    function _burn(uint256 tokenId, bool approvalCheck) internal virtual {
        uint256 prevOwnershipPacked = _packedOwnershipOf(tokenId);
        address from = address(uint160(prevOwnershipPacked));
        (uint256 approvedAddressSlot, address approvedAddress) = _getApprovedSlotAndAddress(tokenId);
        if (approvalCheck) {
            if (!_isSenderApprovedOrOwner(approvedAddress, from, msg.sender))
                if (!isApprovedForAll(from, msg.sender)) _revert(TransferCallerNotOwnerNorApproved.selector);
        }
        _beforeTokenTransfers(from, address(0), tokenId, 1);
        assembly {
            if approvedAddress {
                sstore(approvedAddressSlot, 0)
            }
        }
        unchecked {
            _balanceOfData[from]--; 
            _packedOwnerships[tokenId] = _packOwnershipData(
                from,
                (_BITMASK_BURNED | _BITMASK_NEXT_INITIALIZED) | _nextExtraData(from, address(0), prevOwnershipPacked)
            );
            if (prevOwnershipPacked & _BITMASK_NEXT_INITIALIZED == 0) {
                uint256 nextTokenId = tokenId + 1;
                if (_packedOwnerships[nextTokenId] == 0) {
                    if (nextTokenId != _currentIndex) {
                        _packedOwnerships[nextTokenId] = prevOwnershipPacked;
                    }
                }
            }
        }
        emit Transfer(from, address(0), tokenId);
        _afterTokenTransfers(from, address(0), tokenId, 1);
        unchecked {
            _burnedTokens++;
        }
    }
    function _extraData(
        address from,
        address to,
        uint24 previousExtraData
    ) internal view virtual returns (uint24) {}
    function _nextExtraData(
        address from,
        address to,
        uint256 prevOwnershipPacked
    ) private view returns (uint256) {
        uint24 extraData = uint24(prevOwnershipPacked >> _BITPOS_EXTRA_DATA);
        return uint256(_extraData(from, to, extraData)) << _BITPOS_EXTRA_DATA;
    }
}
pragma solidity ^0.8.25;
interface IERC7496 {
    event TraitUpdated(bytes32 indexed traitKey, uint256 tokenId, bytes32 traitValue);
    event TraitUpdatedRange(bytes32 indexed traitKey, uint256 fromTokenId, uint256 toTokenId);
    event TraitUpdatedRangeUniformValue(
        bytes32 indexed traitKey, uint256 fromTokenId, uint256 toTokenId, bytes32 traitValue
    );
    event TraitUpdatedList(bytes32 indexed traitKey, uint256[] tokenIds);
    event TraitUpdatedListUniformValue(bytes32 indexed traitKey, uint256[] tokenIds, bytes32 traitValue);
    event TraitMetadataURIUpdated();
    function getTraitValue(uint256 tokenId, bytes32 traitKey) external view returns (bytes32 traitValue);
    function getTraitValues(uint256 tokenId, bytes32[] calldata traitKeys)
        external
        view
        returns (bytes32[] memory traitValues);
    function getTraitMetadataURI() external view returns (string memory uri);
    function setTrait(uint256 tokenId, bytes32 traitKey, bytes32 traitValue) external;
    error TraitValueUnchanged();
}
pragma solidity ^0.8.25;
import "../important/README.sol";
interface IN2MCommonStorage is Readme {
    struct RevenueAddress {
        address to;
        uint16 percentage;
    }
    struct AffiliateInformation {
        bool enabled;
        uint16 affiliatePercentage;
        uint16 userDiscount;
    }
    struct TokenApprovalRef {
        address value;
    }
    enum SalePhase { 
        PUBLIC,
        CLOSED,
        PRESALE,
        DROP_DATE,
        DROP_AND_END_DATE,
        END_DATE
    }
    enum MintingType { 
        SEQUENTIAL, 
        RANDOM,
        SPECIFY, 
        CUSTOM_URI,
        SEQUENTIAL_EDITIONS
    }
    enum OperatorFilterStatus { 
        DISABLED, 
        ENABLED_ONLY_WHITELISTED
    }
    function withdrawnERC20Amount(address erc20) external view returns (uint256);
    function pendingAffiliateBalance(address affiliate) external view returns (uint256);
    function whitelistedOperators(address operator) external view returns (bool);
}
pragma solidity ^0.8.25;
import {IN2MCommonStorage} from "./interfaces/IN2MCommonStorage.sol";
import {DynamicNFT} from './interfaces/DynamicNFT.sol';
import {N2MVersion} from "./N2MVersion.sol";
abstract contract N2MCommonStorage is IN2MCommonStorage, N2MVersion {
    uint8 internal constant BIT1MASK = 0x01;
    uint8 internal constant BIT2MASK = 0x02;
    uint8 internal constant BIT3MASK = 0x04;
    uint8 internal constant BIT4MASK = 0x08;
    uint8 internal constant BIT5MASK = 0x10;
    uint8 internal constant BIT6MASK = 0x20;
    uint8 internal constant BIT7MASK = 0x40;
    bytes4 internal constant IERC165_INTERFACE_ID = 0x01ffc9a7;
    bytes4 internal constant IERC173_INTERFACE_ID = 0x7f5828d0;
    bytes4 internal constant IERC721_INTERFACE_ID = 0x80ac58cd;
    bytes4 internal constant IERC721METADATA_INTERFACE_ID = 0x5b5e139f;
    bytes4 internal constant IERC2981_INTERFACE_ID = 0x2a55205a;
    bytes4 internal constant IERC4907_INTERFACE_ID = 0xad092b5c;
    bytes4 internal constant IERC5192_INTERFACE_ID = 0xb45a3c0e;
    bytes4 internal constant IERC7496_INTERFACE_ID = 0xaf332f3e;
    uint256 internal constant REENTRANCY_NOT_ENTERED = 1;
    uint256 internal constant REENTRANCY_ENTERED = 2;
    uint256 internal constant _BITPOS_INIT_COLLECTION_SIZE = 160;
    uint256 internal constant _BITPOS_INIT_ROYALTY_FEE = 192;
    uint256 internal constant _BITPOS_INIT_MINTING_TYPE = 208;
    uint256 internal constant _BITPOS_INIT_PHASE = 216;
    uint256 internal constant _BITPOS_INIT_BITMAP = 224;
    uint256 internal constant _BITPOS_INIT_RESERVED_TOKENS = 232;
    uint256 internal constant _BITPOS_PRESALE_ADDRESS = 16;
    uint256 internal constant _BITPOS_PRESALE_FREE_MINTING = 160;
    uint256 internal constant _BITPOS_PRESALE_SOULBOUND = 168;
    uint256 internal constant _BITPOS_PRESALE_MAX_AMOUNT = 176;
    uint256 internal constant _BITPOS_RENTAL_EXPIRES = 160;
    address internal constant PROTOCOL_FEE_RECIPIENT = 0x6db16927DbC38AA39F0Ee2cB545e15EFd813FB99;
    address internal constant OPENSEA_CONDUIT = 0x1E0049783F008A0085193E00003D00cd54003c71;
    address internal constant N2M_CONDUIT = 0x88899DC0B84C6E726840e00DFb94ABc6248825eC;
    address internal constant N2M_SIGNER = 0x00000000156D54b85de04c897356026a5ff2cBc9;
    address payable internal immutable FACTORY;
    uint256 internal immutable PROTOCOL_FEE;
    uint16 internal _royaltyFee;
    uint32 internal _availableCollectionSize;
    bool internal _isEditions;
    uint32 internal _currentIndex;
    uint16 internal _maxPerAddress;                                                                 
    SalePhase internal _currentPhase;
    MintingType internal _mintingType;                                                              
    bool internal _isERC20Payment;
    bool internal _feesRemoved;
    bool internal _isDynamicNFT;
    bool internal _hasDynamicPrice;
    bool internal _soulboundCollection;
    OperatorFilterStatus internal _operatorFilterStatus;
    uint32 internal _burnedTokens;
    uint16 internal _reservedTokens;
    bool internal _hasPlaceholder;                                                                  
    bool internal _isMetadataEditable;                                                              
    uint24 internal _extraPacked;
    uint256 _extra1;
    uint256 _extra2;
    uint256 _extra3;
    uint256 _extra4;
    uint256 _extra5;
    uint256 _extra6;
    uint256 _extra7;
    uint256 _extra8;
    uint256 _extra9;
    DynamicNFT _dynamicNFT;
    string internal _name;
    string internal _symbol;
    string internal _collectionDescription;
    string internal _baseURIString;
    bytes32 internal _baseURICIDHash;
    bytes32 internal _contractURIMetadataCIDHash;
    bytes32 internal _merkleRoot;
    mapping(address => uint256) public pendingAffiliateBalance;
    uint256 internal _pendingTotalAffiliatesBalance;
    RevenueAddress[] internal _revenueInfo;
    mapping(address => AffiliateInformation) internal _affiliatesInfo;
    uint256 internal _mintPrice;
    uint256 internal _reentrancyStatus;
    uint256 internal _dropDateTimestamp;
    uint256 internal _endDateTimestamp; 
    mapping(address => uint256) public withdrawnERC20Amount;
    address internal _erc20PaymentAddress;
    uint256 internal _withdrawnAmount;
    mapping(bytes => uint256) internal _usedAmountSignature;
    mapping(uint256 => bool) internal _soulbound;
    mapping(uint256 => bytes32) internal _customURICIDHashes;
    mapping(address => bool) public whitelistedOperators;
    struct TraitPermission {
        bool ownerCanUpdateValue;
        bool onlyOnce;
    }
    mapping(bytes32 => TraitPermission) internal _traitPermissions;
    mapping(uint256 tokenId => mapping(bytes32 traitKey => bytes32 traitValue)) internal _traits;
    string internal _traitMetadataURI;
    mapping(uint256 => uint256) internal _packedUserInfo;
    mapping(uint256 => uint256) internal _packedOwnerships;
    mapping(address => uint256) internal _balanceOfData;
    mapping(uint256 => TokenApprovalRef) internal _tokenApprovals;
    mapping(address => mapping(address => bool)) internal _operatorApprovals;
    constructor(address payable factoryAddress_, uint256 protocolFee_) {
        FACTORY = factoryAddress_;
        PROTOCOL_FEE = protocolFee_;
    }
}
pragma solidity ^0.8.4;
library LibString {
    error HexLengthInsufficient();
    error TooBigForSmallString();
    uint256 internal constant NOT_FOUND = type(uint256).max;
    function toString(uint256 value) internal pure returns (string memory str) {
        assembly {
            str := add(mload(0x40), 0x80)
            mstore(0x40, add(str, 0x20))
            mstore(str, 0)
            let end := str
            let w := not(0) 
            for { let temp := value } 1 {} {
                str := add(str, w) 
                mstore8(str, add(48, mod(temp, 10)))
                temp := div(temp, 10)
                if iszero(temp) { break }
            }
            let length := sub(end, str)
            str := sub(str, 0x20)
            mstore(str, length)
        }
    }
    function toString(int256 value) internal pure returns (string memory str) {
        if (value >= 0) {
            return toString(uint256(value));
        }
        unchecked {
            str = toString(~uint256(value) + 1);
        }
        assembly {
            let length := mload(str) 
            mstore(str, 0x2d) 
            str := sub(str, 1) 
            mstore(str, add(length, 1)) 
        }
    }
    function toHexString(uint256 value, uint256 length) internal pure returns (string memory str) {
        str = toHexStringNoPrefix(value, length);
        assembly {
            let strLength := add(mload(str), 2) 
            mstore(str, 0x3078) 
            str := sub(str, 2) 
            mstore(str, strLength) 
        }
    }
    function toHexStringNoPrefix(uint256 value, uint256 length)
        internal
        pure
        returns (string memory str)
    {
        assembly {
            str := add(mload(0x40), and(add(shl(1, length), 0x42), not(0x1f)))
            mstore(0x40, add(str, 0x20))
            mstore(str, 0)
            let end := str
            mstore(0x0f, 0x30313233343536373839616263646566)
            let start := sub(str, add(length, length))
            let w := not(1) 
            let temp := value
            for {} 1 {} {
                str := add(str, w) 
                mstore8(add(str, 1), mload(and(temp, 15)))
                mstore8(str, mload(and(shr(4, temp), 15)))
                temp := shr(8, temp)
                if iszero(xor(str, start)) { break }
            }
            if temp {
                mstore(0x00, 0x2194895a) 
                revert(0x1c, 0x04)
            }
            let strLength := sub(end, str)
            str := sub(str, 0x20)
            mstore(str, strLength)
        }
    }
    function toHexString(uint256 value) internal pure returns (string memory str) {
        str = toHexStringNoPrefix(value);
        assembly {
            let strLength := add(mload(str), 2) 
            mstore(str, 0x3078) 
            str := sub(str, 2) 
            mstore(str, strLength) 
        }
    }
    function toMinimalHexString(uint256 value) internal pure returns (string memory str) {
        str = toHexStringNoPrefix(value);
        assembly {
            let o := eq(byte(0, mload(add(str, 0x20))), 0x30) 
            let strLength := add(mload(str), 2) 
            mstore(add(str, o), 0x3078) 
            str := sub(add(str, o), 2) 
            mstore(str, sub(strLength, o)) 
        }
    }
    function toMinimalHexStringNoPrefix(uint256 value) internal pure returns (string memory str) {
        str = toHexStringNoPrefix(value);
        assembly {
            let o := eq(byte(0, mload(add(str, 0x20))), 0x30) 
            let strLength := mload(str) 
            str := add(str, o) 
            mstore(str, sub(strLength, o)) 
        }
    }
    function toHexStringNoPrefix(uint256 value) internal pure returns (string memory str) {
        assembly {
            str := add(mload(0x40), 0x80)
            mstore(0x40, add(str, 0x20))
            mstore(str, 0)
            let end := str
            mstore(0x0f, 0x30313233343536373839616263646566)
            let w := not(1) 
            for { let temp := value } 1 {} {
                str := add(str, w) 
                mstore8(add(str, 1), mload(and(temp, 15)))
                mstore8(str, mload(and(shr(4, temp), 15)))
                temp := shr(8, temp)
                if iszero(temp) { break }
            }
            let strLength := sub(end, str)
            str := sub(str, 0x20)
            mstore(str, strLength)
        }
    }
    function toHexStringChecksummed(address value) internal pure returns (string memory str) {
        str = toHexString(value);
        assembly {
            let mask := shl(6, div(not(0), 255)) 
            let o := add(str, 0x22)
            let hashed := and(keccak256(o, 40), mul(34, mask)) 
            let t := shl(240, 136) 
            for { let i := 0 } 1 {} {
                mstore(add(i, i), mul(t, byte(i, hashed)))
                i := add(i, 1)
                if eq(i, 20) { break }
            }
            mstore(o, xor(mload(o), shr(1, and(mload(0x00), and(mload(o), mask)))))
            o := add(o, 0x20)
            mstore(o, xor(mload(o), shr(1, and(mload(0x20), and(mload(o), mask)))))
        }
    }
    function toHexString(address value) internal pure returns (string memory str) {
        str = toHexStringNoPrefix(value);
        assembly {
            let strLength := add(mload(str), 2) 
            mstore(str, 0x3078) 
            str := sub(str, 2) 
            mstore(str, strLength) 
        }
    }
    function toHexStringNoPrefix(address value) internal pure returns (string memory str) {
        assembly {
            str := mload(0x40)
            mstore(0x40, add(str, 0x80))
            mstore(0x0f, 0x30313233343536373839616263646566)
            str := add(str, 2)
            mstore(str, 40)
            let o := add(str, 0x20)
            mstore(add(o, 40), 0)
            value := shl(96, value)
            for { let i := 0 } 1 {} {
                let p := add(o, add(i, i))
                let temp := byte(i, value)
                mstore8(add(p, 1), mload(and(temp, 15)))
                mstore8(p, mload(shr(4, temp)))
                i := add(i, 1)
                if eq(i, 20) { break }
            }
        }
    }
    function toHexString(bytes memory raw) internal pure returns (string memory str) {
        str = toHexStringNoPrefix(raw);
        assembly {
            let strLength := add(mload(str), 2) 
            mstore(str, 0x3078) 
            str := sub(str, 2) 
            mstore(str, strLength) 
        }
    }
    function toHexStringNoPrefix(bytes memory raw) internal pure returns (string memory str) {
        assembly {
            let length := mload(raw)
            str := add(mload(0x40), 2) 
            mstore(str, add(length, length)) 
            mstore(0x0f, 0x30313233343536373839616263646566)
            let o := add(str, 0x20)
            let end := add(raw, length)
            for {} iszero(eq(raw, end)) {} {
                raw := add(raw, 1)
                mstore8(add(o, 1), mload(and(mload(raw), 15)))
                mstore8(o, mload(and(shr(4, mload(raw)), 15)))
                o := add(o, 2)
            }
            mstore(o, 0) 
            mstore(0x40, add(o, 0x20)) 
        }
    }
    function runeCount(string memory s) internal pure returns (uint256 result) {
        assembly {
            if mload(s) {
                mstore(0x00, div(not(0), 255))
                mstore(0x20, 0x0202020202020202020202020202020202020202020202020303030304040506)
                let o := add(s, 0x20)
                let end := add(o, mload(s))
                for { result := 1 } 1 { result := add(result, 1) } {
                    o := add(o, byte(0, mload(shr(250, mload(o)))))
                    if iszero(lt(o, end)) { break }
                }
            }
        }
    }
    function is7BitASCII(string memory s) internal pure returns (bool result) {
        assembly {
            let mask := shl(7, div(not(0), 255))
            result := 1
            let n := mload(s)
            if n {
                let o := add(s, 0x20)
                let end := add(o, n)
                let last := mload(end)
                mstore(end, 0)
                for {} 1 {} {
                    if and(mask, mload(o)) {
                        result := 0
                        break
                    }
                    o := add(o, 0x20)
                    if iszero(lt(o, end)) { break }
                }
                mstore(end, last)
            }
        }
    }
    function replace(string memory subject, string memory search, string memory replacement)
        internal
        pure
        returns (string memory result)
    {
        assembly {
            let subjectLength := mload(subject)
            let searchLength := mload(search)
            let replacementLength := mload(replacement)
            subject := add(subject, 0x20)
            search := add(search, 0x20)
            replacement := add(replacement, 0x20)
            result := add(mload(0x40), 0x20)
            let subjectEnd := add(subject, subjectLength)
            if iszero(gt(searchLength, subjectLength)) {
                let subjectSearchEnd := add(sub(subjectEnd, searchLength), 1)
                let h := 0
                if iszero(lt(searchLength, 0x20)) { h := keccak256(search, searchLength) }
                let m := shl(3, sub(0x20, and(searchLength, 0x1f)))
                let s := mload(search)
                for {} 1 {} {
                    let t := mload(subject)
                    if iszero(shr(m, xor(t, s))) {
                        if h {
                            if iszero(eq(keccak256(subject, searchLength), h)) {
                                mstore(result, t)
                                result := add(result, 1)
                                subject := add(subject, 1)
                                if iszero(lt(subject, subjectSearchEnd)) { break }
                                continue
                            }
                        }
                        for { let o := 0 } 1 {} {
                            mstore(add(result, o), mload(add(replacement, o)))
                            o := add(o, 0x20)
                            if iszero(lt(o, replacementLength)) { break }
                        }
                        result := add(result, replacementLength)
                        subject := add(subject, searchLength)
                        if searchLength {
                            if iszero(lt(subject, subjectSearchEnd)) { break }
                            continue
                        }
                    }
                    mstore(result, t)
                    result := add(result, 1)
                    subject := add(subject, 1)
                    if iszero(lt(subject, subjectSearchEnd)) { break }
                }
            }
            let resultRemainder := result
            result := add(mload(0x40), 0x20)
            let k := add(sub(resultRemainder, result), sub(subjectEnd, subject))
            for {} lt(subject, subjectEnd) {} {
                mstore(resultRemainder, mload(subject))
                resultRemainder := add(resultRemainder, 0x20)
                subject := add(subject, 0x20)
            }
            result := sub(result, 0x20)
            let last := add(add(result, 0x20), k) 
            mstore(last, 0)
            mstore(0x40, add(last, 0x20)) 
            mstore(result, k) 
        }
    }
    function indexOf(string memory subject, string memory search, uint256 from)
        internal
        pure
        returns (uint256 result)
    {
        assembly {
            for { let subjectLength := mload(subject) } 1 {} {
                if iszero(mload(search)) {
                    if iszero(gt(from, subjectLength)) {
                        result := from
                        break
                    }
                    result := subjectLength
                    break
                }
                let searchLength := mload(search)
                let subjectStart := add(subject, 0x20)
                result := not(0) 
                subject := add(subjectStart, from)
                let end := add(sub(add(subjectStart, subjectLength), searchLength), 1)
                let m := shl(3, sub(0x20, and(searchLength, 0x1f)))
                let s := mload(add(search, 0x20))
                if iszero(and(lt(subject, end), lt(from, subjectLength))) { break }
                if iszero(lt(searchLength, 0x20)) {
                    for { let h := keccak256(add(search, 0x20), searchLength) } 1 {} {
                        if iszero(shr(m, xor(mload(subject), s))) {
                            if eq(keccak256(subject, searchLength), h) {
                                result := sub(subject, subjectStart)
                                break
                            }
                        }
                        subject := add(subject, 1)
                        if iszero(lt(subject, end)) { break }
                    }
                    break
                }
                for {} 1 {} {
                    if iszero(shr(m, xor(mload(subject), s))) {
                        result := sub(subject, subjectStart)
                        break
                    }
                    subject := add(subject, 1)
                    if iszero(lt(subject, end)) { break }
                }
                break
            }
        }
    }
    function indexOf(string memory subject, string memory search)
        internal
        pure
        returns (uint256 result)
    {
        result = indexOf(subject, search, 0);
    }
    function lastIndexOf(string memory subject, string memory search, uint256 from)
        internal
        pure
        returns (uint256 result)
    {
        assembly {
            for {} 1 {} {
                result := not(0) 
                let searchLength := mload(search)
                if gt(searchLength, mload(subject)) { break }
                let w := result
                let fromMax := sub(mload(subject), searchLength)
                if iszero(gt(fromMax, from)) { from := fromMax }
                let end := add(add(subject, 0x20), w)
                subject := add(add(subject, 0x20), from)
                if iszero(gt(subject, end)) { break }
                for { let h := keccak256(add(search, 0x20), searchLength) } 1 {} {
                    if eq(keccak256(subject, searchLength), h) {
                        result := sub(subject, add(end, 1))
                        break
                    }
                    subject := add(subject, w) 
                    if iszero(gt(subject, end)) { break }
                }
                break
            }
        }
    }
    function lastIndexOf(string memory subject, string memory search)
        internal
        pure
        returns (uint256 result)
    {
        result = lastIndexOf(subject, search, uint256(int256(-1)));
    }
    function contains(string memory subject, string memory search) internal pure returns (bool) {
        return indexOf(subject, search) != NOT_FOUND;
    }
    function startsWith(string memory subject, string memory search)
        internal
        pure
        returns (bool result)
    {
        assembly {
            let searchLength := mload(search)
            result := and(
                iszero(gt(searchLength, mload(subject))),
                eq(
                    keccak256(add(subject, 0x20), searchLength),
                    keccak256(add(search, 0x20), searchLength)
                )
            )
        }
    }
    function endsWith(string memory subject, string memory search)
        internal
        pure
        returns (bool result)
    {
        assembly {
            let searchLength := mload(search)
            let subjectLength := mload(subject)
            let withinRange := iszero(gt(searchLength, subjectLength))
            result := and(
                withinRange,
                eq(
                    keccak256(
                        add(add(subject, 0x20), mul(withinRange, sub(subjectLength, searchLength))),
                        searchLength
                    ),
                    keccak256(add(search, 0x20), searchLength)
                )
            )
        }
    }
    function repeat(string memory subject, uint256 times)
        internal
        pure
        returns (string memory result)
    {
        assembly {
            let subjectLength := mload(subject)
            if iszero(or(iszero(times), iszero(subjectLength))) {
                subject := add(subject, 0x20)
                result := mload(0x40)
                let output := add(result, 0x20)
                for {} 1 {} {
                    for { let o := 0 } 1 {} {
                        mstore(add(output, o), mload(add(subject, o)))
                        o := add(o, 0x20)
                        if iszero(lt(o, subjectLength)) { break }
                    }
                    output := add(output, subjectLength)
                    times := sub(times, 1)
                    if iszero(times) { break }
                }
                mstore(output, 0) 
                let resultLength := sub(output, add(result, 0x20))
                mstore(result, resultLength) 
                mstore(0x40, add(result, add(resultLength, 0x20)))
            }
        }
    }
    function slice(string memory subject, uint256 start, uint256 end)
        internal
        pure
        returns (string memory result)
    {
        assembly {
            let subjectLength := mload(subject)
            if iszero(gt(subjectLength, end)) { end := subjectLength }
            if iszero(gt(subjectLength, start)) { start := subjectLength }
            if lt(start, end) {
                result := mload(0x40)
                let resultLength := sub(end, start)
                mstore(result, resultLength)
                subject := add(subject, start)
                let w := not(0x1f)
                for { let o := and(add(resultLength, 0x1f), w) } 1 {} {
                    mstore(add(result, o), mload(add(subject, o)))
                    o := add(o, w) 
                    if iszero(o) { break }
                }
                mstore(add(add(result, 0x20), resultLength), 0)
                mstore(0x40, add(result, and(add(resultLength, 0x3f), w)))
            }
        }
    }
    function slice(string memory subject, uint256 start)
        internal
        pure
        returns (string memory result)
    {
        result = slice(subject, start, uint256(int256(-1)));
    }
    function indicesOf(string memory subject, string memory search)
        internal
        pure
        returns (uint256[] memory result)
    {
        assembly {
            let subjectLength := mload(subject)
            let searchLength := mload(search)
            if iszero(gt(searchLength, subjectLength)) {
                subject := add(subject, 0x20)
                search := add(search, 0x20)
                result := add(mload(0x40), 0x20)
                let subjectStart := subject
                let subjectSearchEnd := add(sub(add(subject, subjectLength), searchLength), 1)
                let h := 0
                if iszero(lt(searchLength, 0x20)) { h := keccak256(search, searchLength) }
                let m := shl(3, sub(0x20, and(searchLength, 0x1f)))
                let s := mload(search)
                for {} 1 {} {
                    let t := mload(subject)
                    if iszero(shr(m, xor(t, s))) {
                        if h {
                            if iszero(eq(keccak256(subject, searchLength), h)) {
                                subject := add(subject, 1)
                                if iszero(lt(subject, subjectSearchEnd)) { break }
                                continue
                            }
                        }
                        mstore(result, sub(subject, subjectStart))
                        result := add(result, 0x20)
                        subject := add(subject, searchLength)
                        if searchLength {
                            if iszero(lt(subject, subjectSearchEnd)) { break }
                            continue
                        }
                    }
                    subject := add(subject, 1)
                    if iszero(lt(subject, subjectSearchEnd)) { break }
                }
                let resultEnd := result
                result := mload(0x40)
                mstore(result, shr(5, sub(resultEnd, add(result, 0x20))))
                mstore(0x40, add(resultEnd, 0x20))
            }
        }
    }
    function split(string memory subject, string memory delimiter)
        internal
        pure
        returns (string[] memory result)
    {
        uint256[] memory indices = indicesOf(subject, delimiter);
        assembly {
            let w := not(0x1f)
            let indexPtr := add(indices, 0x20)
            let indicesEnd := add(indexPtr, shl(5, add(mload(indices), 1)))
            mstore(add(indicesEnd, w), mload(subject))
            mstore(indices, add(mload(indices), 1))
            let prevIndex := 0
            for {} 1 {} {
                let index := mload(indexPtr)
                mstore(indexPtr, 0x60)
                if iszero(eq(index, prevIndex)) {
                    let element := mload(0x40)
                    let elementLength := sub(index, prevIndex)
                    mstore(element, elementLength)
                    for { let o := and(add(elementLength, 0x1f), w) } 1 {} {
                        mstore(add(element, o), mload(add(add(subject, prevIndex), o)))
                        o := add(o, w) 
                        if iszero(o) { break }
                    }
                    mstore(add(add(element, 0x20), elementLength), 0)
                    mstore(0x40, add(element, and(add(elementLength, 0x3f), w)))
                    mstore(indexPtr, element)
                }
                prevIndex := add(index, mload(delimiter))
                indexPtr := add(indexPtr, 0x20)
                if iszero(lt(indexPtr, indicesEnd)) { break }
            }
            result := indices
            if iszero(mload(delimiter)) {
                result := add(indices, 0x20)
                mstore(result, sub(mload(indices), 2))
            }
        }
    }
    function concat(string memory a, string memory b)
        internal
        pure
        returns (string memory result)
    {
        assembly {
            let w := not(0x1f)
            result := mload(0x40)
            let aLength := mload(a)
            for { let o := and(add(aLength, 0x20), w) } 1 {} {
                mstore(add(result, o), mload(add(a, o)))
                o := add(o, w) 
                if iszero(o) { break }
            }
            let bLength := mload(b)
            let output := add(result, aLength)
            for { let o := and(add(bLength, 0x20), w) } 1 {} {
                mstore(add(output, o), mload(add(b, o)))
                o := add(o, w) 
                if iszero(o) { break }
            }
            let totalLength := add(aLength, bLength)
            let last := add(add(result, 0x20), totalLength)
            mstore(last, 0)
            mstore(result, totalLength)
            mstore(0x40, and(add(last, 0x1f), w))
        }
    }
    function toCase(string memory subject, bool toUpper)
        internal
        pure
        returns (string memory result)
    {
        assembly {
            let length := mload(subject)
            if length {
                result := add(mload(0x40), 0x20)
                subject := add(subject, 1)
                let flags := shl(add(70, shl(5, toUpper)), 0x3ffffff)
                let w := not(0)
                for { let o := length } 1 {} {
                    o := add(o, w)
                    let b := and(0xff, mload(add(subject, o)))
                    mstore8(add(result, o), xor(b, and(shr(b, flags), 0x20)))
                    if iszero(o) { break }
                }
                result := mload(0x40)
                mstore(result, length) 
                let last := add(add(result, 0x20), length)
                mstore(last, 0) 
                mstore(0x40, add(last, 0x20)) 
            }
        }
    }
    function fromSmallString(bytes32 s) internal pure returns (string memory result) {
        assembly {
            result := mload(0x40)
            let n := 0
            for {} byte(n, s) { n := add(n, 1) } {} 
            mstore(result, n)
            let o := add(result, 0x20)
            mstore(o, s)
            mstore(add(o, n), 0)
            mstore(0x40, add(result, 0x40))
        }
    }
    function normalizeSmallString(bytes32 s) internal pure returns (bytes32 result) {
        assembly {
            for {} byte(result, s) { result := add(result, 1) } {} 
            mstore(0x00, s)
            mstore(result, 0x00)
            result := mload(0x00)
        }
    }
    function toSmallString(string memory s) internal pure returns (bytes32 result) {
        assembly {
            result := mload(s)
            if iszero(lt(result, 33)) {
                mstore(0x00, 0xec92f9a3) 
                revert(0x1c, 0x04)
            }
            result := shl(shl(3, sub(32, result)), mload(add(s, result)))
        }
    }
    function lower(string memory subject) internal pure returns (string memory result) {
        result = toCase(subject, false);
    }
    function upper(string memory subject) internal pure returns (string memory result) {
        result = toCase(subject, true);
    }
    function escapeHTML(string memory s) internal pure returns (string memory result) {
        assembly {
            let end := add(s, mload(s))
            result := add(mload(0x40), 0x20)
            mstore(0x1f, 0x900094)
            mstore(0x08, 0xc0000000a6ab)
            mstore(0x00, shl(64, 0x2671756f743b26616d703b262333393b266c743b2667743b))
            for {} iszero(eq(s, end)) {} {
                s := add(s, 1)
                let c := and(mload(s), 0xff)
                if iszero(and(shl(c, 1), 0x500000c400000000)) {
                    mstore8(result, c)
                    result := add(result, 1)
                    continue
                }
                let t := shr(248, mload(c))
                mstore(result, mload(and(t, 0x1f)))
                result := add(result, shr(5, t))
            }
            let last := result
            mstore(last, 0) 
            result := mload(0x40)
            mstore(result, sub(last, add(result, 0x20))) 
            mstore(0x40, add(last, 0x20)) 
        }
    }
    function escapeJSON(string memory s, bool addDoubleQuotes)
        internal
        pure
        returns (string memory result)
    {
        assembly {
            let end := add(s, mload(s))
            result := add(mload(0x40), 0x20)
            if addDoubleQuotes {
                mstore8(result, 34)
                result := add(1, result)
            }
            mstore(0x15, 0x5c75303030303031323334353637383961626364656662746e006672)
            let e := or(shl(0x22, 1), shl(0x5c, 1))
            for {} iszero(eq(s, end)) {} {
                s := add(s, 1)
                let c := and(mload(s), 0xff)
                if iszero(lt(c, 0x20)) {
                    if iszero(and(shl(c, 1), e)) {
                        mstore8(result, c)
                        result := add(result, 1)
                        continue
                    }
                    mstore8(result, 0x5c) 
                    mstore8(add(result, 1), c)
                    result := add(result, 2)
                    continue
                }
                if iszero(and(shl(c, 1), 0x3700)) {
                    mstore8(0x1d, mload(shr(4, c))) 
                    mstore8(0x1e, mload(and(c, 15))) 
                    mstore(result, mload(0x19)) 
                    result := add(result, 6)
                    continue
                }
                mstore8(result, 0x5c) 
                mstore8(add(result, 1), mload(add(c, 8)))
                result := add(result, 2)
            }
            if addDoubleQuotes {
                mstore8(result, 34)
                result := add(1, result)
            }
            let last := result
            mstore(last, 0) 
            result := mload(0x40)
            mstore(result, sub(last, add(result, 0x20))) 
            mstore(0x40, add(last, 0x20)) 
        }
    }
    function escapeJSON(string memory s) internal pure returns (string memory result) {
        result = escapeJSON(s, false);
    }
    function eq(string memory a, string memory b) internal pure returns (bool result) {
        assembly {
            result := eq(keccak256(add(a, 0x20), mload(a)), keccak256(add(b, 0x20), mload(b)))
        }
    }
    function eqs(string memory a, bytes32 b) internal pure returns (bool result) {
        assembly {
            let m := not(shl(7, div(not(iszero(b)), 255))) 
            let x := not(or(m, or(b, add(m, and(b, m)))))
            let r := shl(7, iszero(iszero(shr(128, x))))
            r := or(r, shl(6, iszero(iszero(shr(64, shr(r, x))))))
            r := or(r, shl(5, lt(0xffffffff, shr(r, x))))
            r := or(r, shl(4, lt(0xffff, shr(r, x))))
            r := or(r, shl(3, lt(0xff, shr(r, x))))
            result := gt(eq(mload(a), add(iszero(x), xor(31, shr(3, r)))),
                xor(shr(add(8, r), b), shr(add(8, r), mload(add(a, 0x20)))))
        }
    }
    function packOne(string memory a) internal pure returns (bytes32 result) {
        assembly {
            result :=
                mul(
                    mload(add(a, 0x1f)),
                    lt(sub(mload(a), 1), 0x1f)
                )
        }
    }
    function unpackOne(bytes32 packed) internal pure returns (string memory result) {
        assembly {
            result := mload(0x40)
            mstore(0x40, add(result, 0x40))
            mstore(result, 0)
            mstore(add(result, 0x1f), packed)
            mstore(add(add(result, 0x20), mload(result)), 0)
        }
    }
    function packTwo(string memory a, string memory b) internal pure returns (bytes32 result) {
        assembly {
            let aLength := mload(a)
            result :=
                mul(
                    or(
                        shl(shl(3, sub(0x1f, aLength)), mload(add(a, aLength))),
                        mload(sub(add(b, 0x1e), aLength))
                    ),
                    lt(sub(add(aLength, mload(b)), 1), 0x1e)
                )
        }
    }
    function unpackTwo(bytes32 packed)
        internal
        pure
        returns (string memory resultA, string memory resultB)
    {
        assembly {
            resultA := mload(0x40)
            resultB := add(resultA, 0x40)
            mstore(0x40, add(resultB, 0x40))
            mstore(resultA, 0)
            mstore(resultB, 0)
            mstore(add(resultA, 0x1f), packed)
            mstore(add(resultB, 0x1f), mload(add(add(resultA, 0x20), mload(resultA))))
            mstore(add(add(resultA, 0x20), mload(resultA)), 0)
            mstore(add(add(resultB, 0x20), mload(resultB)), 0)
        }
    }
    function directReturn(string memory a) internal pure {
        assembly {
            let retStart := sub(a, 0x20)
            let retSize := add(mload(a), 0x40)
            mstore(add(retStart, retSize), 0)
            mstore(retStart, 0x20)
            return(retStart, retSize)
        }
    }
}
pragma solidity ^0.8.25;
interface IERC5192 {
  event Locked(uint256 tokenId);
  event Unlocked(uint256 tokenId);
  function locked(uint256 tokenId) external view returns (bool);
}
pragma solidity ^0.8.25;
interface IN2MCrossFactory {
    function ownerOf(uint256 tokenId) external view returns (address);
    function getIPFSURI(bytes32 cidHash) external pure returns (string memory);
    function transferCollectionOwnership(address to) external payable;
}
pragma solidity ^0.8.4;
library MerkleProofLib {
    function verify(bytes32[] memory proof, bytes32 root, bytes32 leaf)
        internal
        pure
        returns (bool isValid)
    {
        assembly {
            if mload(proof) {
                let offset := add(proof, 0x20)
                let end := add(offset, shl(5, mload(proof)))
                for {} 1 {} {
                    let scratch := shl(5, gt(leaf, mload(offset)))
                    mstore(scratch, leaf)
                    mstore(xor(scratch, 0x20), mload(offset))
                    leaf := keccak256(0x00, 0x40)
                    offset := add(offset, 0x20)
                    if iszero(lt(offset, end)) { break }
                }
            }
            isValid := eq(leaf, root)
        }
    }
    function verifyCalldata(bytes32[] calldata proof, bytes32 root, bytes32 leaf)
        internal
        pure
        returns (bool isValid)
    {
        assembly {
            if proof.length {
                let end := add(proof.offset, shl(5, proof.length))
                let offset := proof.offset
                for {} 1 {} {
                    let scratch := shl(5, gt(leaf, calldataload(offset)))
                    mstore(scratch, leaf)
                    mstore(xor(scratch, 0x20), calldataload(offset))
                    leaf := keccak256(0x00, 0x40)
                    offset := add(offset, 0x20)
                    if iszero(lt(offset, end)) { break }
                }
            }
            isValid := eq(leaf, root)
        }
    }
    function verifyMultiProof(
        bytes32[] memory proof,
        bytes32 root,
        bytes32[] memory leaves,
        bool[] memory flags
    ) internal pure returns (bool isValid) {
        assembly {
            let leavesLength := mload(leaves)
            let proofLength := mload(proof)
            let flagsLength := mload(flags)
            leaves := add(0x20, leaves)
            proof := add(0x20, proof)
            flags := add(0x20, flags)
            for {} eq(add(leavesLength, proofLength), add(flagsLength, 1)) {} {
                if iszero(flagsLength) {
                    isValid := eq(mload(xor(leaves, mul(xor(proof, leaves), proofLength))), root)
                    break
                }
                let proofEnd := add(proof, shl(5, proofLength))
                let hashesFront := mload(0x40)
                leavesLength := shl(5, leavesLength)
                for { let i := 0 } iszero(eq(i, leavesLength)) { i := add(i, 0x20) } {
                    mstore(add(hashesFront, i), mload(add(leaves, i)))
                }
                let hashesBack := add(hashesFront, leavesLength)
                flagsLength := add(hashesBack, shl(5, flagsLength))
                for {} 1 {} {
                    let a := mload(hashesFront)
                    let b := mload(add(hashesFront, 0x20))
                    hashesFront := add(hashesFront, 0x40)
                    if iszero(mload(flags)) {
                        b := mload(proof)
                        proof := add(proof, 0x20)
                        hashesFront := sub(hashesFront, 0x20)
                    }
                    flags := add(flags, 0x20)
                    let scratch := shl(5, gt(a, b))
                    mstore(scratch, a)
                    mstore(xor(scratch, 0x20), b)
                    mstore(hashesBack, keccak256(0x00, 0x40))
                    hashesBack := add(hashesBack, 0x20)
                    if iszero(lt(hashesBack, flagsLength)) { break }
                }
                isValid :=
                    and(
                        eq(mload(sub(hashesBack, 0x20)), root),
                        eq(proofEnd, proof)
                    )
                break
            }
        }
    }
    function verifyMultiProofCalldata(
        bytes32[] calldata proof,
        bytes32 root,
        bytes32[] calldata leaves,
        bool[] calldata flags
    ) internal pure returns (bool isValid) {
        assembly {
            for {} eq(add(leaves.length, proof.length), add(flags.length, 1)) {} {
                if iszero(flags.length) {
                    isValid := eq(
                        calldataload(
                            xor(leaves.offset, mul(xor(proof.offset, leaves.offset), proof.length))
                        ),
                        root
                    )
                    break
                }
                let proofEnd := add(proof.offset, shl(5, proof.length))
                let hashesFront := mload(0x40)
                calldatacopy(hashesFront, leaves.offset, shl(5, leaves.length))
                let hashesBack := add(hashesFront, shl(5, leaves.length))
                flags.length := add(hashesBack, shl(5, flags.length))
                for {} 1 {} {
                    let a := mload(hashesFront)
                    let b := mload(add(hashesFront, 0x20))
                    hashesFront := add(hashesFront, 0x40)
                    if iszero(calldataload(flags.offset)) {
                        b := calldataload(proof.offset)
                        proof.offset := add(proof.offset, 0x20)
                        hashesFront := sub(hashesFront, 0x20)
                    }
                    flags.offset := add(flags.offset, 0x20)
                    let scratch := shl(5, gt(a, b))
                    mstore(scratch, a)
                    mstore(xor(scratch, 0x20), b)
                    mstore(hashesBack, keccak256(0x00, 0x40))
                    hashesBack := add(hashesBack, 0x20)
                    if iszero(lt(hashesBack, flags.length)) { break }
                }
                isValid :=
                    and(
                        eq(mload(sub(hashesBack, 0x20)), root),
                        eq(proofEnd, proof.offset)
                    )
                break
            }
        }
    }
    function emptyProof() internal pure returns (bytes32[] calldata proof) {
        assembly {
            proof.length := 0
        }
    }
    function emptyLeaves() internal pure returns (bytes32[] calldata leaves) {
        assembly {
            leaves.length := 0
        }
    }
    function emptyFlags() internal pure returns (bool[] calldata flags) {
        assembly {
            flags.length := 0
        }
    }
}
