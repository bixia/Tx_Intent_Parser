// SPDX-License-Identifier: BSL 1.1 - Blend (c) Non Fungible Trading Ltd.
pragma solidity 0.8.17;

import "./Structs.sol";
import "./Errors.sol";
import "../interfaces/ISignatures.sol";

abstract contract Signatures is ISignatures {
    bytes32 private immutable _LOAN_OFFER_TYPEHASH;
    bytes32 private immutable _FEE_TYPEHASH;
    bytes32 private immutable _SELL_OFFER_TYPEHASH;
    bytes32 private immutable _ORACLE_OFFER_TYPEHASH;
    bytes32 private immutable _EIP_712_DOMAIN_TYPEHASH;

    string private constant _NAME = "Blend";
    string private constant _VERSION = "1.0";

    mapping(address => uint256) public nonces;
    mapping(address => uint256) public oracles;
    uint256 public blockRange;

    uint256[50] private _gap;

    constructor() {
        (
            _LOAN_OFFER_TYPEHASH,
            _SELL_OFFER_TYPEHASH,
            _FEE_TYPEHASH,
            _ORACLE_OFFER_TYPEHASH,
            _EIP_712_DOMAIN_TYPEHASH
        ) = _createTypehashes();
    }

    function information() external view returns (string memory version, bytes32 domainSeparator) {
        version = _VERSION;
        domainSeparator = _hashDomain(
            _EIP_712_DOMAIN_TYPEHASH,
            keccak256(bytes(_NAME)),
            keccak256(bytes(_VERSION))
        );
    }

    function getSellOfferHash(SellOffer calldata offer) external view returns (bytes32) {
        return _hashSellOffer(offer);
    }

    function getOfferHash(LoanOffer calldata offer) external view returns (bytes32) {
        return _hashOffer(offer);
    }

    function getOracleOfferHash(bytes32 hash, uint256 blockNumber) external view returns (bytes32) {
        return _hashOracleOffer(hash, blockNumber);
    }

    /**
     * @notice Generate all EIP712 Typehashes
     */
    function _createTypehashes()
        internal
        view
        returns (
            bytes32 loanOfferTypehash,
            bytes32 sellOfferTypehash,
            bytes32 feeTypehash,
            bytes32 oracleOfferTypehash,
            bytes32 eip712DomainTypehash
        )
    {
        eip712DomainTypehash = keccak256(
            bytes.concat(
                "EIP712Domain(",
                "string name,",
                "string version,",
                "uint256 chainId,",
                "address verifyingContract",
                ")"
            )
        );

        oracleOfferTypehash = keccak256(
            bytes.concat("OracleOffer(", "bytes32 hash,", "uint256 blockNumber", ")")
        );

        loanOfferTypehash = keccak256(
            bytes.concat(
                "LoanOffer(",
                "address lender,",
                "address collection,",
                "uint256 totalAmount,",
                "uint256 minAmount,",
                "uint256 maxAmount,",
                "uint256 auctionDuration,",
                "uint256 salt,",
                "uint256 expirationTime,",
                "uint256 rate,",
                "address oracle,",
                "uint256 nonce",
                ")"
            )
        );

        bytes memory feeTypestring = bytes.concat("Fee(", "uint16 rate,", "address recipient", ")");

        feeTypehash = keccak256(feeTypestring);
        sellOfferTypehash = keccak256(
            bytes.concat(
                "SellOffer(",
                "address borrower,",
                "uint256 lienId,",
                "uint256 price,",
                "uint256 expirationTime,",
                "uint256 salt,",
                "address oracle,",
                "Fee[] fees,",
                "uint256 nonce",
                ")",
                feeTypestring
            )
        );
    }

    function _hashDomain(
        bytes32 eip712DomainTypehash,
        bytes32 nameHash,
        bytes32 versionHash
    ) internal view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    eip712DomainTypehash,
                    nameHash,
                    versionHash,
                    block.chainid,
                    address(this)
                )
            );
    }

    function _hashFee(Fee calldata fee) internal view returns (bytes32) {
        return keccak256(abi.encode(_FEE_TYPEHASH, fee.rate, fee.recipient));
    }

    function _packFees(Fee[] calldata fees) internal view returns (bytes32) {
        bytes32[] memory feeHashes = new bytes32[](fees.length);
        uint256 feesLength = fees.length;
        for (uint256 i; i < feesLength; ) {
            feeHashes[i] = _hashFee(fees[i]);
            unchecked {
                ++i;
            }
        }
        return keccak256(abi.encodePacked(feeHashes));
    }

    function _hashSellOffer(SellOffer calldata offer) internal view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    _SELL_OFFER_TYPEHASH,
                    offer.borrower,
                    offer.lienId,
                    offer.price,
                    offer.expirationTime,
                    offer.salt,
                    offer.oracle,
                    _packFees(offer.fees),
                    nonces[offer.borrower]
                )
            );
    }

    function _hashOffer(LoanOffer calldata offer) internal view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    _LOAN_OFFER_TYPEHASH,
                    offer.lender,
                    offer.collection,
                    offer.totalAmount,
                    offer.minAmount,
                    offer.maxAmount,
                    offer.auctionDuration,
                    offer.salt,
                    offer.expirationTime,
                    offer.rate,
                    offer.oracle,
                    nonces[offer.lender]
                )
            );
    }

    function _hashOracleOffer(bytes32 hash, uint256 blockNumber) internal view returns (bytes32) {
        return keccak256(abi.encode(_ORACLE_OFFER_TYPEHASH, hash, blockNumber));
    }

    function _hashToSign(bytes32 hash) internal view returns (bytes32) {
        return keccak256(
            bytes.concat(
                bytes2(0x1901),
                _hashDomain(
                    _EIP_712_DOMAIN_TYPEHASH,
                    keccak256(bytes(_NAME)),
                    keccak256(bytes(_VERSION))
                ),
                hash
            )
        );
    }

    function _hashToSignOracle(bytes32 hash, uint256 blockNumber) internal view returns (bytes32) {
        return
            keccak256(
                bytes.concat(
                    bytes2(0x1901),
                    _hashDomain(
                        _EIP_712_DOMAIN_TYPEHASH,
                        keccak256(bytes(_NAME)),
                        keccak256(bytes(_VERSION))
                    ),
                    _hashOracleOffer(hash, blockNumber)
                )
            );
    }

    /**
     * @notice Verify authorization of offer
     * @param offerHash Hash of offer struct
     * @param lender Lender address
     * @param oracle Oracle address
     * @param signature Packed offer signature (with oracle signature if necessary)
     */
    function _verifyOfferAuthorization(
        bytes32 offerHash,
        address lender,
        address oracle,
        bytes calldata signature
    ) internal view {
        bytes32 hashToSign = _hashToSign(offerHash);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 0x20))
            v := shr(248, calldataload(add(signature.offset, 0x40)))
        }
        _verify(lender, hashToSign, v, r, s);

        /* Verify oracle signature if required. */
        if (oracle != address(0)) {
            uint256 blockNumber;
            assembly {
                r := calldataload(add(signature.offset, 0x41))
                s := calldataload(add(signature.offset, 0x61))
                v := shr(248, calldataload(add(signature.offset, 0x81)))
                blockNumber := calldataload(add(signature.offset, 0x82))
            }
            if (oracles[oracle] == 0) {
                revert UnauthorizedOracle();
            }
            if (blockNumber + blockRange < block.number) {
                revert SignatureExpired();
            }

            hashToSign = _hashToSignOracle(offerHash, blockNumber);
            _verify(oracle, hashToSign, v, r, s);
        }
    }

    /**
     * @notice Verify signature of digest
     * @param signer Address of expected signer
     * @param digest Signature digest
     * @param v v parameter
     * @param r r parameter
     * @param s s parameter
     */
    function _verify(address signer, bytes32 digest, uint8 v, bytes32 r, bytes32 s) internal pure {
        if (v != 27 && v != 28) {
            revert InvalidVParameter();
        }
        address recoveredSigner = ecrecover(digest, v, r, s);
        if (recoveredSigner == address(0) || signer != recoveredSigner) {
            revert InvalidSignature();
        }
    }
}

// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

/// @notice Signed 18 decimal fixed point (wad) arithmetic library.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/utils/SignedWadMath.sol)
/// @author Modified from Remco Bloemen (https://xn--2-umb.com/22/exp-ln/index.html)

/// @dev Will not revert on overflow, only use where overflow is not possible.
function toWadUnsafe(uint256 x) pure returns (int256 r) {
    /// @solidity memory-safe-assembly
    assembly {
        // Multiply x by 1e18.
        r := mul(x, 1000000000000000000)
    }
}

/// @dev Takes an integer amount of seconds and converts it to a wad amount of days.
/// @dev Will not revert on overflow, only use where overflow is not possible.
/// @dev Not meant for negative second amounts, it assumes x is positive.
function toDaysWadUnsafe(uint256 x) pure returns (int256 r) {
    /// @solidity memory-safe-assembly
    assembly {
        // Multiply x by 1e18 and then divide it by 86400.
        r := div(mul(x, 1000000000000000000), 86400)
    }
}

/// @dev Takes a wad amount of days and converts it to an integer amount of seconds.
/// @dev Will not revert on overflow, only use where overflow is not possible.
/// @dev Not meant for negative day amounts, it assumes x is positive.
function fromDaysWadUnsafe(int256 x) pure returns (uint256 r) {
    /// @solidity memory-safe-assembly
    assembly {
        // Multiply x by 86400 and then divide it by 1e18.
        r := div(mul(x, 86400), 1000000000000000000)
    }
}

/// @dev Will not revert on overflow, only use where overflow is not possible.
function unsafeWadMul(int256 x, int256 y) pure returns (int256 r) {
    /// @solidity memory-safe-assembly
    assembly {
        // Multiply x by y and divide by 1e18.
        r := sdiv(mul(x, y), 1000000000000000000)
    }
}

/// @dev Will return 0 instead of reverting if y is zero and will
/// not revert on overflow, only use where overflow is not possible.
function unsafeWadDiv(int256 x, int256 y) pure returns (int256 r) {
    /// @solidity memory-safe-assembly
    assembly {
        // Multiply x by 1e18 and divide it by y.
        r := sdiv(mul(x, 1000000000000000000), y)
    }
}

function wadMul(int256 x, int256 y) pure returns (int256 r) {
    /// @solidity memory-safe-assembly
    assembly {
        // Store x * y in r for now.
        r := mul(x, y)

        // Equivalent to require(x == 0 || (x * y) / x == y)
        if iszero(or(iszero(x), eq(sdiv(r, x), y))) {
            revert(0, 0)
        }

        // Scale the result down by 1e18.
        r := sdiv(r, 1000000000000000000)
    }
}

function wadDiv(int256 x, int256 y) pure returns (int256 r) {
    /// @solidity memory-safe-assembly
    assembly {
        // Store x * 1e18 in r for now.
        r := mul(x, 1000000000000000000)

        // Equivalent to require(y != 0 && ((x * 1e18) / 1e18 == x))
        if iszero(and(iszero(iszero(y)), eq(sdiv(r, 1000000000000000000), x))) {
            revert(0, 0)
        }

        // Divide r by y.
        r := sdiv(r, y)
    }
}

/// @dev Will not work with negative bases, only use when x is positive.
function wadPow(int256 x, int256 y) pure returns (int256) {
    // Equivalent to x to the power of y because x ** y = (e ** ln(x)) ** y = e ** (ln(x) * y)
    return wadExp((wadLn(x) * y) / 1e18); // Using ln(x) means x must be greater than 0.
}

function wadExp(int256 x) pure returns (int256 r) {
    unchecked {
        // When the result is < 0.5 we return zero. This happens when
        // x <= floor(log(0.5e18) * 1e18) ~ -42e18
        if (x <= -42139678854452767551) return 0;

        // When the result is > (2**255 - 1) / 1e18 we can not represent it as an
        // int. This happens when x >= floor(log((2**255 - 1) / 1e18) * 1e18) ~ 135.
        if (x >= 135305999368893231589) revert("EXP_OVERFLOW");

        // x is now in the range (-42, 136) * 1e18. Convert to (-42, 136) * 2**96
        // for more intermediate precision and a binary basis. This base conversion
        // is a multiplication by 1e18 / 2**96 = 5**18 / 2**78.
        x = (x << 78) / 5**18;

        // Reduce range of x to (-½ ln 2, ½ ln 2) * 2**96 by factoring out powers
        // of two such that exp(x) = exp(x') * 2**k, where k is an integer.
        // Solving this gives k = round(x / log(2)) and x' = x - k * log(2).
        int256 k = ((x << 96) / 54916777467707473351141471128 + 2**95) >> 96;
        x = x - k * 54916777467707473351141471128;

        // k is in the range [-61, 195].

        // Evaluate using a (6, 7)-term rational approximation.
        // p is made monic, we'll multiply by a scale factor later.
        int256 y = x + 1346386616545796478920950773328;
        y = ((y * x) >> 96) + 57155421227552351082224309758442;
        int256 p = y + x - 94201549194550492254356042504812;
        p = ((p * y) >> 96) + 28719021644029726153956944680412240;
        p = p * x + (4385272521454847904659076985693276 << 96);

        // We leave p in 2**192 basis so we don't need to scale it back up for the division.
        int256 q = x - 2855989394907223263936484059900;
        q = ((q * x) >> 96) + 50020603652535783019961831881945;
        q = ((q * x) >> 96) - 533845033583426703283633433725380;
        q = ((q * x) >> 96) + 3604857256930695427073651918091429;
        q = ((q * x) >> 96) - 14423608567350463180887372962807573;
        q = ((q * x) >> 96) + 26449188498355588339934803723976023;

        /// @solidity memory-safe-assembly
        assembly {
            // Div in assembly because solidity adds a zero check despite the unchecked.
            // The q polynomial won't have zeros in the domain as all its roots are complex.
            // No scaling is necessary because p is already 2**96 too large.
            r := sdiv(p, q)
        }

        // r should be in the range (0.09, 0.25) * 2**96.

        // We now need to multiply r by:
        // * the scale factor s = ~6.031367120.
        // * the 2**k factor from the range reduction.
        // * the 1e18 / 2**96 factor for base conversion.
        // We do this all at once, with an intermediate result in 2**213
        // basis, so the final right shift is always by a positive amount.
        r = int256((uint256(r) * 3822833074963236453042738258902158003155416615667) >> uint256(195 - k));
    }
}

function wadLn(int256 x) pure returns (int256 r) {
    unchecked {
        require(x > 0, "UNDEFINED");

        // We want to convert x from 10**18 fixed point to 2**96 fixed point.
        // We do this by multiplying by 2**96 / 10**18. But since
        // ln(x * C) = ln(x) + ln(C), we can simply do nothing here
        // and add ln(2**96 / 10**18) at the end.

        /// @solidity memory-safe-assembly
        assembly {
            r := shl(7, lt(0xffffffffffffffffffffffffffffffff, x))
            r := or(r, shl(6, lt(0xffffffffffffffff, shr(r, x))))
            r := or(r, shl(5, lt(0xffffffff, shr(r, x))))
            r := or(r, shl(4, lt(0xffff, shr(r, x))))
            r := or(r, shl(3, lt(0xff, shr(r, x))))
            r := or(r, shl(2, lt(0xf, shr(r, x))))
            r := or(r, shl(1, lt(0x3, shr(r, x))))
            r := or(r, lt(0x1, shr(r, x)))
        }

        // Reduce range of x to (1, 2) * 2**96
        // ln(2^k * x) = k * ln(2) + ln(x)
        int256 k = r - 96;
        x <<= uint256(159 - k);
        x = int256(uint256(x) >> 159);

        // Evaluate using a (8, 8)-term rational approximation.
        // p is made monic, we will multiply by a scale factor later.
        int256 p = x + 3273285459638523848632254066296;
        p = ((p * x) >> 96) + 24828157081833163892658089445524;
        p = ((p * x) >> 96) + 43456485725739037958740375743393;
        p = ((p * x) >> 96) - 11111509109440967052023855526967;
        p = ((p * x) >> 96) - 45023709667254063763336534515857;
        p = ((p * x) >> 96) - 14706773417378608786704636184526;
        p = p * x - (795164235651350426258249787498 << 96);

        // We leave p in 2**192 basis so we don't need to scale it back up for the division.
        // q is monic by convention.
        int256 q = x + 5573035233440673466300451813936;
        q = ((q * x) >> 96) + 71694874799317883764090561454958;
        q = ((q * x) >> 96) + 283447036172924575727196451306956;
        q = ((q * x) >> 96) + 401686690394027663651624208769553;
        q = ((q * x) >> 96) + 204048457590392012362485061816622;
        q = ((q * x) >> 96) + 31853899698501571402653359427138;
        q = ((q * x) >> 96) + 909429971244387300277376558375;
        /// @solidity memory-safe-assembly
        assembly {
            // Div in assembly because solidity adds a zero check despite the unchecked.
            // The q polynomial is known not to have zeros in the domain.
            // No scaling required because p is already 2**96 too large.
            r := sdiv(p, q)
        }

        // r is in the range (0, 0.125) * 2**96

        // Finalization, we need to:
        // * multiply by the scale factor s = 5.549…
        // * add ln(2**96 / 10**18)
        // * add k * ln(2)
        // * multiply by 10**18 / 2**96 = 5**18 >> 78

        // mul s * 5e18 * 2**96, base is now 5**18 * 2**192
        r *= 1677202110996718588342820967067443963516166;
        // add ln(2) * k * 5e18 * 2**192
        r += 16597577552685614221487285958193947469193820559219878177908093499208371 * k;
        // add ln(2**96 / 10**18) * 5e18 * 2**192
        r += 600920179829731861736702779321621459595472258049074101567377883020018308;
        // base conversion: mul 2**18 / 2**192
        r >>= 174;
    }
}

/// @dev Will return 0 instead of reverting if y is zero.
function unsafeDiv(int256 x, int256 y) pure returns (int256 r) {
    /// @solidity memory-safe-assembly
    assembly {
        // Divide x by y.
        r := sdiv(x, y)
    }
}

// SPDX-License-Identifier: BSL 1.1 - Blend (c) Non Fungible Trading Ltd.
pragma solidity 0.8.17;

import "lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";

import "./Helpers.sol";
import "./lib/Structs.sol";
import "./OfferController.sol";
import "./interfaces/IBlend.sol";
import "../pool/interfaces/IBlurPool.sol";

contract Blend is IBlend, OfferController, UUPSUpgradeable {
    IExchange private immutable _EXCHANGE;
    IExchangeV2 private immutable _EXCHANGE_V2;
    IBlurPool private immutable _POOL;
    address private immutable _SELL_MATCHING_POLICY;
    address private immutable _BID_MATCHING_POLICY;
    address private immutable _DELEGATE;
    address private immutable _DELEGATE_V2;

    uint256 private constant _BASIS_POINTS = 10_000;
    uint256 private constant _MAX_AUCTION_DURATION = 432_000;
    uint256 private constant _LIQUIDATION_THRESHOLD = 100_000;
    uint256 private _nextLienId;

    mapping(uint256 => bytes32) public liens;
    mapping(bytes32 => uint256) public amountTaken;

    // required by the OZ UUPS module
    function _authorizeUpgrade(address) internal override onlyOwner {}

    constructor(
        address pool,
        address exchange,
        address exchangeV2,
        address sellMatchingPolicy,
        address bidMatchingPolicy,
        address delegate,
        address delegateV2
    ) {
        _POOL = IBlurPool(pool);
        _EXCHANGE = IExchange(exchange);
        _EXCHANGE_V2 = IExchangeV2(exchangeV2);
        _SELL_MATCHING_POLICY = sellMatchingPolicy;
        _BID_MATCHING_POLICY = bidMatchingPolicy;
        _DELEGATE = delegate;
        _DELEGATE_V2 = delegateV2;
        _disableInitializers();
    }

    function initialize() external initializer {
        __UUPSUpgradeable_init();
        __Ownable_init();
    }

    /*//////////////////////////////////////////////////
                    BORROW FLOWS
    //////////////////////////////////////////////////*/

    /**
     * @notice Verifies and takes loan offer; then transfers loan and collateral assets
     * @param offer Loan offer
     * @param signature Lender offer signature
     * @param loanAmount Loan amount in ETH
     * @param collateralTokenId Token id to provide as collateral
     * @return lienId New lien id
     */
    function borrow(
        LoanOffer calldata offer,
        bytes calldata signature,
        uint256 loanAmount,
        uint256 collateralTokenId
    ) external returns (uint256 lienId) {
        lienId = _borrow(offer, signature, loanAmount, collateralTokenId);

        /* Lock collateral token. */
        offer.collection.safeTransferFrom(msg.sender, address(this), collateralTokenId);

        /* Transfer loan to borrower. */
        _POOL.transferFrom(offer.lender, msg.sender, loanAmount);
    }

    /**
     * @notice Repays loan and retrieves collateral
     * @param lien Lien preimage
     * @param lienId Lien id
     */
    function repay(
        Lien calldata lien,
        uint256 lienId
    ) external validateLien(lien, lienId) lienIsActive(lien) {
        uint256 debt = _repay(lien, lienId);

        /* Return NFT to borrower. */
        lien.collection.safeTransferFrom(address(this), lien.borrower, lien.tokenId);

        /* Repay loan to lender. */
        _POOL.transferFrom(msg.sender, lien.lender, debt);
    }

    /**
     * @notice Verifies and takes loan offer; creates new lien
     * @param offer Loan offer
     * @param signature Lender offer signature
     * @param loanAmount Loan amount in ETH
     * @param collateralTokenId Token id to provide as collateral
     * @return lienId New lien id
     */
    function _borrow(
        LoanOffer calldata offer,
        bytes calldata signature,
        uint256 loanAmount,
        uint256 collateralTokenId
    ) internal returns (uint256 lienId) {
        if (offer.auctionDuration > _MAX_AUCTION_DURATION) {
            revert InvalidAuctionDuration();
        }

        Lien memory lien = Lien({
            lender: offer.lender,
            borrower: msg.sender,
            collection: offer.collection,
            tokenId: collateralTokenId,
            amount: loanAmount,
            startTime: block.timestamp,
            rate: offer.rate,
            auctionStartBlock: 0,
            auctionDuration: offer.auctionDuration
        });

        /* Create lien. */
        unchecked {
            liens[lienId = _nextLienId++] = keccak256(abi.encode(lien));
        }

        /* Take the loan offer. */
        _takeLoanOffer(offer, signature, lien, lienId);
    }

    /**
     * @notice Computes the current debt repayment and burns the lien
     * @dev Does not transfer assets
     * @param lien Lien preimage
     * @param lienId Lien id
     * @return debt Current amount of debt owed on the lien
     */
    function _repay(Lien calldata lien, uint256 lienId) internal returns (uint256 debt) {
        debt = Helpers.computeCurrentDebt(lien.amount, lien.rate, lien.startTime);

        delete liens[lienId];

        emit Repay(lienId, address(lien.collection));
    }

    /**
     * @notice Verifies and takes loan offer
     * @dev Does not transfer loan and collateral assets; does not update lien hash
     * @param offer Loan offer
     * @param signature Lender offer signature
     * @param lien Lien preimage
     * @param lienId Lien id
     */
    function _takeLoanOffer(
        LoanOffer calldata offer,
        bytes calldata signature,
        Lien memory lien,
        uint256 lienId
    ) internal {
        bytes32 hash = _hashOffer(offer);

        _validateOffer(
            hash,
            offer.lender,
            offer.oracle,
            signature,
            offer.expirationTime,
            offer.salt
        );

        if (offer.rate > _LIQUIDATION_THRESHOLD) {
            revert RateTooHigh();
        }
        if (lien.amount > offer.maxAmount || lien.amount < offer.minAmount) {
            revert InvalidLoan();
        }
        uint256 _amountTaken = amountTaken[hash];
        if (offer.totalAmount - _amountTaken < lien.amount) {
            revert InsufficientOffer();
        }

        unchecked {
            amountTaken[hash] = _amountTaken + lien.amount;
        }

        emit LoanOfferTaken(
            hash,
            lienId,
            address(offer.collection),
            lien.lender,
            lien.borrower,
            lien.amount,
            lien.rate,
            lien.tokenId,
            lien.auctionDuration
        );
    }

    /*//////////////////////////////////////////////////
                    REFINANCING FLOWS
    //////////////////////////////////////////////////*/

    /**
     * @notice Starts Dutch Auction on lien ownership
     * @dev Must be called by lien owner
     * @param lienId Lien token id
     */
    function startAuction(Lien calldata lien, uint256 lienId) external validateLien(lien, lienId) {
        if (msg.sender != lien.lender) {
            revert Unauthorized();
        }

        /* Cannot start if auction has already started. */
        if (lien.auctionStartBlock != 0) {
            revert AuctionIsActive();
        }

        /* Add auction start block to lien. */
        liens[lienId] = keccak256(
            abi.encode(
                Lien({
                    lender: lien.lender,
                    borrower: lien.borrower,
                    collection: lien.collection,
                    tokenId: lien.tokenId,
                    amount: lien.amount,
                    startTime: lien.startTime,
                    rate: lien.rate,
                    auctionStartBlock: block.number,
                    auctionDuration: lien.auctionDuration
                })
            )
        );

        emit StartAuction(lienId, address(lien.collection));
    }

    /**
     * @notice Seizes collateral from defaulted lien, skipping liens that are not defaulted
     * @param lienPointers List of lien, lienId pairs
     */
    function seize(LienPointer[] calldata lienPointers) external {
        uint256 length = lienPointers.length;
        for (uint256 i; i < length; ) {
            Lien calldata lien = lienPointers[i].lien;
            uint256 lienId = lienPointers[i].lienId;

            if (msg.sender != lien.lender) {
                revert Unauthorized();
            }
            if (!_validateLien(lien, lienId)) {
                revert InvalidLien();
            }

            /* Check that the auction has ended and lien is defaulted. */
            if (_lienIsDefaulted(lien)) {
                delete liens[lienId];

                /* Seize collateral to lender. */
                lien.collection.safeTransferFrom(address(this), lien.lender, lien.tokenId);

                emit Seize(lienId, address(lien.collection));
            }

            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Refinances to different loan amount and repays previous loan
     * @dev Must be called by lender; previous loan must be repaid with interest
     * @param lien Lien struct
     * @param lienId Lien id
     * @param offer Loan offer
     * @param signature Offer signatures
     */
    function refinance(
        Lien calldata lien,
        uint256 lienId,
        LoanOffer calldata offer,
        bytes calldata signature
    ) external validateLien(lien, lienId) lienIsActive(lien) {
        if (msg.sender != lien.lender) {
            revert Unauthorized();
        }

        /* Interest rate must be at least as good as current. */
        if (offer.rate > lien.rate || offer.auctionDuration != lien.auctionDuration) {
            revert InvalidRefinance();
        }

        uint256 debt = Helpers.computeCurrentDebt(lien.amount, lien.rate, lien.startTime);

        _refinance(lien, lienId, debt, offer, signature);

        /* Repay initial loan. */
        _POOL.transferFrom(offer.lender, lien.lender, debt);
    }

    /**
     * @notice Refinance lien in auction at the current debt amount where the interest rate ceiling increases over time
     * @dev Interest rate must be lower than the interest rate ceiling
     * @param lien Lien struct
     * @param lienId Lien token id
     * @param rate Interest rate (in bips)
     * @dev Formula: https://www.desmos.com/calculator/urasr71dhb
     */
    function refinanceAuction(
        Lien calldata lien,
        uint256 lienId,
        uint256 rate
    ) external validateLien(lien, lienId) auctionIsActive(lien) {
        /* Rate must be below current rate limit. */
        uint256 rateLimit = Helpers.calcRefinancingAuctionRate(
            lien.auctionStartBlock,
            lien.auctionDuration,
            lien.rate
        );
        if (rate > rateLimit) {
            revert RateTooHigh();
        }

        uint256 debt = Helpers.computeCurrentDebt(lien.amount, lien.rate, lien.startTime);

        /* Reset the lien with the new lender and interest rate. */
        liens[lienId] = keccak256(
            abi.encode(
                Lien({
                    lender: msg.sender, // set new lender
                    borrower: lien.borrower,
                    collection: lien.collection,
                    tokenId: lien.tokenId,
                    amount: debt, // new loan begins with previous debt
                    startTime: block.timestamp,
                    rate: rate,
                    auctionStartBlock: 0, // close the auction
                    auctionDuration: lien.auctionDuration
                })
            )
        );

        emit Refinance(
            lienId,
            address(lien.collection),
            msg.sender,
            debt,
            rate,
            lien.auctionDuration
        );

        /* Repay the initial loan. */
        _POOL.transferFrom(msg.sender, lien.lender, debt);
    }

    /**
     * @notice Refinances to different loan amount and repays previous loan
     * @param lien Lien struct
     * @param lienId Lien id
     * @param offer Loan offer
     * @param signature Offer signatures
     */
    function refinanceAuctionByOther(
        Lien calldata lien,
        uint256 lienId,
        LoanOffer calldata offer,
        bytes calldata signature
    ) external validateLien(lien, lienId) auctionIsActive(lien) {
        /* Rate must be below current rate limit and auction duration must be the same. */
        uint256 rateLimit = Helpers.calcRefinancingAuctionRate(
            lien.auctionStartBlock,
            lien.auctionDuration,
            lien.rate
        );
        if (offer.rate > rateLimit || offer.auctionDuration != lien.auctionDuration) {
            revert InvalidRefinance();
        }

        uint256 debt = Helpers.computeCurrentDebt(lien.amount, lien.rate, lien.startTime);

        _refinance(lien, lienId, debt, offer, signature);

        /* Repay initial loan. */
        _POOL.transferFrom(offer.lender, lien.lender, debt);
    }

    /**
     * @notice Refinances to different loan amount and repays previous loan
     * @dev Must be called by borrower; previous loan must be repaid with interest
     * @param lien Lien struct
     * @param lienId Lien id
     * @param loanAmount New loan amount
     * @param offer Loan offer
     * @param signature Offer signatures
     */
    function borrowerRefinance(
        Lien calldata lien,
        uint256 lienId,
        uint256 loanAmount,
        LoanOffer calldata offer,
        bytes calldata signature
    ) external validateLien(lien, lienId) lienIsActive(lien) {
        if (msg.sender != lien.borrower) {
            revert Unauthorized();
        }
        if (offer.auctionDuration > _MAX_AUCTION_DURATION) {
            revert InvalidAuctionDuration();
        }

        _refinance(lien, lienId, loanAmount, offer, signature);

        uint256 debt = Helpers.computeCurrentDebt(lien.amount, lien.rate, lien.startTime);

        if (loanAmount >= debt) {
            /* If new loan is more than the previous, repay the initial loan and send the remaining to the borrower. */
            _POOL.transferFrom(offer.lender, lien.lender, debt);
            unchecked {
                _POOL.transferFrom(offer.lender, lien.borrower, loanAmount - debt);
            }
        } else {
            /* If new loan is less than the previous, borrower must supply the difference to repay the initial loan. */
            _POOL.transferFrom(offer.lender, lien.lender, loanAmount);
            unchecked {
                _POOL.transferFrom(lien.borrower, lien.lender, debt - loanAmount);
            }
        }
    }

    function _refinance(
        Lien calldata lien,
        uint256 lienId,
        uint256 loanAmount,
        LoanOffer calldata offer,
        bytes calldata signature
    ) internal {
        if (lien.collection != offer.collection) {
            revert CollectionsDoNotMatch();
        }

        /* Update lien with new loan details. */
        Lien memory newLien = Lien({
            lender: offer.lender, // set new lender
            borrower: lien.borrower,
            collection: lien.collection,
            tokenId: lien.tokenId,
            amount: loanAmount,
            startTime: block.timestamp,
            rate: offer.rate,
            auctionStartBlock: 0, // close the auction
            auctionDuration: offer.auctionDuration
        });
        liens[lienId] = keccak256(abi.encode(newLien));

        /* Take the loan offer. */
        _takeLoanOffer(offer, signature, newLien, lienId);

        emit Refinance(
            lienId,
            address(offer.collection),
            offer.lender,
            loanAmount,
            offer.rate,
            offer.auctionDuration
        );
    }

    /*/////////////////////////////////////////////////////////////
                          MARKETPLACE FLOWS
    /////////////////////////////////////////////////////////////*/

    /**
     * @notice Purchase an NFT and use as collateral for a loan
     * @param offer Loan offer to take
     * @param signature Lender offer signature
     * @param loanAmount Loan amount in ETH
     * @param execution Marketplace execution data
     * @return lienId Lien id
     */
    function buyToBorrow(
        LoanOffer calldata offer,
        bytes calldata signature,
        uint256 loanAmount,
        ExecutionV1 calldata execution
    ) public returns (uint256 lienId) {
        if (execution.makerOrder.order.trader == address(this)) {
            revert Unauthorized();
        }
        if (offer.auctionDuration > _MAX_AUCTION_DURATION) {
            revert InvalidAuctionDuration();
        }

        uint256 collateralTokenId = execution.makerOrder.order.tokenId;
        uint256 price = execution.makerOrder.order.price;

        /* Create lien. */
        Lien memory lien = Lien({
            lender: offer.lender,
            borrower: msg.sender,
            collection: offer.collection,
            tokenId: collateralTokenId,
            amount: loanAmount,
            startTime: block.timestamp,
            rate: offer.rate,
            auctionStartBlock: 0,
            auctionDuration: offer.auctionDuration
        });
        unchecked {
            liens[lienId = _nextLienId++] = keccak256(abi.encode(lien));
        }

        /* Take the loan offer. */
        _takeLoanOffer(offer, signature, lien, lienId);

        /* Create the buy side order coming from Blend. */
        Helpers.executeTakeAsk(
            offer,
            execution,
            loanAmount,
            collateralTokenId,
            price,
            _POOL,
            _EXCHANGE,
            _SELL_MATCHING_POLICY
        );
    }

    function buyToBorrowV2(
        LoanOffer calldata offer,
        bytes calldata signature,
        uint256 loanAmount,
        AskExecutionV2 calldata execution
    ) public returns (uint256 lienId) {
        if (offer.auctionDuration > _MAX_AUCTION_DURATION) {
            revert InvalidAuctionDuration();
        }

        uint256 collateralTokenId = execution.listing.tokenId;
        uint256 price = execution.listing.price;

        /* Create lien. */
        Lien memory lien = Lien({
            lender: offer.lender,
            borrower: msg.sender,
            collection: offer.collection,
            tokenId: collateralTokenId,
            amount: loanAmount,
            startTime: block.timestamp,
            rate: offer.rate,
            auctionStartBlock: 0,
            auctionDuration: offer.auctionDuration
        });
        unchecked {
            liens[lienId = _nextLienId++] = keccak256(abi.encode(lien));
        }

        /* Take the loan offer. */
        _takeLoanOffer(offer, signature, lien, lienId);

        /* Execute order using ETH currently in contract. */
        Helpers.executeTakeAskV2(
            offer,
            execution,
            loanAmount,
            collateralTokenId,
            price,
            _POOL,
            _EXCHANGE_V2
        );
    }

    /**
     * @notice Purchase a locked NFT; repay the initial loan; lock the token as collateral for a new loan
     * @param lien Lien preimage struct
     * @param sellInput Sell offer and signature
     * @param loanInput Loan offer and signature
     * @return lienId Lien id
     */
    function buyToBorrowLocked(
        Lien calldata lien,
        SellInput calldata sellInput,
        LoanInput calldata loanInput,
        uint256 loanAmount
    )
        public
        validateLien(lien, sellInput.offer.lienId)
        lienIsActive(lien)
        returns (uint256 lienId)
    {
        if (lien.collection != loanInput.offer.collection) {
            revert CollectionsDoNotMatch();
        }

        (uint256 priceAfterFees, uint256 debt) = _buyLocked(
            lien,
            sellInput.offer,
            sellInput.signature
        );

        lienId = _borrow(loanInput.offer, loanInput.signature, loanAmount, lien.tokenId);

        /* Transfer funds. */
        /* Need to repay the original loan and payout any surplus from the sell or loan funds. */
        if (loanAmount < debt) {
            /* loanAmount < debt < priceAfterFees */

            /* Repay loan with funds from new lender to old lender. */
            _POOL.transferFrom(loanInput.offer.lender, lien.lender, loanAmount); // doesn't cover debt

            unchecked {
                /* Supplement difference from new borrower. */
                _POOL.transferFrom(msg.sender, lien.lender, debt - loanAmount); // cover rest of debt

                /* Send rest of sell funds to borrower. */
                _POOL.transferFrom(msg.sender, sellInput.offer.borrower, priceAfterFees - debt);
            }
        } else if (loanAmount < priceAfterFees) {
            /* debt < loanAmount < priceAfterFees */

            /* Repay loan with funds from new lender to old lender. */
            _POOL.transferFrom(loanInput.offer.lender, lien.lender, debt);

            unchecked {
                /* Send rest of loan from new lender to old borrower. */
                _POOL.transferFrom(
                    loanInput.offer.lender,
                    sellInput.offer.borrower,
                    loanAmount - debt
                );

                /* Send rest of sell funds from new borrower to old borrower. */
                _POOL.transferFrom(
                    msg.sender,
                    sellInput.offer.borrower,
                    priceAfterFees - loanAmount
                );
            }
        } else {
            /* debt < priceAfterFees < loanAmount */

            /* Repay loan with funds from new lender to old lender. */
            _POOL.transferFrom(loanInput.offer.lender, lien.lender, debt);

            unchecked {
                /* Send rest of sell funds from new lender to old borrower. */
                _POOL.transferFrom(
                    loanInput.offer.lender,
                    sellInput.offer.borrower,
                    priceAfterFees - debt
                );

                /* Send rest of loan from new lender to new borrower. */
                _POOL.transferFrom(loanInput.offer.lender, msg.sender, loanAmount - priceAfterFees);
            }
        }
    }

    /**
     * @notice Purchases a locked NFT and uses the funds to repay the loan
     * @param lien Lien preimage
     * @param offer Sell offer
     * @param signature Lender offer signature
     */
    function buyLocked(
        Lien calldata lien,
        SellOffer calldata offer,
        bytes calldata signature
    ) public validateLien(lien, offer.lienId) lienIsActive(lien) {
        (uint256 priceAfterFees, uint256 debt) = _buyLocked(lien, offer, signature);

        /* Send token to buyer. */
        lien.collection.safeTransferFrom(address(this), msg.sender, lien.tokenId);

        /* Repay lender. */
        _POOL.transferFrom(msg.sender, lien.lender, debt);

        /* Send surplus to borrower. */
        unchecked {
            _POOL.transferFrom(msg.sender, lien.borrower, priceAfterFees - debt);
        }
    }

    /**
     * @notice Takes a bid on a locked NFT and use the funds to repay the lien
     * @dev Must be called by the borrower
     * @param lien Lien preimage
     * @param lienId Lien id
     * @param execution Marketplace execution data
     */
    function takeBid(
        Lien calldata lien,
        uint256 lienId,
        ExecutionV1 calldata execution
    ) external validateLien(lien, lienId) lienIsActive(lien) {
        if (execution.makerOrder.order.trader == address(this) || msg.sender != lien.borrower) {
            revert Unauthorized();
        }

        /* Repay loan with funds received from the sale. */
        uint256 debt = _repay(lien, lienId);

        Helpers.executeTakeBid(
            lien,
            lienId,
            execution,
            debt,
            _POOL,
            _EXCHANGE,
            _DELEGATE,
            _BID_MATCHING_POLICY
        );
    }

    function takeBidV2(
        Lien calldata lien,
        uint256 lienId,
        BidExecutionV2 calldata execution
    ) external validateLien(lien, lienId) lienIsActive(lien) {
        if (msg.sender != lien.borrower) {
            revert Unauthorized();
        }

        /* Repay loan with funds received from the sale. */
        uint256 debt = _repay(lien, lienId);

        Helpers.executeTakeBidV2(lien, execution, debt, _POOL, _EXCHANGE_V2, _DELEGATE_V2);
    }

    /**
     * @notice Verify and take sell offer for token locked in lien; use the funds to repay the debt on the lien
     * @dev Does not transfer assets
     * @param lien Lien preimage
     * @param offer Loan offer
     * @param signature Loan offer signature
     * @return priceAfterFees Price of the token (after fees), debt Current debt amount
     */
    function _buyLocked(
        Lien calldata lien,
        SellOffer calldata offer,
        bytes calldata signature
    ) internal returns (uint256 priceAfterFees, uint256 debt) {
        if (lien.borrower != offer.borrower) {
            revert Unauthorized();
        }

        priceAfterFees = _takeSellOffer(offer, signature);

        /* Repay loan with funds received from the sale. */
        debt = _repay(lien, offer.lienId);
        if (priceAfterFees < debt) {
            revert InvalidRepayment();
        }

        emit BuyLocked(
            offer.lienId,
            address(lien.collection),
            msg.sender,
            lien.borrower,
            lien.tokenId
        );
    }

    /**
     * @notice Validates, fulfills, and transfers fees on sell offer
     * @param sellOffer Sell offer
     * @param sellSignature Sell offer signature
     */
    function _takeSellOffer(
        SellOffer calldata sellOffer,
        bytes calldata sellSignature
    ) internal returns (uint256 priceAfterFees) {
        _validateOffer(
            _hashSellOffer(sellOffer),
            sellOffer.borrower,
            sellOffer.oracle,
            sellSignature,
            sellOffer.expirationTime,
            sellOffer.salt
        );

        /* Mark the sell offer as fulfilled. */
        cancelledOrFulfilled[sellOffer.borrower][sellOffer.salt] = 1;

        /* Transfer fees. */
        uint256 totalFees = _transferFees(sellOffer.fees, msg.sender, sellOffer.price);
        unchecked {
            priceAfterFees = sellOffer.price - totalFees;
        }
    }

    function _transferFees(
        Fee[] calldata fees,
        address from,
        uint256 price
    ) internal returns (uint256 totalFee) {
        uint256 feesLength = fees.length;
        for (uint256 i = 0; i < feesLength; ) {
            uint256 fee = (price * fees[i].rate) / _BASIS_POINTS;
            _POOL.transferFrom(from, fees[i].recipient, fee);
            totalFee += fee;
            unchecked {
                ++i;
            }
        }
        if (totalFee > price) {
            revert FeesTooHigh();
        }
    }

    receive() external payable {
        if (msg.sender != address(_POOL) && msg.sender != address(_EXCHANGE_V2)) {
            revert Unauthorized();
        }
    }

    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external pure returns (bytes4) {
        return this.onERC721Received.selector;
    }

    /*/////////////////////////////////////////////////////////////
                        PAYABLE WRAPPERS
    /////////////////////////////////////////////////////////////*/

    /**
     * @notice buyToBorrow wrapper that deposits ETH to pool
     */
    function buyToBorrowETH(
        LoanOffer calldata offer,
        bytes calldata signature,
        uint256 loanAmount,
        ExecutionV1 calldata execution
    ) external payable returns (uint256 lienId) {
        _POOL.deposit{ value: msg.value }(msg.sender);
        return buyToBorrow(offer, signature, loanAmount, execution);
    }

    /**
     * @notice buyToBorrow wrapper that deposits ETH to pool
     */
    function buyToBorrowV2ETH(
        LoanOffer calldata offer,
        bytes calldata signature,
        uint256 loanAmount,
        AskExecutionV2 calldata execution
    ) external payable returns (uint256 lienId) {
        _POOL.deposit{ value: msg.value }(msg.sender);
        return buyToBorrowV2(offer, signature, loanAmount, execution);
    }

    /**
     * @notice buyToBorrowLocked wrapper that deposits ETH to pool
     */
    function buyToBorrowLockedETH(
        Lien calldata lien,
        SellInput calldata sellInput,
        LoanInput calldata loanInput,
        uint256 loanAmount
    ) external payable returns (uint256 lienId) {
        _POOL.deposit{ value: msg.value }(msg.sender);
        return buyToBorrowLocked(lien, sellInput, loanInput, loanAmount);
    }

    /**
     * @notice buyLocked wrapper that deposits ETH to pool
     */
    function buyLockedETH(
        Lien calldata lien,
        SellOffer calldata offer,
        bytes calldata signature
    ) external payable {
        _POOL.deposit{ value: msg.value }(msg.sender);
        return buyLocked(lien, offer, signature);
    }

    /*/////////////////////////////////////////////////////////////
                        VALIDATION MODIFIERS
    /////////////////////////////////////////////////////////////*/

    modifier validateLien(Lien calldata lien, uint256 lienId) {
        if (!_validateLien(lien, lienId)) {
            revert InvalidLien();
        }

        _;
    }

    modifier lienIsActive(Lien calldata lien) {
        if (_lienIsDefaulted(lien)) {
            revert LienIsDefaulted();
        }

        _;
    }

    modifier auctionIsActive(Lien calldata lien) {
        if (!_auctionIsActive(lien)) {
            revert AuctionIsNotActive();
        }

        _;
    }

    function _validateLien(Lien calldata lien, uint256 lienId) internal view returns (bool) {
        return liens[lienId] == keccak256(abi.encode(lien));
    }

    function _lienIsDefaulted(Lien calldata lien) internal view returns (bool) {
        return
            lien.auctionStartBlock != 0 &&
            lien.auctionStartBlock + lien.auctionDuration < block.number;
    }

    function _auctionIsActive(Lien calldata lien) internal view returns (bool) {
        return
            lien.auctionStartBlock != 0 &&
            lien.auctionStartBlock + lien.auctionDuration >= block.number;
    }
}

// SPDX-License-Identifier: BSL 1.1 - Blend (c) Non Fungible Trading Ltd.
pragma solidity 0.8.17;

import "lib/openzeppelin-contracts-upgradeable/contracts/access/Ownable2StepUpgradeable.sol";

import "./lib/Signatures.sol";
import "./interfaces/IOfferController.sol";

abstract contract OfferController is IOfferController, Signatures, Ownable2StepUpgradeable {
    mapping(address => mapping(uint256 => uint256)) public cancelledOrFulfilled;
    uint256[50] private _gap;

    /**
     * @notice Assert offer validity
     * @param offerHash Offer hash
     * @param signer Address of offer signer
     * @param oracle Address of oracle
     * @param signature Packed signature array
     * @param expirationTime Offer expiration time
     * @param salt Offer salt
     */
    function _validateOffer(
        bytes32 offerHash,
        address signer,
        address oracle,
        bytes calldata signature,
        uint256 expirationTime,
        uint256 salt
    ) internal view {
        _verifyOfferAuthorization(offerHash, signer, oracle, signature);

        if (expirationTime < block.timestamp) {
            revert OfferExpired();
        }
        if (cancelledOrFulfilled[signer][salt] == 1) {
            revert OfferUnavailable();
        }
    }

    /*/////////////////////////////////////////
                  CANCEL FUNCTIONS
    /////////////////////////////////////////*/
    /**
     * @notice Cancels offer salt for caller
     * @param salt Unique offer salt
     */
    function cancelOffer(uint256 salt) external {
        _cancelOffer(msg.sender, salt);
    }

    /**
     * @notice Cancels offers in bulk for caller
     * @param salts List of offer salts
     */
    function cancelOffers(uint256[] calldata salts) external {
        uint256 saltsLength = salts.length;
        for (uint256 i; i < saltsLength; ) {
            _cancelOffer(msg.sender, salts[i]);
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Cancels all offers by incrementing caller nonce
     */
    function incrementNonce() external {
        _incrementNonce(msg.sender);
    }

    /**
     * @notice Cancel offer by user and salt
     * @param user Address of user
     * @param salt Unique offer salt
     */
    function _cancelOffer(address user, uint256 salt) private {
        cancelledOrFulfilled[user][salt] = 1;
        emit OfferCancelled(user, salt);
    }

    /**
     * @notice Cancel all orders by incrementing the user nonce
     * @param user Address of user
     */
    function _incrementNonce(address user) internal {
        emit NonceIncremented(user, ++nonces[user]);
    }

    /*/////////////////////////////////////////
                  ADMIN FUNCTIONS
    /////////////////////////////////////////*/

    /**
     * @notice Set approval for an oracle address
     * @param oracle Address of oracle
     * @param approved Whether the oracle is approved
     */
    function setOracle(address oracle, bool approved) external onlyOwner {
        if (approved) {
            oracles[oracle] = 1;
        } else {
            oracles[oracle] = 0;
        }
    }

    /**
     * @notice Set the block range expiry of oracle signatures
     * @param _blockRange Block range
     */
    function setBlockRange(uint256 _blockRange) external onlyOwner {
        blockRange = _blockRange;
    }
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

// SPDX-License-Identifier: BSL 1.1 - Blend (c) Non Fungible Trading Ltd.
pragma solidity 0.8.17;

import "lib/solmate/src/utils/SignedWadMath.sol";

import { InvalidRepayment } from "./lib/Errors.sol";
import "./lib/Structs.sol";
import "../pool/interfaces/IBlurPool.sol";
import { IBlurExchangeV2 as IExchangeV2 } from "../exchangeV2/interfaces/IBlurExchangeV2.sol";
import { Order as OrderV1, SignatureVersion, Side } from "../exchangeV1/lib/OrderStructs.sol";
import {
    TakeAskSingle,
    TakeBidSingle,
    FeeRate,
    Taker,
    Exchange,
    Order as OrderV2,
    AssetType
} from "../exchangeV2/lib/Structs.sol";

interface IExchange {
    function execute(Input calldata sell, Input calldata buy) external payable;
}

library Helpers {
    int256 private constant _YEAR_WAD = 365 days * 1e18;
    uint256 private constant _LIQUIDATION_THRESHOLD = 100_000;
    uint256 private constant _BASIS_POINTS = 10_000;

    error InvalidExecution();

    /**
     * @dev Computes the current debt of a borrow given the last time it was touched and the last computed debt.
     * @param amount Principal in ETH
     * @param startTime Start time of the loan
     * @param rate Interest rate (in bips)
     * @dev Formula: https://www.desmos.com/calculator/l6omp0rwnh
     */
    function computeCurrentDebt(
        uint256 amount,
        uint256 rate,
        uint256 startTime
    ) public view returns (uint256) {
        uint256 loanTime = block.timestamp - startTime;
        int256 yearsWad = wadDiv(int256(loanTime) * 1e18, _YEAR_WAD);
        return uint256(wadMul(int256(amount), wadExp(wadMul(yearsWad, bipsToSignedWads(rate)))));
    }

    /**
     * @dev Calculates the current maximum interest rate a specific refinancing
     * auction could settle at currently given the auction's start block and duration.
     * @param startBlock The block the auction started at
     * @param oldRate Previous interest rate (in bips)
     * @dev Formula: https://www.desmos.com/calculator/urasr71dhb
     */
    function calcRefinancingAuctionRate(
        uint256 startBlock,
        uint256 auctionDuration,
        uint256 oldRate
    ) public view returns (uint256) {
        uint256 currentAuctionBlock = block.number - startBlock;
        int256 oldRateWads = bipsToSignedWads(oldRate);

        uint256 auctionT1 = auctionDuration / 5;
        uint256 auctionT2 = (4 * auctionDuration) / 5;

        int256 maxRateWads;
        {
            int256 aInverse = -bipsToSignedWads(15000);
            int256 b = 2;
            int256 maxMinRateWads = bipsToSignedWads(500);

            if (oldRateWads < -((b * aInverse) / 2)) {
                maxRateWads = maxMinRateWads + (oldRateWads ** 2) / aInverse + b * oldRateWads;
            } else {
                maxRateWads = maxMinRateWads - ((b ** 2) * aInverse) / 4;
            }
        }

        int256 startSlope = maxRateWads / int256(auctionT1); // wad-bips per block

        int256 middleSlope = bipsToSignedWads(9000) / int256((3 * auctionDuration) / 5) + 1; // wad-bips per block (add one to account for rounding)
        int256 middleB = maxRateWads - int256(auctionT1) * middleSlope;

        if (currentAuctionBlock < auctionT1) {
            return signedWadsToBips(startSlope * int256(currentAuctionBlock));
        } else if (currentAuctionBlock < auctionT2) {
            return signedWadsToBips(middleSlope * int256(currentAuctionBlock) + middleB);
        } else if (currentAuctionBlock < auctionDuration) {
            int256 endSlope;
            int256 endB;
            {
                endSlope =
                    (bipsToSignedWads(_LIQUIDATION_THRESHOLD) -
                        ((int256(auctionT2) * middleSlope) + middleB)) /
                    int256(auctionDuration - auctionT2); // wad-bips per block
                endB =
                    bipsToSignedWads(_LIQUIDATION_THRESHOLD) -
                    int256(auctionDuration) *
                    endSlope;
            }

            return signedWadsToBips(endSlope * int256(currentAuctionBlock) + endB);
        } else {
            return _LIQUIDATION_THRESHOLD;
        }
    }

    /**
     * @dev Converts an integer bips value to a signed wad value.
     */
    function bipsToSignedWads(uint256 bips) public pure returns (int256) {
        return int256((bips * 1e18) / _BASIS_POINTS);
    }

    /**
     * @dev Converts a signed wad value to an integer bips value.
     */
    function signedWadsToBips(int256 wads) public pure returns (uint256) {
        return uint256((wads * int256(_BASIS_POINTS)) / 1e18);
    }

    function executeTakeBid(
        Lien calldata lien,
        uint256 lienId,
        ExecutionV1 calldata execution,
        uint256 debt,
        IBlurPool pool,
        IExchange exchange,
        address delegate,
        address matchingPolicy
    ) external {
        /* Create sell side order from Blend. */
        OrderV1 memory sellOrder = OrderV1({
            trader: address(this),
            side: Side.Sell,
            matchingPolicy: matchingPolicy,
            collection: address(lien.collection),
            tokenId: lien.tokenId,
            amount: 1,
            paymentToken: address(pool),
            price: execution.makerOrder.order.price,
            listingTime: execution.makerOrder.order.listingTime + 1, // listingTime determines maker/taker
            expirationTime: type(uint256).max,
            fees: new Fee[](0),
            salt: lienId, // prevent reused order hash
            extraParams: "\x01" // require oracle signature
        });
        Input memory sell = Input({
            order: sellOrder,
            v: 0,
            r: bytes32(0),
            s: bytes32(0),
            extraSignature: execution.extraSignature,
            signatureVersion: SignatureVersion.Single,
            blockNumber: execution.blockNumber
        });

        /* Execute marketplace order. */
        uint256 balanceBefore = pool.balanceOf(address(this));
        lien.collection.approve(delegate, lien.tokenId);
        exchange.execute(sell, execution.makerOrder);

        /* Determine the funds received from the sale (after fees). */
        uint256 amountReceivedFromSale = pool.balanceOf(address(this)) - balanceBefore;
        if (amountReceivedFromSale < debt) {
            revert InvalidRepayment();
        }

        /* Repay lender. */
        pool.transferFrom(address(this), lien.lender, debt);

        /* Send surplus to borrower. */
        unchecked {
            pool.transferFrom(address(this), lien.borrower, amountReceivedFromSale - debt);
        }
    }

    function executeTakeAskV2(
        LoanOffer calldata offer, 
        AskExecutionV2 calldata execution,
        uint256 loanAmount,
        uint256 collateralTokenId,
        uint256 price,
        IBlurPool pool,
        IExchangeV2 exchangeV2
    ) external {
        OrderV2 calldata order = execution.order;
        if (address(offer.collection) != order.collection || order.assetType != AssetType.ERC721) {
            revert InvalidExecution();
        }

        /* Transfer funds. */
        /* Need to retrieve the ETH to fund the marketplace execution. */
        if (loanAmount < price) {
            /* Take funds from lender. */
            pool.withdrawFrom(offer.lender, address(this), loanAmount);

            /* Supplement difference from borrower. */
            unchecked {
                pool.withdrawFrom(msg.sender, address(this), price - loanAmount);
            }
        } else {
            /* Take funds from lender. */
            pool.withdrawFrom(offer.lender, address(this), price);

            /* Send surplus to borrower. */
            unchecked {
                pool.transferFrom(offer.lender, msg.sender, loanAmount - price);
            }
        }

        TakeAskSingle memory execute = TakeAskSingle({
            order: execution.order,
            exchange: Exchange({
                index: 0,
                proof: execution.proof,
                listing: Listing({
                    index: execution.listing.index,
                    tokenId: collateralTokenId,
                    amount: 1,
                    price: price
                }),
                taker: Taker({ tokenId: collateralTokenId, amount: 1 })
            }),
            takerFee: FeeRate(address(0), 0),
            signature: execution.signature,
            tokenRecipient: address(this)
        });
        exchangeV2.takeAskSingle{ value: price }(execute, execution.oracleSignature);
    }

    function executeTakeAsk(
        LoanOffer calldata offer,
        ExecutionV1 calldata execution,
        uint256 loanAmount,
        uint256 collateralTokenId,
        uint256 price,
        IBlurPool pool,
        IExchange exchange,
        address matchingPolicy
    ) external {
        /* Transfer funds. */
        /* Need to retrieve the ETH to fund the marketplace execution. */
        if (loanAmount < price) {
            /* Take funds from lender. */
            pool.withdrawFrom(offer.lender, address(this), loanAmount);

            /* Supplement difference from borrower. */
            unchecked {
                pool.withdrawFrom(msg.sender, address(this), price - loanAmount);
            }
        } else {
            /* Take funds from lender. */
            pool.withdrawFrom(offer.lender, address(this), price);

            /* Send surplus to borrower. */
            unchecked {
                pool.transferFrom(offer.lender, msg.sender, loanAmount - price);
            }
        }

        OrderV1 memory buyOrder = OrderV1({
            trader: address(this),
            side: Side.Buy,
            matchingPolicy: matchingPolicy,
            collection: address(offer.collection),
            tokenId: collateralTokenId,
            amount: 1,
            paymentToken: address(0),
            price: price,
            listingTime: execution.makerOrder.order.listingTime + 1, // listingTime determines maker/taker
            expirationTime: type(uint256).max,
            fees: new Fee[](0),
            salt: uint160(execution.makerOrder.order.trader), // prevent reused order hash
            extraParams: "\x01" // require oracle signature
        });
        Input memory buy = Input({
            order: buyOrder,
            v: 0,
            r: bytes32(0),
            s: bytes32(0),
            extraSignature: execution.extraSignature,
            signatureVersion: SignatureVersion.Single,
            blockNumber: execution.blockNumber
        });

        /* Execute order using ETH currently in contract. */
        exchange.execute{ value: price }(execution.makerOrder, buy);
    }

    function executeTakeBidV2(
        Lien calldata lien,
        BidExecutionV2 calldata execution,
        uint256 debt,
        IBlurPool pool,
        IExchangeV2 exchangeV2,
        address delegateV2
    ) external {
        OrderV2 calldata order = execution.order;
        if (address(lien.collection) != order.collection || order.assetType != AssetType.ERC721) {
            revert InvalidExecution();
        }

        uint256 balanceBefore = pool.balanceOf(address(this));

        TakeBidSingle memory execute = TakeBidSingle({
            order: execution.order,
            exchange: Exchange({
                index: 0,
                proof: execution.proof,
                listing: execution.listing,
                taker: Taker({ tokenId: lien.tokenId, amount: 1 })
            }),
            takerFee: FeeRate(address(0), 0),
            signature: execution.signature
        });

        /* Execute marketplace order. */
        lien.collection.approve(delegateV2, lien.tokenId);
        exchangeV2.takeBidSingle(execute, execution.oracleSignature);

        /* Determine the funds received from the sale (after fees). */
        uint256 amountReceivedFromSale = pool.balanceOf(address(this)) - balanceBefore;
        if (amountReceivedFromSale < debt) {
            revert InvalidRepayment();
        }

        /* Repay lender. */
        pool.transferFrom(address(this), lien.lender, debt);

        /* Send surplus to borrower. */
        unchecked {
            pool.transferFrom(address(this), lien.borrower, amountReceivedFromSale - debt);
        }
    }
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

// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity >=0.8.0;

/// @notice Modern, minimalist, and gas efficient ERC-721 implementation.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/tokens/ERC721.sol)
abstract contract ERC721 {
    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event Transfer(address indexed from, address indexed to, uint256 indexed id);

    event Approval(address indexed owner, address indexed spender, uint256 indexed id);

    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    /*//////////////////////////////////////////////////////////////
                         METADATA STORAGE/LOGIC
    //////////////////////////////////////////////////////////////*/

    string public name;

    string public symbol;

    function tokenURI(uint256 id) public view virtual returns (string memory);

    /*//////////////////////////////////////////////////////////////
                      ERC721 BALANCE/OWNER STORAGE
    //////////////////////////////////////////////////////////////*/

    mapping(uint256 => address) internal _ownerOf;

    mapping(address => uint256) internal _balanceOf;

    function ownerOf(uint256 id) public view virtual returns (address owner) {
        require((owner = _ownerOf[id]) != address(0), "NOT_MINTED");
    }

    function balanceOf(address owner) public view virtual returns (uint256) {
        require(owner != address(0), "ZERO_ADDRESS");

        return _balanceOf[owner];
    }

    /*//////////////////////////////////////////////////////////////
                         ERC721 APPROVAL STORAGE
    //////////////////////////////////////////////////////////////*/

    mapping(uint256 => address) public getApproved;

    mapping(address => mapping(address => bool)) public isApprovedForAll;

    /*//////////////////////////////////////////////////////////////
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(string memory _name, string memory _symbol) {
        name = _name;
        symbol = _symbol;
    }

    /*//////////////////////////////////////////////////////////////
                              ERC721 LOGIC
    //////////////////////////////////////////////////////////////*/

    function approve(address spender, uint256 id) public virtual {
        address owner = _ownerOf[id];

        require(msg.sender == owner || isApprovedForAll[owner][msg.sender], "NOT_AUTHORIZED");

        getApproved[id] = spender;

        emit Approval(owner, spender, id);
    }

    function setApprovalForAll(address operator, bool approved) public virtual {
        isApprovedForAll[msg.sender][operator] = approved;

        emit ApprovalForAll(msg.sender, operator, approved);
    }

    function transferFrom(
        address from,
        address to,
        uint256 id
    ) public virtual {
        require(from == _ownerOf[id], "WRONG_FROM");

        require(to != address(0), "INVALID_RECIPIENT");

        require(
            msg.sender == from || isApprovedForAll[from][msg.sender] || msg.sender == getApproved[id],
            "NOT_AUTHORIZED"
        );

        // Underflow of the sender's balance is impossible because we check for
        // ownership above and the recipient's balance can't realistically overflow.
        unchecked {
            _balanceOf[from]--;

            _balanceOf[to]++;
        }

        _ownerOf[id] = to;

        delete getApproved[id];

        emit Transfer(from, to, id);
    }

    function safeTransferFrom(
        address from,
        address to,
        uint256 id
    ) public virtual {
        transferFrom(from, to, id);

        require(
            to.code.length == 0 ||
                ERC721TokenReceiver(to).onERC721Received(msg.sender, from, id, "") ==
                ERC721TokenReceiver.onERC721Received.selector,
            "UNSAFE_RECIPIENT"
        );
    }

    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        bytes calldata data
    ) public virtual {
        transferFrom(from, to, id);

        require(
            to.code.length == 0 ||
                ERC721TokenReceiver(to).onERC721Received(msg.sender, from, id, data) ==
                ERC721TokenReceiver.onERC721Received.selector,
            "UNSAFE_RECIPIENT"
        );
    }

    /*//////////////////////////////////////////////////////////////
                              ERC165 LOGIC
    //////////////////////////////////////////////////////////////*/

    function supportsInterface(bytes4 interfaceId) public view virtual returns (bool) {
        return
            interfaceId == 0x01ffc9a7 || // ERC165 Interface ID for ERC165
            interfaceId == 0x80ac58cd || // ERC165 Interface ID for ERC721
            interfaceId == 0x5b5e139f; // ERC165 Interface ID for ERC721Metadata
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL MINT/BURN LOGIC
    //////////////////////////////////////////////////////////////*/

    function _mint(address to, uint256 id) internal virtual {
        require(to != address(0), "INVALID_RECIPIENT");

        require(_ownerOf[id] == address(0), "ALREADY_MINTED");

        // Counter overflow is incredibly unrealistic.
        unchecked {
            _balanceOf[to]++;
        }

        _ownerOf[id] = to;

        emit Transfer(address(0), to, id);
    }

    function _burn(uint256 id) internal virtual {
        address owner = _ownerOf[id];

        require(owner != address(0), "NOT_MINTED");

        // Ownership check above ensures no underflow.
        unchecked {
            _balanceOf[owner]--;
        }

        delete _ownerOf[id];

        delete getApproved[id];

        emit Transfer(owner, address(0), id);
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL SAFE MINT LOGIC
    //////////////////////////////////////////////////////////////*/

    function _safeMint(address to, uint256 id) internal virtual {
        _mint(to, id);

        require(
            to.code.length == 0 ||
                ERC721TokenReceiver(to).onERC721Received(msg.sender, address(0), id, "") ==
                ERC721TokenReceiver.onERC721Received.selector,
            "UNSAFE_RECIPIENT"
        );
    }

    function _safeMint(
        address to,
        uint256 id,
        bytes memory data
    ) internal virtual {
        _mint(to, id);

        require(
            to.code.length == 0 ||
                ERC721TokenReceiver(to).onERC721Received(msg.sender, address(0), id, data) ==
                ERC721TokenReceiver.onERC721Received.selector,
            "UNSAFE_RECIPIENT"
        );
    }
}

/// @notice A generic interface for a contract which properly accepts ERC721 tokens.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/tokens/ERC721.sol)
abstract contract ERC721TokenReceiver {
    function onERC721Received(
        address,
        address,
        uint256,
        bytes calldata
    ) external virtual returns (bytes4) {
        return ERC721TokenReceiver.onERC721Received.selector;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBlurPool {
    event Transfer(address indexed from, address indexed to, uint256 amount);

    function initialize() external;
    function decimals() external pure returns (uint8);
    function totalSupply() external view returns (uint256);
    function balanceOf(address user) external view returns (uint256);
    function deposit() external payable;
    function deposit(address user) external payable;
    function withdraw(uint256 amount) external;
    function withdrawFrom(address from, address to, uint256 amount) external;
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./ISignatures.sol";

interface IOfferController is ISignatures {
    event OfferCancelled(address indexed user, uint256 salt);
    event NonceIncremented(address indexed user, uint256 newNonce);

    function cancelOffer(uint256 salt) external;

    function cancelOffers(uint256[] calldata salts) external;

    function incrementNonce() external;

    /* Admin */
    function setOracle(address oracle, bool approved) external;

    function setBlockRange(uint256 blockRange) external;
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

// SPDX-License-Identifier: BSL 1.1 - Blend (c) Non Fungible Trading Ltd.
pragma solidity 0.8.17;

// Blend
error Unauthorized();
error InvalidLoan();
error InvalidLien();
error InsufficientOffer();
error InvalidRepayment();
error LienIsDefaulted();
error LienNotDefaulted();
error AuctionIsActive();
error AuctionIsNotActive();
error InvalidRefinance();
error RateTooHigh();
error FeesTooHigh();
error CollectionsDoNotMatch();
error InvalidAuctionDuration();

// OfferController
error OfferExpired();
error OfferUnavailable();

// Signatures
error UnauthorizedOracle();
error SignatureExpired();
error InvalidSignature();
error InvalidVParameter();

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../lib/Structs.sol";

interface ISignatures {
    function information()
        external
        view
        returns (
            string memory version,
            bytes32 domainSeparator
        );
    function getOracleOfferHash(bytes32 hash, uint256 blockNumber) external view returns (bytes32);
    function getSellOfferHash(SellOffer calldata offer) external view returns (bytes32);
    function getOfferHash(LoanOffer calldata offer) external view returns (bytes32);
    function cancelledOrFulfilled(address user, uint256 salt) external view returns (uint256);
    function nonces(address user) external view returns (uint256);
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
pragma solidity ^0.8.0;

import "../lib/Structs.sol";
import "./IOfferController.sol";

interface IBlend is IOfferController {
    event LoanOfferTaken(
        bytes32 offerHash,
        uint256 lienId,
        address collection,
        address lender,
        address borrower,
        uint256 loanAmount,
        uint256 rate,
        uint256 tokenId,
        uint256 auctionDuration
    );

    event Repay(uint256 lienId, address collection);

    event StartAuction(uint256 lienId, address collection);

    event Refinance(
        uint256 lienId,
        address collection,
        address newLender,
        uint256 newAmount,
        uint256 newRate,
        uint256 newAuctionDuration
    );

    event Seize(uint256 lienId, address collection);

    event BuyLocked(
        uint256 lienId,
        address collection,
        address buyer,
        address seller,
        uint256 tokenId
    );

    function amountTaken(bytes32 offerHash) external view returns (uint256);

    function liens(uint256 lienId) external view returns (bytes32);

    /*//////////////////////////////////////////////////
                    BORROW FLOWS
    //////////////////////////////////////////////////*/
    function borrow(
        LoanOffer calldata offer,
        bytes calldata signature,
        uint256 loanAmount,
        uint256 collateralId
    ) external returns (uint256 lienId);

    function repay(Lien calldata lien, uint256 lienId) external;

    /*//////////////////////////////////////////////////
                    REFINANCING FLOWS
    //////////////////////////////////////////////////*/
    function startAuction(Lien calldata lien, uint256 lienId) external;

    function seize(LienPointer[] calldata lienPointers) external;

    function refinance(
        Lien calldata lien,
        uint256 lienId,
        LoanOffer calldata offer,
        bytes calldata signature
    ) external;

    function refinanceAuction(Lien calldata lien, uint256 lienId, uint256 rate) external;

    function refinanceAuctionByOther(
        Lien calldata lien,
        uint256 lienId,
        LoanOffer calldata offer,
        bytes calldata signature
    ) external;

    function borrowerRefinance(
        Lien calldata lien,
        uint256 lienId,
        uint256 loanAmount,
        LoanOffer calldata offer,
        bytes calldata signature
    ) external;

    /*//////////////////////////////////////////////////
                    MARKETPLACE FLOWS
    //////////////////////////////////////////////////*/
    function buyToBorrow(
        LoanOffer calldata offer,
        bytes calldata signature,
        uint256 loanAmount,
        ExecutionV1 calldata execution
    ) external returns (uint256 lienId);

    function buyToBorrowETH(
        LoanOffer calldata offer,
        bytes calldata signature,
        uint256 loanAmount,
        ExecutionV1 calldata execution
    ) external payable returns (uint256 lienId);

    function buyToBorrowLocked(
        Lien calldata lien,
        SellInput calldata sellInput,
        LoanInput calldata loanInput,
        uint256 loanAmount
    ) external returns (uint256 lienId);

    function buyToBorrowLockedETH(
        Lien calldata lien,
        SellInput calldata sellInput,
        LoanInput calldata loanInput,
        uint256 loanAmount
    ) external payable returns (uint256 lienId);

    function buyLocked(
        Lien calldata lien,
        SellOffer calldata offer,
        bytes calldata signature
    ) external;

    function buyLockedETH(
        Lien calldata lien,
        SellOffer calldata offer,
        bytes calldata signature
    ) external payable;

    function takeBid(Lien calldata lien, uint256 lienId, ExecutionV1 calldata execution) external;
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import "lib/solmate/src/tokens/ERC721.sol";

import { Input, Fee } from "../../exchangeV1/lib/OrderStructs.sol";
import { Order as OrderV2, Listing } from "../../exchangeV2/lib/Structs.sol";

struct LienPointer {
    Lien lien;
    uint256 lienId;
}

struct SellOffer {
    address borrower;
    uint256 lienId;
    uint256 price;
    uint256 expirationTime;
    uint256 salt;
    address oracle;
    Fee[] fees;
}

struct Lien {
    address lender;
    address borrower;
    ERC721 collection;
    uint256 tokenId;
    uint256 amount;
    uint256 startTime;
    uint256 rate;
    uint256 auctionStartBlock;
    uint256 auctionDuration;
}

struct LoanOffer {
    address lender;
    ERC721 collection;
    uint256 totalAmount;
    uint256 minAmount;
    uint256 maxAmount;
    uint256 auctionDuration;
    uint256 salt;
    uint256 expirationTime;
    uint256 rate;
    address oracle;
}

struct LoanInput {
    LoanOffer offer;
    bytes signature;
}

struct SellInput {
    SellOffer offer;
    bytes signature;
}

struct ExecutionV1 {
    Input makerOrder;
    bytes extraSignature;
    uint256 blockNumber;
}

struct BidExecutionV2 {
    OrderV2 order;
    Listing listing;
    bytes32[] proof;
    bytes signature;
    bytes oracleSignature;
}

struct AskExecutionV2 {
    OrderV2 order;
    Listing listing;
    bytes32[] proof;
    bytes signature;
    bytes oracleSignature;
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

enum Side { Buy, Sell }
enum SignatureVersion { Single, Bulk }
enum AssetType { ERC721, ERC1155 }

struct Fee {
    uint16 rate;
    address payable recipient;
}

struct Order {
    address trader;
    Side side;
    address matchingPolicy;
    address collection;
    uint256 tokenId;
    uint256 amount;
    address paymentToken;
    uint256 price;
    uint256 listingTime;
    /* Order expiration timestamp - 0 for oracle cancellations. */
    uint256 expirationTime;
    Fee[] fees;
    uint256 salt;
    bytes extraParams;
}

struct Input {
    Order order;
    uint8 v;
    bytes32 r;
    bytes32 s;
    bytes extraSignature;
    SignatureVersion signatureVersion;
    uint256 blockNumber;
}

struct Execution {
  Input sell;
  Input buy;
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

