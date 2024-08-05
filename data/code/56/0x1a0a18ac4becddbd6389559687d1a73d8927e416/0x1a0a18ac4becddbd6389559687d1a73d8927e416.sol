
pragma solidity ^0.8.0;
interface IStableSwap {
    function get_dy(
        uint256 i,
        uint256 j,
        uint256 dx
    ) external view returns (uint256 dy);
    function exchange(
        uint256 i,
        uint256 j,
        uint256 dx,
        uint256 minDy
    ) external payable;
    function coins(uint256 i) external view returns (address);
    function balances(uint256 i) external view returns (uint256);
    function A() external view returns (uint256);
    function fee() external view returns (uint256);
}
pragma solidity ^0.8.17;
interface IAllowanceTransfer {
    error AllowanceExpired(uint256 deadline);
    error InsufficientAllowance(uint256 amount);
    error ExcessiveInvalidation();
    event NonceInvalidation(
        address indexed owner, address indexed token, address indexed spender, uint48 newNonce, uint48 oldNonce
    );
    event Approval(
        address indexed owner, address indexed token, address indexed spender, uint160 amount, uint48 expiration
    );
    event Permit(
        address indexed owner,
        address indexed token,
        address indexed spender,
        uint160 amount,
        uint48 expiration,
        uint48 nonce
    );
    event Lockdown(address indexed owner, address token, address spender);
    struct PermitDetails {
        address token;
        uint160 amount;
        uint48 expiration;
        uint48 nonce;
    }
    struct PermitSingle {
        PermitDetails details;
        address spender;
        uint256 sigDeadline;
    }
    struct PermitBatch {
        PermitDetails[] details;
        address spender;
        uint256 sigDeadline;
    }
    struct PackedAllowance {
        uint160 amount;
        uint48 expiration;
        uint48 nonce;
    }
    struct TokenSpenderPair {
        address token;
        address spender;
    }
    struct AllowanceTransferDetails {
        address from;
        address to;
        uint160 amount;
        address token;
    }
    function allowance(address, address, address) external view returns (uint160, uint48, uint48);
    function approve(address token, address spender, uint160 amount, uint48 expiration) external;
    function permit(address owner, PermitSingle memory permitSingle, bytes calldata signature) external;
    function permit(address owner, PermitBatch memory permitBatch, bytes calldata signature) external;
    function transferFrom(address from, address to, uint160 amount, address token) external;
    function transferFrom(AllowanceTransferDetails[] calldata transferDetails) external;
    function lockdown(TokenSpenderPair[] calldata approvals) external;
    function invalidateNonces(address token, address spender, uint48 newNonce) external;
}
pragma solidity ^0.8.0;
interface IPancakeNFTMarket {
    function buyTokenUsingBNB(
        address _collection, 
        uint256 _tokenId
    ) external payable;
    function buyTokenUsingWBNB(
        address _collection,
        uint256 _tokenId,
        uint256 _price
    ) external;
}
pragma solidity >=0.5.0;
interface IPancakeV3PoolState {
    function slot0()
        external
        view
        returns (
            uint160 sqrtPriceX96,
            int24 tick,
            uint16 observationIndex,
            uint16 observationCardinality,
            uint16 observationCardinalityNext,
            uint32 feeProtocol,
            bool unlocked
        );
    function feeGrowthGlobal0X128() external view returns (uint256);
    function feeGrowthGlobal1X128() external view returns (uint256);
    function protocolFees() external view returns (uint128 token0, uint128 token1);
    function liquidity() external view returns (uint128);
    function ticks(int24 tick)
        external
        view
        returns (
            uint128 liquidityGross,
            int128 liquidityNet,
            uint256 feeGrowthOutside0X128,
            uint256 feeGrowthOutside1X128,
            int56 tickCumulativeOutside,
            uint160 secondsPerLiquidityOutsideX128,
            uint32 secondsOutside,
            bool initialized
        );
    function tickBitmap(int16 wordPosition) external view returns (uint256);
    function positions(bytes32 key)
        external
        view
        returns (
            uint128 _liquidity,
            uint256 feeGrowthInside0LastX128,
            uint256 feeGrowthInside1LastX128,
            uint128 tokensOwed0,
            uint128 tokensOwed1
        );
    function observations(uint256 index)
        external
        view
        returns (
            uint32 blockTimestamp,
            int56 tickCumulative,
            uint160 secondsPerLiquidityCumulativeX128,
            bool initialized
        );
}
pragma solidity ^0.8.0;
import {Constants} from './Constants.sol';
library BytesLib {
    error SliceOutOfBounds();
    function toAddress(bytes calldata _bytes) internal pure returns (address _address) {
        if (_bytes.length < Constants.ADDR_SIZE) revert SliceOutOfBounds();
        assembly {
            _address := shr(96, calldataload(_bytes.offset))
        }
    }
    function toPool(bytes calldata _bytes) internal pure returns (address token0, uint24 fee, address token1) {
        if (_bytes.length < Constants.V3_POP_OFFSET) revert SliceOutOfBounds();
        assembly {
            let firstWord := calldataload(_bytes.offset)
            token0 := shr(96, firstWord)
            fee := and(shr(72, firstWord), 0xffffff)
            token1 := shr(96, calldataload(add(_bytes.offset, 23)))
        }
    }
    function toLengthOffset(bytes calldata _bytes, uint256 _arg)
        internal
        pure
        returns (uint256 length, uint256 offset)
    {
        uint256 relativeOffset;
        assembly {
            let lengthPtr := add(_bytes.offset, calldataload(add(_bytes.offset, shl(5, _arg))))
            length := calldataload(lengthPtr)
            offset := add(lengthPtr, 0x20)
            relativeOffset := sub(offset, _bytes.offset)
        }
        if (_bytes.length < length + relativeOffset) revert SliceOutOfBounds();
    }
    function toBytes(bytes calldata _bytes, uint256 _arg) internal pure returns (bytes calldata res) {
        (uint256 length, uint256 offset) = toLengthOffset(_bytes, _arg);
        assembly {
            res.length := length
            res.offset := offset
        }
    }
    function toAddressArray(bytes calldata _bytes, uint256 _arg) internal pure returns (address[] calldata res) {
        (uint256 length, uint256 offset) = toLengthOffset(_bytes, _arg);
        assembly {
            res.length := length
            res.offset := offset
        }
    }
    function toBytesArray(bytes calldata _bytes, uint256 _arg) internal pure returns (bytes[] calldata res) {
        (uint256 length, uint256 offset) = toLengthOffset(_bytes, _arg);
        assembly {
            res.length := length
            res.offset := offset
        }
    }
    function toUintArray(bytes calldata _bytes, uint256 _arg) internal pure returns (uint[] calldata res) {
        (uint256 length, uint256 offset) = toLengthOffset(_bytes, _arg);
        assembly {
            res.length := length
            res.offset := offset
        }
    }
}
pragma solidity ^0.8.0;
interface IStableSwapFactory {
    struct StableSwapPairInfo {
        address swapContract;
        address token0;
        address token1;
        address LPContract;
    }
    struct StableSwapThreePoolPairInfo {
        address swapContract;
        address token0;
        address token1;
        address token2;
        address LPContract;
    }
    function pairLength() external view returns (uint256);
    function getPairInfo(address _tokenA, address _tokenB) 
        external 
        view 
        returns (StableSwapPairInfo memory info);
    function getThreePoolPairInfo(address _tokenA, address _tokenB)
        external
        view
        returns (StableSwapThreePoolPairInfo memory info);
}
pragma solidity ^0.8.17;
import {IWETH9} from '../interfaces/IWETH9.sol';
library Constants {
    uint256 internal constant CONTRACT_BALANCE = 0x8000000000000000000000000000000000000000000000000000000000000000;
    uint256 internal constant ALREADY_PAID = 0;
    address internal constant ETH = address(0);
    address internal constant MSG_SENDER = address(1);
    address internal constant ADDRESS_THIS = address(2);
    uint256 internal constant ADDR_SIZE = 20;
    uint256 internal constant V3_FEE_SIZE = 3;
    uint256 internal constant NEXT_V3_POOL_OFFSET = ADDR_SIZE + V3_FEE_SIZE;
    uint256 internal constant V3_POP_OFFSET = NEXT_V3_POOL_OFFSET + ADDR_SIZE;
    uint256 internal constant MULTIPLE_V3_POOLS_MIN_LENGTH = V3_POP_OFFSET + NEXT_V3_POOL_OFFSET;
}
pragma solidity ^0.8.17;
import {IAllowanceTransfer} from '../permit2/src/interfaces/IAllowanceTransfer.sol';
import {SafeCast160} from '../permit2/src/libraries/SafeCast160.sol';
import {Payments} from './Payments.sol';
import {Constants} from '../libraries/Constants.sol';
import {RouterImmutables} from '../base/RouterImmutables.sol';
abstract contract Permit2Payments is Payments {
    using SafeCast160 for uint256;
    error FromAddressIsNotOwner();
    function permit2TransferFrom(address token, address from, address to, uint160 amount) internal {
        PERMIT2.transferFrom(from, to, amount, token);
    }
    function permit2TransferFrom(IAllowanceTransfer.AllowanceTransferDetails[] memory batchDetails, address owner)
        internal
    {
        uint256 batchLength = batchDetails.length;
        for (uint256 i = 0; i < batchLength; ++i) {
            if (batchDetails[i].from != owner) revert FromAddressIsNotOwner();
        }
        PERMIT2.transferFrom(batchDetails);
    }
    function payOrPermit2Transfer(address token, address payer, address recipient, uint256 amount) internal {
        if (payer == address(this)) pay(token, recipient, amount);
        else permit2TransferFrom(token, payer, recipient, amount.toUint160());
    }
}
pragma solidity ^0.8.17;
library SafeCast160 {
    error UnsafeCast();
    function toUint160(uint256 value) internal pure returns (uint160) {
        if (value > type(uint160).max) revert UnsafeCast();
        return uint160(value);
    }
}
pragma solidity >=0.8.0;
abstract contract ERC721 {
    event Transfer(address indexed from, address indexed to, uint256 indexed id);
    event Approval(address indexed owner, address indexed spender, uint256 indexed id);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);
    string public name;
    string public symbol;
    function tokenURI(uint256 id) public view virtual returns (string memory);
    mapping(uint256 => address) internal _ownerOf;
    mapping(address => uint256) internal _balanceOf;
    function ownerOf(uint256 id) public view virtual returns (address owner) {
        require((owner = _ownerOf[id]) != address(0), "NOT_MINTED");
    }
    function balanceOf(address owner) public view virtual returns (uint256) {
        require(owner != address(0), "ZERO_ADDRESS");
        return _balanceOf[owner];
    }
    mapping(uint256 => address) public getApproved;
    mapping(address => mapping(address => bool)) public isApprovedForAll;
    constructor(string memory _name, string memory _symbol) {
        name = _name;
        symbol = _symbol;
    }
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
    function supportsInterface(bytes4 interfaceId) public view virtual returns (bool) {
        return
            interfaceId == 0x01ffc9a7 || 
            interfaceId == 0x80ac58cd || 
            interfaceId == 0x5b5e139f; 
    }
    function _mint(address to, uint256 id) internal virtual {
        require(to != address(0), "INVALID_RECIPIENT");
        require(_ownerOf[id] == address(0), "ALREADY_MINTED");
        unchecked {
            _balanceOf[to]++;
        }
        _ownerOf[id] = to;
        emit Transfer(address(0), to, id);
    }
    function _burn(uint256 id) internal virtual {
        address owner = _ownerOf[id];
        require(owner != address(0), "NOT_MINTED");
        unchecked {
            _balanceOf[owner]--;
        }
        delete _ownerOf[id];
        delete getApproved[id];
        emit Transfer(owner, address(0), id);
    }
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
pragma solidity ^0.8.17;
import {IERC721Receiver} from '@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol';
import {IERC1155Receiver} from '@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol';
import {IERC165} from '@openzeppelin/contracts/utils/introspection/IERC165.sol';
contract Callbacks is IERC721Receiver, IERC1155Receiver {
    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC721Received.selector;
    }
    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC1155Received.selector;
    }
    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return this.onERC1155BatchReceived.selector;
    }
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IERC1155Receiver).interfaceId || interfaceId == type(IERC721Receiver).interfaceId
            || interfaceId == type(IERC165).interfaceId;
    }
}
pragma solidity ^0.8.17;
import {Constants} from '../libraries/Constants.sol';
contract LockAndMsgSender {
    error ContractLocked();
    address internal constant NOT_LOCKED_FLAG = address(1);
    address internal lockedBy = NOT_LOCKED_FLAG;
    modifier isNotLocked() {
        if (msg.sender != address(this)) {
            if (lockedBy != NOT_LOCKED_FLAG) revert ContractLocked();
            lockedBy = msg.sender;
            _;
            lockedBy = NOT_LOCKED_FLAG;
        } else {
            _;
        }
    }
    function map(address recipient) internal view returns (address) {
        if (recipient == Constants.MSG_SENDER) {
            return lockedBy;
        } else if (recipient == Constants.ADDRESS_THIS) {
            return address(this);
        } else {
            return recipient;
        }
    }
}
pragma solidity ^0.8.4;
import {IERC20} from '@openzeppelin/contracts/token/ERC20/IERC20.sol';
interface IWETH9 is IERC20 {
    function deposit() external payable;
    function withdraw(uint256) external;
}
pragma solidity >=0.5.0;
library SafeCast {
    function toUint160(uint256 y) internal pure returns (uint160 z) {
        require((z = uint160(y)) == y);
    }
    function toInt128(int256 y) internal pure returns (int128 z) {
        require((z = int128(y)) == y);
    }
    function toInt256(uint256 y) internal pure returns (int256 z) {
        require(y < 2**255);
        z = int256(y);
    }
}
pragma solidity ^0.8.0;
import "../../utils/introspection/IERC165.sol";
interface IERC1155Receiver is IERC165 {
    function onERC1155Received(
        address operator,
        address from,
        uint256 id,
        uint256 value,
        bytes calldata data
    ) external returns (bytes4);
    function onERC1155BatchReceived(
        address operator,
        address from,
        uint256[] calldata ids,
        uint256[] calldata values,
        bytes calldata data
    ) external returns (bytes4);
}
pragma solidity ^0.8.17;
import {RouterImmutables} from '../../base/RouterImmutables.sol';
import {Payments} from '../Payments.sol';
import {Permit2Payments} from '../Permit2Payments.sol';
import {Constants} from '../../libraries/Constants.sol';
import {UniversalRouterHelper} from '../../libraries/UniversalRouterHelper.sol';
import {ERC20} from 'solmate/src/tokens/ERC20.sol';
import {SafeTransferLib} from 'solmate/src/utils/SafeTransferLib.sol';
import {Ownable} from '@openzeppelin/contracts/access/Ownable.sol';
import {IStableSwap} from '../../interfaces/IStableSwap.sol';
abstract contract StableSwapRouter is RouterImmutables, Permit2Payments, Ownable {
    using SafeTransferLib for ERC20;
    using UniversalRouterHelper for address;
    error StableTooLittleReceived();
    error StableTooMuchRequested();
    error StableInvalidPath();
    address public stableSwapFactory;
    address public stableSwapInfo;
    event SetStableSwap(address indexed factory, address indexed info);
    constructor(
        address _stableSwapFactory,
        address _stableSwapInfo
    ) {
        stableSwapFactory = _stableSwapFactory;
        stableSwapInfo = _stableSwapInfo;
    }
    function setStableSwap(
        address _factory,
        address _info
    ) external onlyOwner {
        require(_factory != address(0) && _info != address(0));
        stableSwapFactory = _factory;
        stableSwapInfo = _info;
        emit SetStableSwap(stableSwapFactory, stableSwapInfo);
    }
    function _stableSwap(
        address[] calldata path,
        uint256[] calldata flag
    ) private {
        unchecked {
            if (path.length - 1 != flag.length) revert StableInvalidPath();
            for (uint256 i; i < flag.length; i++) {
                (address input, address output) = (path[i], path[i + 1]);
                (uint256 k, uint256 j, address swapContract) = stableSwapFactory.getStableInfo(input, output, flag[i]); 
                uint256 amountIn = ERC20(input).balanceOf(address(this));
                ERC20(input).safeApprove(swapContract, amountIn);
                IStableSwap(swapContract).exchange(k, j, amountIn, 0);
            }
        }
    }
    function stableSwapExactInput(
        address recipient,
        uint256 amountIn,
        uint256 amountOutMinimum,
        address[] calldata path,
        uint256[] calldata flag,
        address payer
    ) internal {
        if (
            amountIn != Constants.ALREADY_PAID && amountIn != Constants.CONTRACT_BALANCE
        ) {
            payOrPermit2Transfer(path[0], payer, address(this), amountIn);
        }
        ERC20 tokenOut = ERC20(path[path.length - 1]);
        _stableSwap(path, flag); 
        uint256 amountOut = tokenOut.balanceOf(address(this));
        if (amountOut < amountOutMinimum) revert StableTooLittleReceived();
        if (recipient != address(this)) pay(address(tokenOut), recipient, amountOut);
    }
    function stableSwapExactOutput(
        address recipient,
        uint256 amountOut,
        uint256 amountInMaximum,
        address[] calldata path,
        uint256[] calldata flag,
        address payer
    ) internal {
        uint256 amountIn = stableSwapFactory.getStableAmountsIn(stableSwapInfo, path, flag, amountOut)[0];
        if (amountIn > amountInMaximum) revert StableTooMuchRequested();
        payOrPermit2Transfer(path[0], payer, address(this), amountIn);
        _stableSwap(path, flag); 
        if (recipient != address(this)) pay(path[path.length - 1], recipient, amountOut);
    }
}
pragma solidity ^0.8.17;
import {Dispatcher} from './base/Dispatcher.sol';
import {RewardsCollector} from './base/RewardsCollector.sol';
import {RouterParameters, RouterImmutables} from './base/RouterImmutables.sol';
import {Commands} from './libraries/Commands.sol';
import {Constants} from './libraries/Constants.sol';
import {IUniversalRouter} from './interfaces/IUniversalRouter.sol';
import {StableSwapRouter} from './modules/pancakeswap/StableSwapRouter.sol';
import {Pausable} from '@openzeppelin/contracts/security/Pausable.sol';
contract UniversalRouter is RouterImmutables, IUniversalRouter, Dispatcher, RewardsCollector, Pausable {
    modifier checkDeadline(uint256 deadline) {
        if (block.timestamp > deadline) revert TransactionDeadlinePassed();
        _;
    }
    constructor(RouterParameters memory params) RouterImmutables(params) StableSwapRouter(params.stableFactory, params.stableInfo) {}
    function execute(bytes calldata commands, bytes[] calldata inputs, uint256 deadline)
        external
        payable
        checkDeadline(deadline)
    {
        execute(commands, inputs);
    }
    function execute(bytes calldata commands, bytes[] calldata inputs) 
        public 
        payable 
        override 
        isNotLocked 
        whenNotPaused 
    {
        bool success;
        bytes memory output;
        uint256 numCommands = commands.length;
        if (inputs.length != numCommands) revert LengthMismatch();
        for (uint256 commandIndex = 0; commandIndex < numCommands;) {
            bytes1 command = commands[commandIndex];
            bytes calldata input = inputs[commandIndex];
            (success, output) = dispatch(command, input);
            if (!success && successRequired(command)) {
                revert ExecutionFailed({commandIndex: commandIndex, message: output});
            }
            unchecked {
                commandIndex++;
            }
        }
        uint256 balance = address(this).balance;
        if ((balance > 0) && (msg.sender != address(this))) sweep(Constants.ETH, msg.sender, balance);
    }
    function successRequired(bytes1 command) internal pure returns (bool) {
        return command & Commands.FLAG_ALLOW_REVERT == 0;
    }
    function pause() external onlyOwner whenNotPaused {
        _pause();
    }
    function unpause() external onlyOwner whenPaused {
        _unpause();
    }
    receive() external payable {}
}
pragma solidity ^0.8.0;
interface IERC20 {
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool);
}
pragma solidity >=0.5.0;
interface IPancakeV3PoolEvents {
    event Initialize(uint160 sqrtPriceX96, int24 tick);
    event Mint(
        address sender,
        address indexed owner,
        int24 indexed tickLower,
        int24 indexed tickUpper,
        uint128 amount,
        uint256 amount0,
        uint256 amount1
    );
    event Collect(
        address indexed owner,
        address recipient,
        int24 indexed tickLower,
        int24 indexed tickUpper,
        uint128 amount0,
        uint128 amount1
    );
    event Burn(
        address indexed owner,
        int24 indexed tickLower,
        int24 indexed tickUpper,
        uint128 amount,
        uint256 amount0,
        uint256 amount1
    );
    event Swap(
        address indexed sender,
        address indexed recipient,
        int256 amount0,
        int256 amount1,
        uint160 sqrtPriceX96,
        uint128 liquidity,
        int24 tick,
        uint128 protocolFeesToken0,
        uint128 protocolFeesToken1
    );
    event Flash(
        address indexed sender,
        address indexed recipient,
        uint256 amount0,
        uint256 amount1,
        uint256 paid0,
        uint256 paid1
    );
    event IncreaseObservationCardinalityNext(
        uint16 observationCardinalityNextOld,
        uint16 observationCardinalityNextNew
    );
    event SetFeeProtocol(
        uint32 feeProtocol0Old,
        uint32 feeProtocol1Old,
        uint32 feeProtocol0New,
        uint32 feeProtocol1New
    );
    event CollectProtocol(address indexed sender, address indexed recipient, uint128 amount0, uint128 amount1);
}
pragma solidity >=0.5.0;
interface IUniswapV2Pair {
    event Approval(address indexed owner, address indexed spender, uint value);
    event Transfer(address indexed from, address indexed to, uint value);
    function name() external pure returns (string memory);
    function symbol() external pure returns (string memory);
    function decimals() external pure returns (uint8);
    function totalSupply() external view returns (uint);
    function balanceOf(address owner) external view returns (uint);
    function allowance(address owner, address spender) external view returns (uint);
    function approve(address spender, uint value) external returns (bool);
    function transfer(address to, uint value) external returns (bool);
    function transferFrom(address from, address to, uint value) external returns (bool);
    function DOMAIN_SEPARATOR() external view returns (bytes32);
    function PERMIT_TYPEHASH() external pure returns (bytes32);
    function nonces(address owner) external view returns (uint);
    function permit(address owner, address spender, uint value, uint deadline, uint8 v, bytes32 r, bytes32 s) external;
    event Mint(address indexed sender, uint amount0, uint amount1);
    event Burn(address indexed sender, uint amount0, uint amount1, address indexed to);
    event Swap(
        address indexed sender,
        uint amount0In,
        uint amount1In,
        uint amount0Out,
        uint amount1Out,
        address indexed to
    );
    event Sync(uint112 reserve0, uint112 reserve1);
    function MINIMUM_LIQUIDITY() external pure returns (uint);
    function factory() external view returns (address);
    function token0() external view returns (address);
    function token1() external view returns (address);
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    function price0CumulativeLast() external view returns (uint);
    function price1CumulativeLast() external view returns (uint);
    function kLast() external view returns (uint);
    function mint(address to) external returns (uint liquidity);
    function burn(address to) external returns (uint amount0, uint amount1);
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function skim(address to) external;
    function sync() external;
    function initialize(address, address) external;
}
pragma solidity >=0.5.0;
interface IPancakeV3PoolActions {
    function initialize(uint160 sqrtPriceX96) external;
    function mint(
        address recipient,
        int24 tickLower,
        int24 tickUpper,
        uint128 amount,
        bytes calldata data
    ) external returns (uint256 amount0, uint256 amount1);
    function collect(
        address recipient,
        int24 tickLower,
        int24 tickUpper,
        uint128 amount0Requested,
        uint128 amount1Requested
    ) external returns (uint128 amount0, uint128 amount1);
    function burn(
        int24 tickLower,
        int24 tickUpper,
        uint128 amount
    ) external returns (uint256 amount0, uint256 amount1);
    function swap(
        address recipient,
        bool zeroForOne,
        int256 amountSpecified,
        uint160 sqrtPriceLimitX96,
        bytes calldata data
    ) external returns (int256 amount0, int256 amount1);
    function flash(
        address recipient,
        uint256 amount0,
        uint256 amount1,
        bytes calldata data
    ) external;
    function increaseObservationCardinalityNext(uint16 observationCardinalityNext) external;
}
pragma solidity ^0.8.17;
import {V2SwapRouter} from '../modules/pancakeswap/V2SwapRouter.sol';
import {V3SwapRouter} from '../modules/pancakeswap/V3SwapRouter.sol';
import {StableSwapRouter} from '../modules/pancakeswap/StableSwapRouter.sol';
import {Payments} from '../modules/Payments.sol';
import {RouterImmutables} from '../base/RouterImmutables.sol';
import {Callbacks} from '../base/Callbacks.sol';
import {BytesLib} from '../libraries/BytesLib.sol';
import {Commands} from '../libraries/Commands.sol';
import {LockAndMsgSender} from './LockAndMsgSender.sol';
import {ERC721} from 'solmate/src/tokens/ERC721.sol';
import {ERC1155} from 'solmate/src/tokens/ERC1155.sol';
import {ERC20} from 'solmate/src/tokens/ERC20.sol';
import {IAllowanceTransfer} from '../permit2/src/interfaces/IAllowanceTransfer.sol';
import {IPancakeNFTMarket} from '../interfaces/IPancakeNFTMarket.sol';
abstract contract Dispatcher is Payments, V2SwapRouter, V3SwapRouter, StableSwapRouter, Callbacks, LockAndMsgSender {
    using BytesLib for bytes;
    error InvalidCommandType(uint256 commandType);
    error BuyPunkFailed();
    error BuyPancakeNFTFailed();
    error InvalidOwnerERC721();
    error InvalidOwnerERC1155();
    error BalanceTooLow();
    function dispatch(bytes1 commandType, bytes calldata inputs) internal returns (bool success, bytes memory output) {
        uint256 command = uint8(commandType & Commands.COMMAND_TYPE_MASK);
        success = true;
        if (command < Commands.FOURTH_IF_BOUNDARY) {
            if (command < Commands.SECOND_IF_BOUNDARY) {
                if (command < Commands.FIRST_IF_BOUNDARY) {
                    if (command == Commands.V3_SWAP_EXACT_IN) {
                        address recipient;
                        uint256 amountIn;
                        uint256 amountOutMin;
                        bool payerIsUser;
                        assembly {
                            recipient := calldataload(inputs.offset)
                            amountIn := calldataload(add(inputs.offset, 0x20))
                            amountOutMin := calldataload(add(inputs.offset, 0x40))
                            payerIsUser := calldataload(add(inputs.offset, 0x80))
                        }
                        bytes calldata path = inputs.toBytes(3);
                        address payer = payerIsUser ? lockedBy : address(this);
                        v3SwapExactInput(map(recipient), amountIn, amountOutMin, path, payer);
                    } else if (command == Commands.V3_SWAP_EXACT_OUT) {
                        address recipient;
                        uint256 amountOut;
                        uint256 amountInMax;
                        bool payerIsUser;
                        assembly {
                            recipient := calldataload(inputs.offset)
                            amountOut := calldataload(add(inputs.offset, 0x20))
                            amountInMax := calldataload(add(inputs.offset, 0x40))
                            payerIsUser := calldataload(add(inputs.offset, 0x80))
                        }
                        bytes calldata path = inputs.toBytes(3);
                        address payer = payerIsUser ? lockedBy : address(this);
                        v3SwapExactOutput(map(recipient), amountOut, amountInMax, path, payer);
                    } else if (command == Commands.PERMIT2_TRANSFER_FROM) {
                        address token;
                        address recipient;
                        uint160 amount;
                        assembly {
                            token := calldataload(inputs.offset)
                            recipient := calldataload(add(inputs.offset, 0x20))
                            amount := calldataload(add(inputs.offset, 0x40))
                        }
                        permit2TransferFrom(token, lockedBy, map(recipient), amount);
                    } else if (command == Commands.PERMIT2_PERMIT_BATCH) {
                        (IAllowanceTransfer.PermitBatch memory permitBatch,) =
                            abi.decode(inputs, (IAllowanceTransfer.PermitBatch, bytes));
                        bytes calldata data = inputs.toBytes(1);
                        PERMIT2.permit(lockedBy, permitBatch, data);
                    } else if (command == Commands.SWEEP) {
                        address token;
                        address recipient;
                        uint160 amountMin;
                        assembly {
                            token := calldataload(inputs.offset)
                            recipient := calldataload(add(inputs.offset, 0x20))
                            amountMin := calldataload(add(inputs.offset, 0x40))
                        }
                        Payments.sweep(token, map(recipient), amountMin);
                    } else if (command == Commands.TRANSFER) {
                        address token;
                        address recipient;
                        uint256 value;
                        assembly {
                            token := calldataload(inputs.offset)
                            recipient := calldataload(add(inputs.offset, 0x20))
                            value := calldataload(add(inputs.offset, 0x40))
                        }
                        Payments.pay(token, map(recipient), value);
                    } else if (command == Commands.PAY_PORTION) {
                        address token;
                        address recipient;
                        uint256 bips;
                        assembly {
                            token := calldataload(inputs.offset)
                            recipient := calldataload(add(inputs.offset, 0x20))
                            bips := calldataload(add(inputs.offset, 0x40))
                        }
                        Payments.payPortion(token, map(recipient), bips);
                    } else {
                        revert InvalidCommandType(command);
                    }
                } else {
                    if (command == Commands.V2_SWAP_EXACT_IN) {
                        address recipient;
                        uint256 amountIn;
                        uint256 amountOutMin;
                        bool payerIsUser;
                        assembly {
                            recipient := calldataload(inputs.offset)
                            amountIn := calldataload(add(inputs.offset, 0x20))
                            amountOutMin := calldataload(add(inputs.offset, 0x40))
                            payerIsUser := calldataload(add(inputs.offset, 0x80))
                        }
                        address[] calldata path = inputs.toAddressArray(3);
                        address payer = payerIsUser ? lockedBy : address(this);
                        v2SwapExactInput(map(recipient), amountIn, amountOutMin, path, payer);
                    } else if (command == Commands.V2_SWAP_EXACT_OUT) {
                        address recipient;
                        uint256 amountOut;
                        uint256 amountInMax;
                        bool payerIsUser;
                        assembly {
                            recipient := calldataload(inputs.offset)
                            amountOut := calldataload(add(inputs.offset, 0x20))
                            amountInMax := calldataload(add(inputs.offset, 0x40))
                            payerIsUser := calldataload(add(inputs.offset, 0x80))
                        }
                        address[] calldata path = inputs.toAddressArray(3);
                        address payer = payerIsUser ? lockedBy : address(this);
                        v2SwapExactOutput(map(recipient), amountOut, amountInMax, path, payer);
                    } else if (command == Commands.PERMIT2_PERMIT) {
                        IAllowanceTransfer.PermitSingle calldata permitSingle;
                        assembly {
                            permitSingle := inputs.offset
                        }
                        bytes calldata data = inputs.toBytes(6); 
                        PERMIT2.permit(lockedBy, permitSingle, data);
                    } else if (command == Commands.WRAP_ETH) {
                        address recipient;
                        uint256 amountMin;
                        assembly {
                            recipient := calldataload(inputs.offset)
                            amountMin := calldataload(add(inputs.offset, 0x20))
                        }
                        Payments.wrapETH(map(recipient), amountMin);
                    } else if (command == Commands.UNWRAP_WETH) {
                        address recipient;
                        uint256 amountMin;
                        assembly {
                            recipient := calldataload(inputs.offset)
                            amountMin := calldataload(add(inputs.offset, 0x20))
                        }
                        Payments.unwrapWETH9(map(recipient), amountMin);
                    } else if (command == Commands.PERMIT2_TRANSFER_FROM_BATCH) {
                        (IAllowanceTransfer.AllowanceTransferDetails[] memory batchDetails) =
                            abi.decode(inputs, (IAllowanceTransfer.AllowanceTransferDetails[]));
                        permit2TransferFrom(batchDetails, lockedBy);
                    } else if (command == Commands.BALANCE_CHECK_ERC20) {
                        address owner;
                        address token;
                        uint256 minBalance;
                        assembly {
                            owner := calldataload(inputs.offset)
                            token := calldataload(add(inputs.offset, 0x20))
                            minBalance := calldataload(add(inputs.offset, 0x40))
                        }
                        success = (ERC20(token).balanceOf(owner) >= minBalance);
                        if (!success) output = abi.encodePacked(BalanceTooLow.selector);
                    } else {
                        revert InvalidCommandType(command);
                    }
                }
            } else {
                if (command < Commands.THIRD_IF_BOUNDARY) {
                    if (command == Commands.OWNER_CHECK_721) {
                        address owner;
                        address token;
                        uint256 id;
                        assembly {
                            owner := calldataload(inputs.offset)
                            token := calldataload(add(inputs.offset, 0x20))
                            id := calldataload(add(inputs.offset, 0x40))
                        }
                        success = (ERC721(token).ownerOf(id) == owner);
                        if (!success) output = abi.encodePacked(InvalidOwnerERC721.selector);
                    } else if (command == Commands.OWNER_CHECK_1155) {
                        address owner;
                        address token;
                        uint256 id;
                        uint256 minBalance;
                        assembly {
                            owner := calldataload(inputs.offset)
                            token := calldataload(add(inputs.offset, 0x20))
                            id := calldataload(add(inputs.offset, 0x40))
                            minBalance := calldataload(add(inputs.offset, 0x60))
                        }
                        success = (ERC1155(token).balanceOf(owner, id) >= minBalance);
                        if (!success) output = abi.encodePacked(InvalidOwnerERC1155.selector);
                    } else if (command == Commands.SWEEP_ERC721) {
                        address token;
                        address recipient;
                        uint256 id;
                        assembly {
                            token := calldataload(inputs.offset)
                            recipient := calldataload(add(inputs.offset, 0x20))
                            id := calldataload(add(inputs.offset, 0x40))
                        }
                        Payments.sweepERC721(token, map(recipient), id);
                    } else if (command == Commands.SWEEP_ERC1155) {
                        address token;
                        address recipient;
                        uint256 id;
                        uint256 amount;
                        assembly {
                            token := calldataload(inputs.offset)
                            recipient := calldataload(add(inputs.offset, 0x20))
                            id := calldataload(add(inputs.offset, 0x40))
                            amount := calldataload(add(inputs.offset, 0x60))
                        }
                        Payments.sweepERC1155(token, map(recipient), id, amount);
                    } else {
                        revert InvalidCommandType(command);
                    }
                } else {
                    if (command == Commands.SEAPORT_V1_5) {
                        (uint256 value, bytes calldata data) = getValueAndData(inputs);
                        (success, output) = SEAPORT_V1_5.call{value: value}(data);
                    } else if (command == Commands.SEAPORT_V1_4) {
                        (uint256 value, bytes calldata data) = getValueAndData(inputs);
                        (success, output) = SEAPORT_V1_4.call{value: value}(data);
                    } else if (command == Commands.LOOKS_RARE_V2) {
                        uint256 value;
                        assembly {
                            value := calldataload(inputs.offset)
                        }
                        bytes calldata data = inputs.toBytes(1);
                        (success, output) = LOOKS_RARE_V2.call{value: value}(data);
                    } else if (command == Commands.X2Y2_721) {
                        (success, output) = callAndTransfer721(inputs, X2Y2);
                    } else if (command == Commands.X2Y2_1155) {
                        (success, output) = callAndTransfer1155(inputs, X2Y2);
                    } else {
                        revert InvalidCommandType(command);
                    }
                }
            }
        } else {
            if (command == Commands.EXECUTE_SUB_PLAN) {
                bytes calldata _commands = inputs.toBytes(0);
                bytes[] calldata _inputs = inputs.toBytesArray(1);
                (success, output) =
                    (address(this)).call(abi.encodeWithSelector(Dispatcher.execute.selector, _commands, _inputs));                
            } else if (command == Commands.APPROVE_ERC20) {
                ERC20 token;
                RouterImmutables.Spenders spender;
                assembly {
                    token := calldataload(inputs.offset)
                    spender := calldataload(add(inputs.offset, 0x20))
                }
                Payments.approveERC20(token, spender);
            } else if (command == Commands.STABLE_SWAP_EXACT_IN) {
                address recipient;
                uint256 amountIn;
                uint256 amountOutMin;
                bool payerIsUser;
                assembly {
                    recipient := calldataload(inputs.offset)
                    amountIn := calldataload(add(inputs.offset, 0x20))
                    amountOutMin := calldataload(add(inputs.offset, 0x40))
                    payerIsUser := calldataload(add(inputs.offset, 0xa0))
                }
                address[] calldata path = inputs.toAddressArray(3);
                uint256[] calldata flag = inputs.toUintArray(4);
                address payer = payerIsUser ? lockedBy : address(this);
                stableSwapExactInput(map(recipient), amountIn, amountOutMin, path, flag, payer);
            } else if (command == Commands.STABLE_SWAP_EXACT_OUT) {
                address recipient;
                uint256 amountOut;
                uint256 amountInMax;
                bool payerIsUser;
                assembly {
                    recipient := calldataload(inputs.offset)
                    amountOut := calldataload(add(inputs.offset, 0x20))
                    amountInMax := calldataload(add(inputs.offset, 0x40))
                    payerIsUser := calldataload(add(inputs.offset, 0xa0))
                }
                address[] calldata path = inputs.toAddressArray(3);
                uint256[] calldata flag = inputs.toUintArray(4);
                address payer = payerIsUser ? lockedBy : address(this);
                stableSwapExactOutput(map(recipient), amountOut, amountInMax, path, flag, payer);
            } else if (command == Commands.PANCAKE_NFT_BNB) {
                address collection;
                uint256 tokenId;
                uint256 value;
                assembly {
                    collection := calldataload(inputs.offset)
                    tokenId := calldataload(add(inputs.offset, 0x20))
                    value := calldataload(add(inputs.offset, 0x40))
                }
                (success, output) = PANCAKESWAP_NFT_MARKET.call{value: value}(
                    abi.encodeWithSelector(IPancakeNFTMarket.buyTokenUsingBNB.selector, collection, tokenId)
                );
                if (!success) output = abi.encodePacked(BuyPancakeNFTFailed.selector);
            } else if (command == Commands.PANCAKE_NFT_WBNB) {
                address collection;
                uint256 tokenId;
                uint256 price;
                assembly {
                    collection := calldataload(inputs.offset)
                    tokenId := calldataload(add(inputs.offset, 0x20))
                    price := calldataload(add(inputs.offset, 0x40))
                }
                IPancakeNFTMarket(PANCAKESWAP_NFT_MARKET).buyTokenUsingWBNB(collection, tokenId, price);
            } else {
                revert InvalidCommandType(command);
            }
        }
    }
    function execute(bytes calldata commands, bytes[] calldata inputs) external payable virtual;
    function callAndTransfer721(bytes calldata inputs, address protocol)
        internal
        returns (bool success, bytes memory output)
    {
        (uint256 value, bytes calldata data) = getValueAndData(inputs);
        address recipient;
        address token;
        uint256 id;
        assembly {
            recipient := calldataload(add(inputs.offset, 0x40))
            token := calldataload(add(inputs.offset, 0x60))
            id := calldataload(add(inputs.offset, 0x80))
        }
        (success, output) = protocol.call{value: value}(data);
        if (success) ERC721(token).safeTransferFrom(address(this), map(recipient), id);
    }
    function callAndTransfer1155(bytes calldata inputs, address protocol)
        internal
        returns (bool success, bytes memory output)
    {
        (uint256 value, bytes calldata data) = getValueAndData(inputs);
        address recipient;
        address token;
        uint256 id;
        uint256 amount;
        assembly {
            recipient := calldataload(add(inputs.offset, 0x40))
            token := calldataload(add(inputs.offset, 0x60))
            id := calldataload(add(inputs.offset, 0x80))
            amount := calldataload(add(inputs.offset, 0xa0))
        }
        (success, output) = protocol.call{value: value}(data);
        if (success) ERC1155(token).safeTransferFrom(address(this), map(recipient), id, amount, new bytes(0));
    }
    function getValueAndData(bytes calldata inputs) internal pure returns (uint256 value, bytes calldata data) {
        assembly {
            value := calldataload(inputs.offset)
        }
        data = inputs.toBytes(1);
    }
}
pragma solidity ^0.8.0;
import "../utils/Context.sol";
abstract contract Pausable is Context {
    event Paused(address account);
    event Unpaused(address account);
    bool private _paused;
    constructor() {
        _paused = false;
    }
    modifier whenNotPaused() {
        _requireNotPaused();
        _;
    }
    modifier whenPaused() {
        _requirePaused();
        _;
    }
    function paused() public view virtual returns (bool) {
        return _paused;
    }
    function _requireNotPaused() internal view virtual {
        require(!paused(), "Pausable: paused");
    }
    function _requirePaused() internal view virtual {
        require(paused(), "Pausable: not paused");
    }
    function _pause() internal virtual whenNotPaused {
        _paused = true;
        emit Paused(_msgSender());
    }
    function _unpause() internal virtual whenPaused {
        _paused = false;
        emit Unpaused(_msgSender());
    }
}
pragma solidity ^0.8.15;
import {ERC20} from 'solmate/src/tokens/ERC20.sol';
import {SafeTransferLib} from 'solmate/src/utils/SafeTransferLib.sol';
import {RouterImmutables} from './RouterImmutables.sol';
import {IRewardsCollector} from '../interfaces/IRewardsCollector.sol';
abstract contract RewardsCollector is IRewardsCollector, RouterImmutables {
    using SafeTransferLib for ERC20;
    event RewardsSent(uint256 amount);
    error UnableToClaim();
    function collectRewards(bytes calldata looksRareClaim) external {
        (bool success,) = LOOKS_RARE_REWARDS_DISTRIBUTOR.call(looksRareClaim);
        if (!success) revert UnableToClaim();
        uint256 balance = LOOKS_RARE_TOKEN.balanceOf(address(this));
        LOOKS_RARE_TOKEN.safeTransfer(ROUTER_REWARDS_DISTRIBUTOR, balance);
        emit RewardsSent(balance);
    }
}
pragma solidity ^0.8.17;
import {IAllowanceTransfer} from '../permit2/src/interfaces/IAllowanceTransfer.sol';
import {ERC20} from 'solmate/src/tokens/ERC20.sol';
import {IWETH9} from '../interfaces/IWETH9.sol';
struct RouterParameters {
    address permit2;
    address weth9;
    address seaportV1_5;
    address seaportV1_4;
    address openseaConduit;
    address x2y2;
    address looksRareV2;
    address routerRewardsDistributor;
    address looksRareRewardsDistributor;
    address looksRareToken;
    address v2Factory;
    address v3Factory;
    address v3Deployer;
    bytes32 v2InitCodeHash;
    bytes32 v3InitCodeHash;
    address stableFactory;
    address stableInfo;
    address pancakeNFTMarket;
}
contract RouterImmutables {
    IWETH9 internal immutable WETH9;
    IAllowanceTransfer internal immutable PERMIT2;
    address internal immutable SEAPORT_V1_5;
    address internal immutable SEAPORT_V1_4;
    address internal immutable OPENSEA_CONDUIT;
    address internal immutable X2Y2;
    address internal immutable LOOKS_RARE_V2;
    ERC20 internal immutable LOOKS_RARE_TOKEN;
    address internal immutable LOOKS_RARE_REWARDS_DISTRIBUTOR;
    address internal immutable ROUTER_REWARDS_DISTRIBUTOR;
    address internal immutable PANCAKESWAP_V2_FACTORY;
    bytes32 internal immutable PANCAKESWAP_V2_PAIR_INIT_CODE_HASH;
    address internal immutable PANCAKESWAP_V3_FACTORY;
    bytes32 internal immutable PANCAKESWAP_V3_POOL_INIT_CODE_HASH;
    address internal immutable PANCAKESWAP_V3_DEPLOYER;
    address internal immutable PANCAKESWAP_NFT_MARKET;
    enum Spenders {
        OSConduit
    }
    constructor(RouterParameters memory params) {
        PERMIT2 = IAllowanceTransfer(params.permit2);
        WETH9 = IWETH9(params.weth9);
        SEAPORT_V1_5 = params.seaportV1_5;
        SEAPORT_V1_4 = params.seaportV1_4;
        OPENSEA_CONDUIT = params.openseaConduit;
        X2Y2 = params.x2y2;
        LOOKS_RARE_V2 = params.looksRareV2;
        LOOKS_RARE_TOKEN = ERC20(params.looksRareToken);
        LOOKS_RARE_REWARDS_DISTRIBUTOR = params.looksRareRewardsDistributor;
        ROUTER_REWARDS_DISTRIBUTOR = params.routerRewardsDistributor;
        PANCAKESWAP_V2_FACTORY = params.v2Factory;
        PANCAKESWAP_V2_PAIR_INIT_CODE_HASH = params.v2InitCodeHash;
        PANCAKESWAP_V3_FACTORY = params.v3Factory;
        PANCAKESWAP_V3_POOL_INIT_CODE_HASH = params.v3InitCodeHash;
        PANCAKESWAP_V3_DEPLOYER = params.v3Deployer;
        PANCAKESWAP_NFT_MARKET = params.pancakeNFTMarket;
    }
}
pragma solidity >=0.8.0;
import {IUniswapV2Pair} from '@uniswap/v2-core/contracts/interfaces/IUniswapV2Pair.sol';
import {IPancakeV3Pool} from '@pancakeswap/v3-core/contracts/interfaces/IPancakeV3Pool.sol';
import {IStableSwapFactory} from '../interfaces/IStableSwapFactory.sol';
import {IStableSwapInfo} from '../interfaces/IStableSwapInfo.sol';
import {BytesLib} from './BytesLib.sol';
import {Constants} from './Constants.sol';
library UniversalRouterHelper {
    using BytesLib for bytes;
    error InvalidPoolAddress();
    error InvalidPoolLength();
    error InvalidReserves();
    error InvalidPath();
    function getStableInfo(
        address stableSwapFactory,
        address input,
        address output,
        uint256 flag
    ) internal view returns (uint256 i, uint256 j, address swapContract) {
        if (flag == 2) {
            IStableSwapFactory.StableSwapPairInfo memory info = IStableSwapFactory(stableSwapFactory).getPairInfo(input, output);
            i = input == info.token0 ? 0 : 1;
            j = (i == 0) ? 1 : 0;
            swapContract = info.swapContract;
        } else if (flag == 3) {
            IStableSwapFactory.StableSwapThreePoolPairInfo memory info = IStableSwapFactory(stableSwapFactory).getThreePoolPairInfo(input, output);
            if (input == info.token0) i = 0;
            else if (input == info.token1) i = 1;
            else if (input == info.token2) i = 2;
            if (output == info.token0) j = 0;
            else if (output == info.token1) j = 1;
            else if (output == info.token2) j = 2;
            swapContract = info.swapContract;
        }
        if (swapContract == address(0)) revert InvalidPoolAddress();
    }
    function getStableAmountsIn(
        address stableSwapFactory,
        address stableSwapInfo,
        address[] calldata path,
        uint256[] calldata flag,
        uint256 amountOut
    ) internal view returns (uint256[] memory amounts) {
        uint256 length = path.length;
        if (length < 2) revert InvalidPoolLength();
        amounts = new uint256[](length);
        amounts[length - 1] = amountOut;
        for (uint256 i = length - 1; i > 0; i--) {
            uint256 last = i - 1;
            (uint256 k, uint256 j, address swapContract) = getStableInfo(stableSwapFactory, path[last], path[i], flag[last]);
            amounts[last] = IStableSwapInfo(stableSwapInfo).get_dx(swapContract, k, j, amounts[i], type(uint256).max);
        }
    }
    function sortTokens(address tokenA, address tokenB) internal pure returns (address token0, address token1) {
        (token0, token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
    }
    function pairForPreSorted(address factory, bytes32 initCodeHash, address token0, address token1)
        private
        pure
        returns (address pair)
    {
        pair = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(hex'ff', factory, keccak256(abi.encodePacked(token0, token1)), initCodeHash)
                    )
                )
            )
        );
    }
    function pairFor(address factory, bytes32 initCodeHash, address tokenA, address tokenB)
        internal
        pure
        returns (address pair)
    {
        (address token0, address token1) = sortTokens(tokenA, tokenB);
        pair = pairForPreSorted(factory, initCodeHash, token0, token1);
    }
    function pairAndToken0For(address factory, bytes32 initCodeHash, address tokenA, address tokenB)
        internal
        pure
        returns (address pair, address token0)
    {
        address token1;
        (token0, token1) = sortTokens(tokenA, tokenB);
        pair = pairForPreSorted(factory, initCodeHash, token0, token1);
    }
    function pairAndReservesFor(address factory, bytes32 initCodeHash, address tokenA, address tokenB)
        private
        view
        returns (address pair, uint256 reserveA, uint256 reserveB)
    {
        address token0;
        (pair, token0) = pairAndToken0For(factory, initCodeHash, tokenA, tokenB);
        (uint256 reserve0, uint256 reserve1,) = IUniswapV2Pair(pair).getReserves();
        (reserveA, reserveB) = tokenA == token0 ? (reserve0, reserve1) : (reserve1, reserve0);
    }
    function getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut)
        internal
        pure
        returns (uint256 amountOut)
    {
        if (reserveIn == 0 || reserveOut == 0) revert InvalidReserves();
        uint256 amountInWithFee = amountIn * 9975;
        uint256 numerator = amountInWithFee * reserveOut;
        uint256 denominator = reserveIn * 10000 + amountInWithFee;
        amountOut = numerator / denominator;
    }
    function getAmountIn(uint256 amountOut, uint256 reserveIn, uint256 reserveOut)
        internal
        pure
        returns (uint256 amountIn)
    {
        if (reserveIn == 0 || reserveOut == 0) revert InvalidReserves();
        uint256 numerator = reserveIn * amountOut * 10000;
        uint256 denominator = (reserveOut - amountOut) * 9975;
        amountIn = (numerator / denominator) + 1;
    }
    function getAmountInMultihop(address factory, bytes32 initCodeHash, uint256 amountOut, address[] calldata path)
        internal
        view
        returns (uint256 amount, address pair)
    {
        if (path.length < 2) revert InvalidPath();
        amount = amountOut;
        for (uint256 i = path.length - 1; i > 0; i--) {
            uint256 reserveIn;
            uint256 reserveOut;
            (pair, reserveIn, reserveOut) = pairAndReservesFor(factory, initCodeHash, path[i - 1], path[i]);
            amount = getAmountIn(amount, reserveIn, reserveOut);
        }
    }
    function hasMultiplePools(bytes calldata path) internal pure returns (bool) {
        return path.length >= Constants.MULTIPLE_V3_POOLS_MIN_LENGTH;
    }
    function decodeFirstPool(bytes calldata path) internal pure returns (address, uint24, address) {
        return path.toPool();
    }
    function getFirstPool(bytes calldata path) internal pure returns (bytes calldata) {
        return path[:Constants.V3_POP_OFFSET];
    }
    function decodeFirstToken(bytes calldata path) internal pure returns (address tokenA) {
        tokenA = path.toAddress();
    }
    function skipToken(bytes calldata path) internal pure returns (bytes calldata) {
        return path[Constants.NEXT_V3_POOL_OFFSET:];
    }
    function computePoolAddress(
        address deployer, 
        bytes32 initCodeHash, 
        address tokenA, 
        address tokenB, 
        uint24 fee
    ) internal pure returns (address pool) {
        if (tokenA > tokenB) (tokenA, tokenB) = (tokenB, tokenA);
        pool = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            hex'ff',
                            deployer,
                            keccak256(abi.encode(tokenA, tokenB, fee)),
                            initCodeHash
                        )
                    )
                )
            )
        );
    }
}
pragma solidity ^0.8.17;
import {IUniswapV2Pair} from '@uniswap/v2-core/contracts/interfaces/IUniswapV2Pair.sol';
import {RouterImmutables} from '../../base/RouterImmutables.sol';
import {Payments} from '../Payments.sol';
import {Permit2Payments} from '../Permit2Payments.sol';
import {Constants} from '../../libraries/Constants.sol';
import {UniversalRouterHelper} from '../../libraries/UniversalRouterHelper.sol';
import {ERC20} from 'solmate/src/tokens/ERC20.sol';
abstract contract V2SwapRouter is RouterImmutables, Permit2Payments {
    error V2TooLittleReceived();
    error V2TooMuchRequested();
    error V2InvalidPath();
    function _v2Swap(address[] calldata path, address recipient, address pair) private {
        unchecked {
            if (path.length < 2) revert V2InvalidPath();
            (address token0,) = UniversalRouterHelper.sortTokens(path[0], path[1]);
            uint256 finalPairIndex = path.length - 1;
            uint256 penultimatePairIndex = finalPairIndex - 1;
            for (uint256 i; i < finalPairIndex; i++) {
                (address input, address output) = (path[i], path[i + 1]);
                (uint256 reserve0, uint256 reserve1,) = IUniswapV2Pair(pair).getReserves();
                (uint256 reserveInput, uint256 reserveOutput) =
                    input == token0 ? (reserve0, reserve1) : (reserve1, reserve0);
                uint256 amountInput = ERC20(input).balanceOf(pair) - reserveInput;
                uint256 amountOutput = UniversalRouterHelper.getAmountOut(amountInput, reserveInput, reserveOutput);
                (uint256 amount0Out, uint256 amount1Out) =
                    input == token0 ? (uint256(0), amountOutput) : (amountOutput, uint256(0));
                address nextPair;
                (nextPair, token0) = i < penultimatePairIndex
                    ? UniversalRouterHelper.pairAndToken0For(
                        PANCAKESWAP_V2_FACTORY, PANCAKESWAP_V2_PAIR_INIT_CODE_HASH, output, path[i + 2]
                    )
                    : (recipient, address(0));
                IUniswapV2Pair(pair).swap(amount0Out, amount1Out, nextPair, new bytes(0));
                pair = nextPair;
            }
        }
    }
    function v2SwapExactInput(
        address recipient,
        uint256 amountIn,
        uint256 amountOutMinimum,
        address[] calldata path,
        address payer
    ) internal {
        address firstPair =
            UniversalRouterHelper.pairFor(PANCAKESWAP_V2_FACTORY, PANCAKESWAP_V2_PAIR_INIT_CODE_HASH, path[0], path[1]);
        if (
            amountIn != Constants.ALREADY_PAID 
        ) {
            payOrPermit2Transfer(path[0], payer, firstPair, amountIn);
        }
        ERC20 tokenOut = ERC20(path[path.length - 1]);
        uint256 balanceBefore = tokenOut.balanceOf(recipient);
        _v2Swap(path, recipient, firstPair);
        uint256 amountOut = tokenOut.balanceOf(recipient) - balanceBefore;
        if (amountOut < amountOutMinimum) revert V2TooLittleReceived();
    }
    function v2SwapExactOutput(
        address recipient,
        uint256 amountOut,
        uint256 amountInMaximum,
        address[] calldata path,
        address payer
    ) internal {
        (uint256 amountIn, address firstPair) =
            UniversalRouterHelper.getAmountInMultihop(PANCAKESWAP_V2_FACTORY, PANCAKESWAP_V2_PAIR_INIT_CODE_HASH, amountOut, path);
        if (amountIn > amountInMaximum) revert V2TooMuchRequested();
        payOrPermit2Transfer(path[0], payer, firstPair, amountIn);
        _v2Swap(path, recipient, firstPair);
    }
}
pragma solidity ^0.8.0;
import "../utils/Context.sol";
abstract contract Ownable is Context {
    address private _owner;
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    constructor() {
        _transferOwnership(_msgSender());
    }
    modifier onlyOwner() {
        _checkOwner();
        _;
    }
    function owner() public view virtual returns (address) {
        return _owner;
    }
    function _checkOwner() internal view virtual {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
    }
    function renounceOwnership() public virtual onlyOwner {
        _transferOwnership(address(0));
    }
    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        _transferOwnership(newOwner);
    }
    function _transferOwnership(address newOwner) internal virtual {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}
pragma solidity ^0.8.17;
import {SafeCast} from '@pancakeswap/v3-core/contracts/libraries/SafeCast.sol';
import {IPancakeV3Pool} from '@pancakeswap/v3-core/contracts/interfaces/IPancakeV3Pool.sol';
import {IPancakeV3SwapCallback} from '@pancakeswap/v3-core/contracts/interfaces/callback/IPancakeV3SwapCallback.sol';
import {BytesLib} from '../../libraries/BytesLib.sol';
import {Constants} from '../../libraries/Constants.sol';
import {UniversalRouterHelper} from '../../libraries/UniversalRouterHelper.sol';
import {RouterImmutables} from '../../base/RouterImmutables.sol';
import {Permit2Payments} from '../Permit2Payments.sol';
import {ERC20} from 'solmate/src/tokens/ERC20.sol';
abstract contract V3SwapRouter is RouterImmutables, Permit2Payments, IPancakeV3SwapCallback {
    using UniversalRouterHelper for bytes;
    using BytesLib for bytes;
    using SafeCast for uint256;
    error V3InvalidSwap();
    error V3TooLittleReceived();
    error V3TooMuchRequested();
    error V3InvalidAmountOut();
    error V3InvalidCaller();
    uint256 private constant DEFAULT_MAX_AMOUNT_IN = type(uint256).max;
    uint256 private maxAmountInCached = DEFAULT_MAX_AMOUNT_IN;
    uint160 internal constant MIN_SQRT_RATIO = 4295128739;
    uint160 internal constant MAX_SQRT_RATIO = 1461446703485210103287273052203988822378723970342;
    function pancakeV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes calldata data) external {
        if (amount0Delta <= 0 && amount1Delta <= 0) revert V3InvalidSwap(); 
        (, address payer) = abi.decode(data, (bytes, address));
        bytes calldata path = data.toBytes(0);
        (address tokenIn, uint24 fee, address tokenOut) = path.decodeFirstPool();
        if (UniversalRouterHelper.computePoolAddress(PANCAKESWAP_V3_DEPLOYER, PANCAKESWAP_V3_POOL_INIT_CODE_HASH, tokenIn, tokenOut, fee) != msg.sender) revert V3InvalidCaller();
        (bool isExactInput, uint256 amountToPay) =
            amount0Delta > 0 ? (tokenIn < tokenOut, uint256(amount0Delta)) : (tokenOut < tokenIn, uint256(amount1Delta));
        if (isExactInput) {
            payOrPermit2Transfer(tokenIn, payer, msg.sender, amountToPay);
        } else {
            if (path.hasMultiplePools()) {
                path = path.skipToken();
                _swap(-amountToPay.toInt256(), msg.sender, path, payer, false);
            } else {
                if (amountToPay > maxAmountInCached) revert V3TooMuchRequested();
                payOrPermit2Transfer(tokenOut, payer, msg.sender, amountToPay);
            }
        }
    }
    function v3SwapExactInput(
        address recipient,
        uint256 amountIn,
        uint256 amountOutMinimum,
        bytes calldata path,
        address payer
    ) internal {
        if (amountIn == Constants.CONTRACT_BALANCE) {
            address tokenIn = path.decodeFirstToken();
            amountIn = ERC20(tokenIn).balanceOf(address(this));
        }
        uint256 amountOut;
        while (true) {
            bool hasMultiplePools = path.hasMultiplePools();
            (int256 amount0Delta, int256 amount1Delta, bool zeroForOne) = _swap(
                amountIn.toInt256(),
                hasMultiplePools ? address(this) : recipient, 
                path.getFirstPool(), 
                payer, 
                true
            );
            amountIn = uint256(-(zeroForOne ? amount1Delta : amount0Delta));
            if (hasMultiplePools) {
                payer = address(this);
                path = path.skipToken();
            } else {
                amountOut = amountIn;
                break;
            }
        }
        if (amountOut < amountOutMinimum) revert V3TooLittleReceived();
    }
    function v3SwapExactOutput(
        address recipient,
        uint256 amountOut,
        uint256 amountInMaximum,
        bytes calldata path,
        address payer
    ) internal {
        maxAmountInCached = amountInMaximum;
        (int256 amount0Delta, int256 amount1Delta, bool zeroForOne) =
            _swap(-amountOut.toInt256(), recipient, path, payer, false);
        uint256 amountOutReceived = zeroForOne ? uint256(-amount1Delta) : uint256(-amount0Delta);
        if (amountOutReceived != amountOut) revert V3InvalidAmountOut();
        maxAmountInCached = DEFAULT_MAX_AMOUNT_IN;
    }
    function _swap(int256 amount, address recipient, bytes calldata path, address payer, bool isExactIn)
        private
        returns (int256 amount0Delta, int256 amount1Delta, bool zeroForOne)
    {
        (address tokenIn, uint24 fee, address tokenOut) = path.decodeFirstPool();
        zeroForOne = isExactIn ? tokenIn < tokenOut : tokenOut < tokenIn;
        (amount0Delta, amount1Delta) = IPancakeV3Pool(UniversalRouterHelper.computePoolAddress(PANCAKESWAP_V3_DEPLOYER, PANCAKESWAP_V3_POOL_INIT_CODE_HASH, tokenIn, tokenOut, fee)).swap(
            recipient,
            zeroForOne,
            amount,
            (zeroForOne ? MIN_SQRT_RATIO + 1 : MAX_SQRT_RATIO - 1),
            abi.encode(path, payer)
        );
    }
}
pragma solidity ^0.8.15;
import {ERC20} from 'solmate/src/tokens/ERC20.sol';
interface IRewardsCollector {
    function collectRewards(bytes calldata looksRareClaim) external;
}
pragma solidity ^0.8.0;
interface IStableSwapInfo {
    function get_dx(
        address _swap,
        uint256 i,
        uint256 j,
        uint256 dy,
        uint256 max_dx
    ) external view returns (uint256);
}
pragma solidity ^0.8.17;
import {Constants} from '../libraries/Constants.sol';
import {RouterImmutables} from '../base/RouterImmutables.sol';
import {SafeTransferLib} from 'solmate/src/utils/SafeTransferLib.sol';
import {ERC20} from 'solmate/src/tokens/ERC20.sol';
import {ERC721} from 'solmate/src/tokens/ERC721.sol';
import {ERC1155} from 'solmate/src/tokens/ERC1155.sol';
abstract contract Payments is RouterImmutables {
    using SafeTransferLib for ERC20;
    using SafeTransferLib for address;
    error InsufficientToken();
    error InsufficientETH();
    error InvalidBips();
    error InvalidSpender();
    uint256 internal constant FEE_BIPS_BASE = 10_000;
    function pay(address token, address recipient, uint256 value) internal {
        if (token == Constants.ETH) {
            recipient.safeTransferETH(value);
        } else {
            if (value == Constants.CONTRACT_BALANCE) {
                value = ERC20(token).balanceOf(address(this));
            }
            ERC20(token).safeTransfer(recipient, value);
        }
    }
    function approveERC20(ERC20 token, Spenders spender) internal {
        address spenderAddress;
        if (spender == Spenders.OSConduit) spenderAddress = OPENSEA_CONDUIT;
        else revert InvalidSpender();
        token.safeApprove(spenderAddress, type(uint256).max);
    }
    function payPortion(address token, address recipient, uint256 bips) internal {
        if (bips == 0 || bips > FEE_BIPS_BASE) revert InvalidBips();
        if (token == Constants.ETH) {
            uint256 balance = address(this).balance;
            uint256 amount = (balance * bips) / FEE_BIPS_BASE;
            recipient.safeTransferETH(amount);
        } else {
            uint256 balance = ERC20(token).balanceOf(address(this));
            uint256 amount = (balance * bips) / FEE_BIPS_BASE;
            ERC20(token).safeTransfer(recipient, amount);
        }
    }
    function sweep(address token, address recipient, uint256 amountMinimum) internal {
        uint256 balance;
        if (token == Constants.ETH) {
            balance = address(this).balance;
            if (balance < amountMinimum) revert InsufficientETH();
            if (balance > 0) recipient.safeTransferETH(balance);
        } else {
            balance = ERC20(token).balanceOf(address(this));
            if (balance < amountMinimum) revert InsufficientToken();
            if (balance > 0) ERC20(token).safeTransfer(recipient, balance);
        }
    }
    function sweepERC721(address token, address recipient, uint256 id) internal {
        ERC721(token).safeTransferFrom(address(this), recipient, id);
    }
    function sweepERC1155(address token, address recipient, uint256 id, uint256 amountMinimum) internal {
        uint256 balance = ERC1155(token).balanceOf(address(this), id);
        if (balance < amountMinimum) revert InsufficientToken();
        ERC1155(token).safeTransferFrom(address(this), recipient, id, balance, bytes(''));
    }
    function wrapETH(address recipient, uint256 amount) internal {
        if (amount == Constants.CONTRACT_BALANCE) {
            amount = address(this).balance;
        } else if (amount > address(this).balance) {
            revert InsufficientETH();
        }
        if (amount > 0) {
            WETH9.deposit{value: amount}();
            if (recipient != address(this)) {
                WETH9.transfer(recipient, amount);
            }
        }
    }
    function unwrapWETH9(address recipient, uint256 amountMinimum) internal {
        uint256 value = WETH9.balanceOf(address(this));
        if (value < amountMinimum) {
            revert InsufficientETH();
        }
        if (value > 0) {
            WETH9.withdraw(value);
            if (recipient != address(this)) {
                recipient.safeTransferETH(value);
            }
        }
    }
}
pragma solidity ^0.8.0;
interface IERC721Receiver {
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}
pragma solidity >=0.8.0;
abstract contract ERC1155 {
    event TransferSingle(
        address indexed operator,
        address indexed from,
        address indexed to,
        uint256 id,
        uint256 amount
    );
    event TransferBatch(
        address indexed operator,
        address indexed from,
        address indexed to,
        uint256[] ids,
        uint256[] amounts
    );
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);
    event URI(string value, uint256 indexed id);
    mapping(address => mapping(uint256 => uint256)) public balanceOf;
    mapping(address => mapping(address => bool)) public isApprovedForAll;
    function uri(uint256 id) public view virtual returns (string memory);
    function setApprovalForAll(address operator, bool approved) public virtual {
        isApprovedForAll[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }
    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes calldata data
    ) public virtual {
        require(msg.sender == from || isApprovedForAll[from][msg.sender], "NOT_AUTHORIZED");
        balanceOf[from][id] -= amount;
        balanceOf[to][id] += amount;
        emit TransferSingle(msg.sender, from, to, id, amount);
        require(
            to.code.length == 0
                ? to != address(0)
                : ERC1155TokenReceiver(to).onERC1155Received(msg.sender, from, id, amount, data) ==
                    ERC1155TokenReceiver.onERC1155Received.selector,
            "UNSAFE_RECIPIENT"
        );
    }
    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata amounts,
        bytes calldata data
    ) public virtual {
        require(ids.length == amounts.length, "LENGTH_MISMATCH");
        require(msg.sender == from || isApprovedForAll[from][msg.sender], "NOT_AUTHORIZED");
        uint256 id;
        uint256 amount;
        for (uint256 i = 0; i < ids.length; ) {
            id = ids[i];
            amount = amounts[i];
            balanceOf[from][id] -= amount;
            balanceOf[to][id] += amount;
            unchecked {
                ++i;
            }
        }
        emit TransferBatch(msg.sender, from, to, ids, amounts);
        require(
            to.code.length == 0
                ? to != address(0)
                : ERC1155TokenReceiver(to).onERC1155BatchReceived(msg.sender, from, ids, amounts, data) ==
                    ERC1155TokenReceiver.onERC1155BatchReceived.selector,
            "UNSAFE_RECIPIENT"
        );
    }
    function balanceOfBatch(address[] calldata owners, uint256[] calldata ids)
        public
        view
        virtual
        returns (uint256[] memory balances)
    {
        require(owners.length == ids.length, "LENGTH_MISMATCH");
        balances = new uint256[](owners.length);
        unchecked {
            for (uint256 i = 0; i < owners.length; ++i) {
                balances[i] = balanceOf[owners[i]][ids[i]];
            }
        }
    }
    function supportsInterface(bytes4 interfaceId) public view virtual returns (bool) {
        return
            interfaceId == 0x01ffc9a7 || 
            interfaceId == 0xd9b67a26 || 
            interfaceId == 0x0e89341c; 
    }
    function _mint(
        address to,
        uint256 id,
        uint256 amount,
        bytes memory data
    ) internal virtual {
        balanceOf[to][id] += amount;
        emit TransferSingle(msg.sender, address(0), to, id, amount);
        require(
            to.code.length == 0
                ? to != address(0)
                : ERC1155TokenReceiver(to).onERC1155Received(msg.sender, address(0), id, amount, data) ==
                    ERC1155TokenReceiver.onERC1155Received.selector,
            "UNSAFE_RECIPIENT"
        );
    }
    function _batchMint(
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) internal virtual {
        uint256 idsLength = ids.length; 
        require(idsLength == amounts.length, "LENGTH_MISMATCH");
        for (uint256 i = 0; i < idsLength; ) {
            balanceOf[to][ids[i]] += amounts[i];
            unchecked {
                ++i;
            }
        }
        emit TransferBatch(msg.sender, address(0), to, ids, amounts);
        require(
            to.code.length == 0
                ? to != address(0)
                : ERC1155TokenReceiver(to).onERC1155BatchReceived(msg.sender, address(0), ids, amounts, data) ==
                    ERC1155TokenReceiver.onERC1155BatchReceived.selector,
            "UNSAFE_RECIPIENT"
        );
    }
    function _batchBurn(
        address from,
        uint256[] memory ids,
        uint256[] memory amounts
    ) internal virtual {
        uint256 idsLength = ids.length; 
        require(idsLength == amounts.length, "LENGTH_MISMATCH");
        for (uint256 i = 0; i < idsLength; ) {
            balanceOf[from][ids[i]] -= amounts[i];
            unchecked {
                ++i;
            }
        }
        emit TransferBatch(msg.sender, from, address(0), ids, amounts);
    }
    function _burn(
        address from,
        uint256 id,
        uint256 amount
    ) internal virtual {
        balanceOf[from][id] -= amount;
        emit TransferSingle(msg.sender, from, address(0), id, amount);
    }
}
abstract contract ERC1155TokenReceiver {
    function onERC1155Received(
        address,
        address,
        uint256,
        uint256,
        bytes calldata
    ) external virtual returns (bytes4) {
        return ERC1155TokenReceiver.onERC1155Received.selector;
    }
    function onERC1155BatchReceived(
        address,
        address,
        uint256[] calldata,
        uint256[] calldata,
        bytes calldata
    ) external virtual returns (bytes4) {
        return ERC1155TokenReceiver.onERC1155BatchReceived.selector;
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
pragma solidity ^0.8.0;
interface IERC165 {
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}
pragma solidity >=0.5.0;
import './pool/IPancakeV3PoolImmutables.sol';
import './pool/IPancakeV3PoolState.sol';
import './pool/IPancakeV3PoolDerivedState.sol';
import './pool/IPancakeV3PoolActions.sol';
import './pool/IPancakeV3PoolOwnerActions.sol';
import './pool/IPancakeV3PoolEvents.sol';
interface IPancakeV3Pool is
    IPancakeV3PoolImmutables,
    IPancakeV3PoolState,
    IPancakeV3PoolDerivedState,
    IPancakeV3PoolActions,
    IPancakeV3PoolOwnerActions,
    IPancakeV3PoolEvents
{
}
pragma solidity >=0.5.0;
interface IPancakeV3PoolImmutables {
    function factory() external view returns (address);
    function token0() external view returns (address);
    function token1() external view returns (address);
    function fee() external view returns (uint24);
    function tickSpacing() external view returns (int24);
    function maxLiquidityPerTick() external view returns (uint128);
}
pragma solidity ^0.8.17;
import {IERC721Receiver} from '@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol';
import {IERC1155Receiver} from '@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol';
import {IRewardsCollector} from './IRewardsCollector.sol';
interface IUniversalRouter is IRewardsCollector, IERC721Receiver, IERC1155Receiver {
    error ExecutionFailed(uint256 commandIndex, bytes message);
    error ETHNotAccepted();
    error TransactionDeadlinePassed();
    error LengthMismatch();
    function execute(bytes calldata commands, bytes[] calldata inputs, uint256 deadline) external payable;
}
pragma solidity >=0.5.0;
interface IPancakeV3PoolOwnerActions {
    function setFeeProtocol(uint32 feeProtocol0, uint32 feeProtocol1) external;
    function collectProtocol(
        address recipient,
        uint128 amount0Requested,
        uint128 amount1Requested
    ) external returns (uint128 amount0, uint128 amount1);
    function setLmPool(address lmPool) external;
}
pragma solidity ^0.8.17;
library Commands {
    bytes1 internal constant FLAG_ALLOW_REVERT = 0x80;
    bytes1 internal constant COMMAND_TYPE_MASK = 0x3f;
    uint256 constant V3_SWAP_EXACT_IN = 0x00;
    uint256 constant V3_SWAP_EXACT_OUT = 0x01;
    uint256 constant PERMIT2_TRANSFER_FROM = 0x02;
    uint256 constant PERMIT2_PERMIT_BATCH = 0x03;
    uint256 constant SWEEP = 0x04;
    uint256 constant TRANSFER = 0x05;
    uint256 constant PAY_PORTION = 0x06;
    uint256 constant FIRST_IF_BOUNDARY = 0x08;
    uint256 constant V2_SWAP_EXACT_IN = 0x08;
    uint256 constant V2_SWAP_EXACT_OUT = 0x09;
    uint256 constant PERMIT2_PERMIT = 0x0a;
    uint256 constant WRAP_ETH = 0x0b;
    uint256 constant UNWRAP_WETH = 0x0c;
    uint256 constant PERMIT2_TRANSFER_FROM_BATCH = 0x0d;
    uint256 constant BALANCE_CHECK_ERC20 = 0x0e;
    uint256 constant SECOND_IF_BOUNDARY = 0x10;
    uint256 constant OWNER_CHECK_721 = 0x10;
    uint256 constant OWNER_CHECK_1155 = 0x11;
    uint256 constant SWEEP_ERC721 = 0x12;
    uint256 constant SWEEP_ERC1155 = 0x13;
    uint256 constant THIRD_IF_BOUNDARY = 0x18;
    uint256 constant SEAPORT_V1_5 = 0x18;
    uint256 constant SEAPORT_V1_4 = 0x19;
    uint256 constant LOOKS_RARE_V2 = 0x1a;
    uint256 constant X2Y2_721 = 0x1b;
    uint256 constant X2Y2_1155 = 0x1c;
    uint256 constant FOURTH_IF_BOUNDARY = 0x20;
    uint256 constant EXECUTE_SUB_PLAN = 0x20;
    uint256 constant APPROVE_ERC20 = 0x21;
    uint256 constant STABLE_SWAP_EXACT_IN = 0x22;
    uint256 constant STABLE_SWAP_EXACT_OUT = 0x23;
    uint256 constant PANCAKE_NFT_BNB = 0x24;
    uint256 constant PANCAKE_NFT_WBNB = 0x25;        
}
pragma solidity >=0.5.0;
interface IPancakeV3SwapCallback {
    function pancakeV3SwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata data
    ) external;
}
pragma solidity >=0.5.0;
interface IPancakeV3PoolDerivedState {
    function observe(uint32[] calldata secondsAgos)
        external
        view
        returns (int56[] memory tickCumulatives, uint160[] memory secondsPerLiquidityCumulativeX128s);
    function snapshotCumulativesInside(int24 tickLower, int24 tickUpper)
        external
        view
        returns (
            int56 tickCumulativeInside,
            uint160 secondsPerLiquidityInsideX128,
            uint32 secondsInside
        );
}
pragma solidity ^0.8.0;
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }
    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }
}
