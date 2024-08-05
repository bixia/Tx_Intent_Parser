
pragma solidity ^0.8.17;
library Errors {
    string public constant OK = '0'; 
    string public constant PROXY_ID_NOT_EXIST = '1'; 
    string public constant PROXY_ID_ALREADY_EXIST = '2'; 
    string public constant LPAD_ONLY_COLLABORATOR_OWNER = '3'; 
    string public constant LPAD_ONLY_CONTROLLER_COLLABORATOR_OWNER = '4'; 
    string public constant LPAD_ONLY_AUTHORITIES_ADDRESS = '5'; 
    string public constant TRANSFER_ETH_FAILED = '6'; 
    string public constant SENDER_MUST_TX_CALLER = '7'; 
    string public constant LPAD_INVALID_ID  = '10';  
    string public constant LPAD_ID_EXISTS   = '11';  
    string public constant LPAD_RECEIPT_ADDRESS_INVALID = '12'; 
    string public constant LPAD_REFERRAL_FEE_PCT_LIMIT = '13'; 
    string public constant LPAD_RECEIPT_MUST_NOT_CONTRACT = '14'; 
    string public constant LPAD_NOT_ENABLE = '15'; 
    string public constant LPAD_TRANSFER_TO_RECEIPT_FAIL = '16'; 
    string public constant LPAD_TRANSFER_TO_REFERRAL_FAIL = '17'; 
    string public constant LPAD_TRANSFER_BACK_TO_SENDER_FAIL = '18'; 
    string public constant LPAD_INPUT_ARRAY_LEN_NOT_MATCH = '19'; 
    string public constant LPAD_FEES_PERCENT_INVALID = '20'; 
    string public constant LPAD_PARAM_LOCKED = '21'; 
    string public constant LPAD_TRANSFER_TO_LPAD_PROXY_FAIL = '22'; 
    string public constant LPAD_SIMULATE_BUY_OK = '28'; 
    string public constant LPAD_SIMULATE_OPEN_OK = '29'; 
    string public constant LPAD_SLOT_IDX_INVALID = '30'; 
    string public constant LPAD_SLOT_MAX_SUPPLY_INVALID = '31'; 
    string public constant LPAD_SLOT_SALE_QUANTITY = '32'; 
    string public constant LPAD_SLOT_TARGET_CONTRACT_INVALID = '33'; 
    string public constant LPAD_SLOT_ABI_ARRAY_LEN = '34'; 
    string public constant LPAD_SLOT_MAX_BUY_QTY_INVALID = '35'; 
    string public constant LPAD_SLOT_FLAGS_ARRAY_LEN = '36'; 
    string public constant LPAD_SLOT_TOKEN_ADDRESS_INVALID = '37';  
    string public constant LPAD_SLOT_BUY_DISABLE = '38'; 
    string public constant LPAD_SLOT_BUY_FROM_CONTRACT_NOT_ALLOWED = '39'; 
    string public constant LPAD_SLOT_SALE_NOT_START = '40'; 
    string public constant LPAD_SLOT_MAX_BUY_QTY_PER_TX_LIMIT = '41'; 
    string public constant LPAD_SLOT_QTY_NOT_ENOUGH_TO_BUY = '42'; 
    string public constant LPAD_SLOT_PAYMENT_NOT_ENOUGH = '43'; 
    string public constant LPAD_SLOT_PAYMENT_ALLOWANCE_NOT_ENOUGH = '44'; 
    string public constant LPAD_SLOT_ACCOUNT_MAX_BUY_LIMIT = '45'; 
    string public constant LPAD_SLOT_ACCOUNT_BUY_INTERVAL_LIMIT = '46'; 
    string public constant LPAD_SLOT_ACCOUNT_NOT_IN_WHITELIST = '47'; 
    string public constant LPAD_SLOT_OPENBOX_DISABLE = '48'; 
    string public constant LPAD_SLOT_OPENBOX_FROM_CONTRACT_NOT_ALLOWED = '49'; 
    string public constant LPAD_SLOT_ABI_BUY_SELECTOR_INVALID = '50'; 
    string public constant LPAD_SLOT_ABI_OPENBOX_SELECTOR_INVALID = '51'; 
    string public constant LPAD_SLOT_SALE_START_TIME_INVALID = '52'; 
    string public constant LPAD_SLOT_OPENBOX_TIME_INVALID = '53'; 
    string public constant LPAD_SLOT_PRICE_INVALID = '54'; 
    string public constant LPAD_SLOT_CALL_BUY_CONTRACT_FAILED = '55'; 
    string public constant LPAD_SLOT_CALL_OPEN_CONTRACT_FAILED = '56'; 
    string public constant LPAD_SLOT_CALL_0X_ERC20_PROXY_FAILED = '57'; 
    string public constant LPAD_SLOT_0X_ERC20_PROXY_INVALID = '58'; 
    string public constant LPAD_SLOT_ONLY_OPENBOX_WHEN_SOLD_OUT = '59'; 
    string public constant LPAD_SLOT_ERC20_BLC_NOT_ENOUGH = '60'; 
    string public constant LPAD_SLOT_PAY_VALUE_NOT_ENOUGH = '61'; 
    string public constant LPAD_SLOT_PAY_VALUE_NOT_NEED = '62'; 
    string public constant LPAD_SLOT_PAY_VALUE_UPPER_NEED = '63'; 
    string public constant LPAD_SLOT_OPENBOX_NOT_SUPPORT = '64'; 
    string public constant LPAD_SLOT_ERC20_TRANSFER_FAILED = '65'; 
    string public constant LPAD_SLOT_OPEN_NUM_INIT = '66'; 
    string public constant LPAD_SLOT_ABI_NOT_FOUND = '67'; 
    string public constant LPAD_SLOT_SALE_END = '68'; 
    string public constant LPAD_SLOT_SALE_END_TIME_INVALID = '69'; 
    string public constant LPAD_SLOT_WHITELIST_BUY_NUM_LIMIT = '70'; 
    string public constant LPAD_CONTROLLER_NO_PERMISSION = '71'; 
    string public constant LPAD_SLOT_WHITELIST_SALE_NOT_START = '72'; 
    string public constant LPAD_NOT_VALID_SIGNER = '73'; 
    string public constant LPAD_SLOT_WHITELIST_TIME_INVALID = '74'; 
    string public constant LPAD_INVALID_WHITELIST_SIGNATURE_LEN = '75'; 
    string public constant LPAD_SEPARATOR = ':'; 
}
pragma solidity ^0.8.17;
import "../data_type/DataType.sol";
library LibLaunchpadStorage {
    uint256 constant STORAGE_ID_LAUNCHPAD = 2 << 128;
    struct Storage {
        mapping(address => bool) administrators;
        mapping(bytes32 => DataType.LaunchpadSlot) launchpadSlots;
        mapping(bytes32 => DataType.AccountSlotStats) accountSlotStats;
    }
    function getStorage() internal pure returns (Storage storage stor) {
        assembly { stor.slot := STORAGE_ID_LAUNCHPAD }
    }
}
pragma solidity ^0.8.17;
import "../storage/LibOwnableStorage.sol";
abstract contract ReentrancyGuard {
    constructor() {
        LibOwnableStorage.Storage storage stor = LibOwnableStorage.getStorage();
        if (stor.reentrancyStatus == 0) {
            stor.reentrancyStatus = 1;
        }
    }
    modifier nonReentrant() {
        LibOwnableStorage.Storage storage stor = LibOwnableStorage.getStorage();
        require(stor.reentrancyStatus == 1, "ReentrancyGuard: reentrant call");
        stor.reentrancyStatus = 2;
        _;
        stor.reentrancyStatus = 1;
    }
}
pragma solidity ^0.8.17;
import "../storage/LibOwnableStorage.sol";
abstract contract Ownable {
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    constructor() {
        if (owner() == address(0)) {
            _transferOwnership(msg.sender);
        }
    }
    function owner() public view virtual returns (address) {
        return LibOwnableStorage.getStorage().owner;
    }
    modifier onlyOwner() {
        require(owner() == msg.sender, "Ownable: caller is not the owner");
        _;
    }
    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        _transferOwnership(newOwner);
    }
    function _transferOwnership(address newOwner) private {
        LibOwnableStorage.Storage storage stor = LibOwnableStorage.getStorage();
        address oldOwner = stor.owner;
        stor.owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}
pragma solidity ^0.8.17;
library LibOwnableStorage {
    uint256 constant STORAGE_ID_OWNABLE = 1 << 128;
    struct Storage {
        uint256 reentrancyStatus;
        address owner;
    }
    function getStorage() internal pure returns (Storage storage stor) {
        assembly { stor.slot := STORAGE_ID_OWNABLE }
    }
}
pragma solidity ^0.8.17;
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "../data_type/Errors.sol";
import "../data_type/DataType.sol";
import "../storage/LibLaunchpadStorage.sol";
import "../libs/Ownable.sol";
import "../libs/ReentrancyGuard.sol";
import "../libs/FixinTokenSpender.sol";
contract LaunchpadFeature is Ownable, ReentrancyGuard, FixinTokenSpender {
    function launchpadBuy(
        bytes4 ,
        bytes4 launchpadId,
        uint256 slotId,
        uint256 quantity,
        uint256[] calldata additional,
        bytes calldata data
    ) external payable nonReentrant {
        require(tx.origin == msg.sender, "contract call not allowed");
        uint256 ethBalanceBefore = address(this).balance - msg.value;
        uint256 maxWhitelistBuy;
        uint256 simulationBuy;
        if (additional.length > DataType.BUY_ADDITIONAL_IDX_WL_MAX_BUY_NUM) {
            maxWhitelistBuy = additional[DataType.BUY_ADDITIONAL_IDX_WL_MAX_BUY_NUM];
        }
        if (additional.length > DataType.BUY_ADDITIONAL_IDX_SIMULATION) {
            simulationBuy = additional[DataType.BUY_ADDITIONAL_IDX_SIMULATION];
        }
        uint256 payableValue = _launchpadBuy(
            launchpadId, slotId, quantity, maxWhitelistBuy, simulationBuy, data
        );
        require(msg.value == payableValue, Errors.LPAD_SLOT_PAY_VALUE_NOT_ENOUGH);
        if (simulationBuy > DataType.SIMULATION_NONE) {
            revert(Errors.LPAD_SIMULATE_BUY_OK);
        }
        require(address(this).balance >= ethBalanceBefore, "refund error.");
    }
    function launchpadBuys(DataType.BuyParameter[] calldata parameters) external payable nonReentrant {
        require(tx.origin == msg.sender, "contract call not allowed");
        uint256 ethBalanceBefore = address(this).balance - msg.value;
        unchecked {
            uint256 payableValue;
            for (uint256 i; i < parameters.length; i++) {
                payableValue += _launchpadBuy(
                    parameters[i].launchpadId,
                    parameters[i].slotId,
                    parameters[i].quantity,
                    parameters[i].maxWhitelistBuy,
                    DataType.SIMULATION_NONE,
                    parameters[i].data
                );
            }
            require(msg.value == payableValue, Errors.LPAD_SLOT_PAY_VALUE_NOT_ENOUGH);
        }
        require(address(this).balance >= ethBalanceBefore, "refund error.");
    }
    function _launchpadBuy(
        bytes4 launchpadId,
        uint256 slotId,
        uint256 quantity,
        uint256 maxWhitelistBuy,
        uint256 simulationBuy,
        bytes calldata data
    ) internal returns(uint256) {
        require(quantity > 0, "quantity must gt 0");
        require(quantity < type(uint16).max, Errors.LPAD_SLOT_MAX_BUY_QTY_PER_TX_LIMIT);
        DataType.LaunchpadSlot memory slot = _getLaunchpadSlot(launchpadId, slotId);
        (bool success, uint256 alreadyBuyBty) = _getAlreadyBuyBty(slot, msg.sender);
        require(success, "_getAlreadyBuyBty failed");
        if (simulationBuy < DataType.SIMULATION_NO_CHECK_PROCESS_REVERT) {
            _checkLaunchpadBuy(slot, alreadyBuyBty, quantity, maxWhitelistBuy, data, simulationBuy);
            if (simulationBuy == DataType.SIMULATION_CHECK_REVERT) {
                revert(Errors.LPAD_SIMULATE_BUY_OK);
            }
        }
        if (slot.storeSaleQtyFlag) {
            bytes32 key = _getLaunchpadSlotKey(launchpadId, slotId);
            LibLaunchpadStorage.getStorage().launchpadSlots[key].saleQty += uint32(quantity);
        }
        if (slot.storeAccountQtyFlag) {
            bytes32 key = _getAccountStatKey(launchpadId, slotId, msg.sender);
            LibLaunchpadStorage.getStorage().accountSlotStats[key].totalBuyQty += uint16(quantity);
        }
        uint256 currentPrice = _getCurrentPrice(slot);
        uint256 payableValue = _transferFees(slot, quantity, currentPrice);
        _callLaunchpadBuy(slot, quantity, currentPrice, data);
        return payableValue;
    }
    function _getLaunchpadSlot(bytes4 launchpadId, uint256 slotId) internal view returns(DataType.LaunchpadSlot memory slot) {
        bytes32 key = _getLaunchpadSlotKey(launchpadId, slotId);
        slot = LibLaunchpadStorage.getStorage().launchpadSlots[key];
        require(slot.launchpadId == launchpadId, Errors.LPAD_INVALID_ID);
        require(slot.enable, Errors.LPAD_NOT_ENABLE);
        require(uint256(slot.slotId) == slotId, Errors.LPAD_SLOT_IDX_INVALID);
        require(slot.targetContract != address(0), Errors.LPAD_SLOT_TARGET_CONTRACT_INVALID);
        require(slot.mintSelector != bytes4(0), Errors.LPAD_SLOT_ABI_NOT_FOUND);
        if (!slot.storeAccountQtyFlag) {
            require(slot.queryAccountMintedQtySelector != bytes4(0), Errors.LPAD_SLOT_ABI_NOT_FOUND);
        }
    }
    function _getLaunchpadSlotKey(bytes4 launchpadId, uint256 slotId) internal pure returns(bytes32 key) {
        assembly {
            key := or(launchpadId, shl(216, and(slotId, 0xff)))
        }
    }
    function _getAccountStatKey(bytes4 launchpadId, uint256 slotId, address account) internal pure returns(bytes32 key) {
        assembly {
            key := or(or(launchpadId, shl(216, and(slotId, 0xff))), account)
        }
    }
    function _transferFees(DataType.LaunchpadSlot memory slot, uint256 buyQty, uint256 currentPrice) internal returns(uint256) {
        uint256 shouldPay;
        unchecked {
            shouldPay = buyQty * currentPrice;
        }
        if (slot.paymentToken == address(0)) {
            if (shouldPay > 0) {
                if (slot.feeType == 0 && slot.feeReceipt != address(0)) {
                    _transferEth(slot.feeReceipt, shouldPay);
                }
            }
            return shouldPay;
        } else {
            if (shouldPay > 0) {
                require(slot.feeType == 0, "feeType error");
                require(slot.feeReceipt != address(0), "feeReceipt error");
                _transferERC20From(slot.paymentToken, msg.sender, slot.feeReceipt, shouldPay);
            }
            return 0;
        }
    }
    function _callLaunchpadBuy(DataType.LaunchpadSlot memory slot, uint256 buyQty, uint256 currentPrice, bytes calldata data) internal {
        uint256 price;
        if (slot.paymentToken == address(0) && slot.feeType != 0) {
            price = currentPrice;
        }
        uint256 extraOffset;
        if (
            slot.whiteListModel != DataType.WhiteListModel.NONE &&
            (slot.whiteListSaleStart == 0 || block.timestamp < slot.saleStart)
        ) {
            extraOffset = 65;
        }
        if (data.length < extraOffset) {
            revert("extra_data error");
        }
        bytes4 selector = slot.mintSelector;
        address targetContract = slot.targetContract;
        if (slot.mintParams == 0) {
            assembly {
                let extraLength := sub(data.length, extraOffset)
                let calldataLength := add(0x24, extraLength)
                let ptr := mload(0x40) 
                mstore(ptr, selector)
                mstore(add(ptr, 0x04), caller())
                if extraLength {
                    calldatacopy(add(ptr, 0x24), add(data.offset, extraOffset), extraLength)
                }
                for { let i } lt(i, buyQty) { i := add(i, 1) } {
                    if iszero(call(gas(), targetContract, price, ptr, calldataLength, ptr, 0)) {
                        returndatacopy(0, 0, returndatasize())
                        revert(0, returndatasize())
                    }
                }
            }
        } else if (slot.mintParams == 1) {
            assembly {
                let extraLength := sub(data.length, extraOffset)
                let calldataLength := add(0x44, extraLength)
                let ptr := mload(0x40) 
                mstore(ptr, selector)
                mstore(add(ptr, 0x04), caller())
                mstore(add(ptr, 0x24), buyQty)
                if extraLength {
                    calldatacopy(add(ptr, 0x44), add(data.offset, extraOffset), extraLength)
                }
                if iszero(call(gas(), targetContract, mul(buyQty, price), ptr, calldataLength, ptr, 0)) {
                    returndatacopy(0, 0, returndatasize())
                    revert(0, returndatasize())
                }
            }
        } else {
            revert(Errors.LPAD_SLOT_ABI_NOT_FOUND);
        }
    }
    function _getAlreadyBuyBty(
        DataType.LaunchpadSlot memory slot,
        address account
    ) internal view returns(
        bool success,
        uint256 alreadyBuyBty
    ) {
        if (slot.storeAccountQtyFlag) {
            bytes32 key = _getAccountStatKey(slot.launchpadId, slot.slotId, account);
            return (true, LibLaunchpadStorage.getStorage().accountSlotStats[key].totalBuyQty);
        } else {
            bytes4 selector = slot.queryAccountMintedQtySelector;
            address targetContract = slot.targetContract;
            assembly {
                let ptr := mload(0x40) 
                mstore(ptr, selector)
                mstore(add(ptr, 0x04), account)
                if staticcall(gas(), targetContract, ptr, 0x24, ptr, 0x20) {
                    if eq(returndatasize(), 0x20) {
                        success := 1
                        alreadyBuyBty := mload(ptr)
                    }
                }
            }
            return (success, alreadyBuyBty);
        }
    }
    function _getCurrentPrice(DataType.LaunchpadSlot memory slot) internal view returns(uint256) {
        unchecked {
            if (slot.whiteListModel == DataType.WhiteListModel.NONE) {
                return slot.price * (10 ** slot.priceUint);
            } else if (slot.whiteListSaleStart > 0) { 
                uint256 price = (block.timestamp < slot.saleStart) ? slot.pricePresale : slot.price;
                return price * (10 ** slot.priceUint);
            } else { 
                uint256 price = slot.price > 0 ? slot.price : slot.pricePresale;
                return price * (10 ** slot.priceUint);
            }
        }
    }
    function _checkLaunchpadBuy(
        DataType.LaunchpadSlot memory slot,
        uint256 alreadyBuyBty,
        uint256 buyQty,
        uint256 maxWhitelistBuy,
        bytes calldata data,
        uint256 simulateBuy
    ) internal view {
        unchecked {
            if (slot.storeSaleQtyFlag) {
                if (slot.saleQty + buyQty > uint256(slot.maxSupply)) {
                    revert(Errors.LPAD_SLOT_QTY_NOT_ENOUGH_TO_BUY);
                }
            }
            require(block.timestamp < slot.saleEnd, Errors.LPAD_SLOT_SALE_END);
            if (slot.whiteListModel == DataType.WhiteListModel.NONE) {
                if (block.timestamp < slot.saleStart) {
                    if (simulateBuy != DataType.SIMULATION_CHECK_SKIP_START_PROCESS_REVERT) {
                        revert(Errors.LPAD_SLOT_SALE_NOT_START);
                    }
                }
                if (buyQty + alreadyBuyBty > slot.maxBuyQtyPerAccount) {
                    revert(Errors.LPAD_SLOT_ACCOUNT_MAX_BUY_LIMIT);
                }
            } else {
                if (simulateBuy == DataType.SIMULATION_CHECK_SKIP_WHITELIST_PROCESS_REVERT) {
                    return;
                }
                if (slot.whiteListSaleStart > 0) { 
                    if (block.timestamp < slot.whiteListSaleStart) {
                        if (simulateBuy != DataType.SIMULATION_CHECK_SKIP_START_PROCESS_REVERT) {
                            revert(Errors.LPAD_SLOT_WHITELIST_SALE_NOT_START);
                        }
                    }
                    if (block.timestamp < slot.saleStart) { 
                        if (buyQty + alreadyBuyBty > maxWhitelistBuy) {
                            revert(Errors.LPAD_SLOT_WHITELIST_BUY_NUM_LIMIT);
                        }
                    } else { 
                        if (buyQty + alreadyBuyBty > slot.maxBuyQtyPerAccount) {
                            revert(Errors.LPAD_SLOT_ACCOUNT_MAX_BUY_LIMIT);
                        }
                        return;
                    }
                } else { 
                    if (block.timestamp < slot.saleStart) {
                        if (simulateBuy != DataType.SIMULATION_CHECK_SKIP_START_PROCESS_REVERT) {
                            revert(Errors.LPAD_SLOT_WHITELIST_SALE_NOT_START);
                        }
                    }
                    if (buyQty + alreadyBuyBty > maxWhitelistBuy) {
                        revert(Errors.LPAD_SLOT_WHITELIST_BUY_NUM_LIMIT);
                    }
                }
                require(_offChainSignCheck(slot, msg.sender, maxWhitelistBuy, data), Errors.LPAD_SLOT_ACCOUNT_NOT_IN_WHITELIST);
            }
        }
    }
    function _offChainSignCheck(
        DataType.LaunchpadSlot memory slot,
        address account,
        uint256 maxBuyNum,
        bytes calldata signature
    ) internal view returns (bool success) {
        if (signature.length >= 65) {
            if (slot.signer == address(0)) {
                return false;
            }
            uint256 slotId = uint256(slot.slotId);
            bytes32 hash = keccak256(
                abi.encodePacked(
                    "\x19Ethereum Signed Message:\n32",
                    keccak256(abi.encodePacked(account, address(this), slot.launchpadId, slotId, maxBuyNum))
                )
            );
            bytes32 r;
            bytes32 s;
            uint8 v;
            assembly {
                r := calldataload(signature.offset)
                s := calldataload(add(signature.offset, 0x20))
                v := byte(0, calldataload(add(signature.offset, 0x40)))
            }
            return (ecrecover(hash, v, r, s) == slot.signer);
        }
        return false;
    }
    function isInWhiteList(
        bytes4 launchpadId,
        uint256 slotId,
        address[] calldata accounts,
        uint256[] calldata offChainMaxBuy,
        bytes[] calldata offChainSign
    ) external view returns (uint8[] memory wln) {
        wln = new uint8[](accounts.length);
        if (offChainSign.length > 0) {
            require(accounts.length == offChainMaxBuy.length && accounts.length == offChainSign.length, Errors.LPAD_INPUT_ARRAY_LEN_NOT_MATCH);
            bytes32 key = _getLaunchpadSlotKey(launchpadId, slotId);
            DataType.LaunchpadSlot memory slot = LibLaunchpadStorage.getStorage().launchpadSlots[key];
            for (uint256 i; i < accounts.length; i++) {
                if (_offChainSignCheck(slot, accounts[0], offChainMaxBuy[i], offChainSign[i])) {
                    wln[i] = uint8(offChainMaxBuy[i]);
                }
            }
        }
    }
    function hashForWhitelist(
        address account,
        bytes4 launchpadId,
        uint256 slot,
        uint256 maxBuy
    ) external view returns (bytes32) {
        return keccak256(abi.encodePacked(account, address(this), launchpadId, slot, maxBuy));
    }
    function getLaunchpadInfo(bytes4 , bytes4 launchpadId, uint256[] calldata ) external view returns (
        bool[] memory boolData,
        uint256[] memory intData,
        address[] memory addressData,
        bytes[] memory bytesData
    ) {
        bytes32 key = _getLaunchpadSlotKey(launchpadId, 0);
        DataType.LaunchpadSlot memory slot = LibLaunchpadStorage.getStorage().launchpadSlots[key];
        boolData = new bool[](2);
        boolData[0] = slot.enable;
        boolData[1] = slot.enable;
        bytesData = new bytes[](1);
        bytesData[0] = abi.encodePacked(slot.launchpadId);
        addressData = new address[](3);
        addressData[0] = address(0); 
        addressData[1] = address(this); 
        if (slot.feeType == 0) {
            addressData[2] = slot.feeReceipt != address(0) ? slot.feeReceipt : address(this);
        } else {
            addressData[2] = slot.targetContract;
        }
        uint256 slotsNum = 1;
        uint256 feesNum = 1;
        intData = new uint256[](4 + feesNum + slotsNum * 2);
        intData[0] = slotsNum;
        intData[1] = feesNum;
        intData[2] = 0; 
        intData[3] = 0; 
        intData[4] = 10000; 
        for (uint256 i = 5; i < intData.length; i += 2) {
            intData[i] = slot.saleQty;
            intData[i + 1] = 0;
        }
    }
    function getLaunchpadSlotInfo(bytes4 , bytes4 launchpadId, uint256 slotId) external view returns (
        bool[] memory boolData,
        uint256[] memory intData,
        address[] memory addressData,
        bytes4[] memory bytesData
    ) {
        bytes32 key = _getLaunchpadSlotKey(launchpadId, slotId);
        DataType.LaunchpadSlot memory slot = LibLaunchpadStorage.getStorage().launchpadSlots[key];
        if (launchpadId == 0 || launchpadId != slot.launchpadId || slotId != slot.slotId) {
            return (boolData, intData, addressData, bytesData); 
        }
        boolData = new bool[](6);
        boolData[0] = slot.enable; 
        boolData[1] = true; 
        intData = new uint256[](13);
        intData[0] = uint256(slot.saleStart); 
        intData[1] = uint256(slot.whiteListModel); 
        intData[2] = uint256(slot.maxSupply); 
        intData[3] = uint256(slot.saleQty); 
        intData[4] = uint256(slot.maxBuyQtyPerAccount); 
        intData[5]  = _getCurrentPrice(slot);
        intData[6] = 0; 
        intData[7] = 0; 
        intData[8] = 0; 
        intData[9] = uint256(slot.saleEnd); 
        intData[10] = uint256(slot.whiteListSaleStart); 
        intData[11] = uint256(slot.pricePresale * (10 ** slot.priceUint)); 
        intData[12] = uint256(slot.price * (10 ** slot.priceUint)); 
        addressData = new address[](3);
        addressData[0] = slot.paymentToken; 
        addressData[1] = slot.targetContract; 
        addressData[2] = address(this); 
        bytesData = new bytes4[](2);
        bytesData[0] = slot.mintSelector;
        bytesData[1] = slot.queryAccountMintedQtySelector;
    }
    function getAlreadyBuyBty(
        address account,
        bytes4 launchpadId,
        uint256 slotId
    ) external view returns (uint256) {
        bytes32 key = _getLaunchpadSlotKey(launchpadId, slotId);
        DataType.LaunchpadSlot memory slot = LibLaunchpadStorage.getStorage().launchpadSlots[key];
        if (launchpadId == 0 || launchpadId != slot.launchpadId || slotId != slot.slotId) {
            return 0;
        }
        (, uint256 alreadyBuyBty) = _getAlreadyBuyBty(slot, account);
        return alreadyBuyBty;
    }
    function getAccountInfoInLaunchpad(
        bytes4 proxyId,
        bytes4 launchpadId,
        uint256 slotId,
        uint256 quantity
    ) external view returns (
        bool[] memory boolData,
        uint256[] memory intData,
        bytes[] memory byteData
    ) {
        (
            boolData,
            intData,
            byteData
        ) = getAccountInfoInLaunchpadV2(msg.sender, proxyId, launchpadId, slotId, quantity);
        return (boolData, intData, byteData);
    }
    function getAccountInfoInLaunchpadV2(
        address account,
        bytes4 ,
        bytes4 launchpadId,
        uint256 slotId,
        uint256 quantity
    ) public view returns (
        bool[] memory boolData,
        uint256[] memory intData,
        bytes[] memory byteData
    ) {
        bytes32 key = _getLaunchpadSlotKey(launchpadId, slotId);
        DataType.LaunchpadSlot memory slot = LibLaunchpadStorage.getStorage().launchpadSlots[key];
        if (launchpadId == 0 || launchpadId != slot.launchpadId || slotId != slot.slotId) {
            return(boolData, intData, byteData); 
        }
        boolData = new bool[](4);
        if (slot.whiteListModel == DataType.WhiteListModel.NONE) {
            boolData[0] = false; 
            boolData[3] = false; 
        } else {
            boolData[0] = true; 
            boolData[3] = !(slot.whiteListSaleStart != 0 && block.timestamp >= slot.saleStart); 
        }
        intData = new uint256[](6);
        intData[0] = slot.saleQty; 
        intData[2] = 0; 
        intData[3] = (slot.whiteListModel == DataType.WhiteListModel.NONE) ? 0 : (quantity >> 128);
        quantity = uint256(quantity & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF); 
        (, uint256 alreadyBuyBty) = _getAlreadyBuyBty(slot, account);
        if (boolData[3]) {
            intData[1] = (intData[3] > alreadyBuyBty) ? (intData[3] - alreadyBuyBty) : 0;
        } else {
            intData[1] = uint256(slot.maxBuyQtyPerAccount) - alreadyBuyBty;
        }
        byteData = new bytes[](2);
        byteData[1] = bytes("Do not support openBox");
        if (account != address(0)) {
            if (quantity > 0) {
                byteData[0] = bytes(
                    _checkLaunchpadBuyWithoutRevert(
                        slot, alreadyBuyBty, quantity, intData[3]
                    )
                );
            }
            uint256 paymentNeeded = quantity * _getCurrentPrice(slot);
            if (slot.paymentToken != address(0)) { 
                intData[4] = IERC20(slot.paymentToken).balanceOf(account);
                boolData[1] = intData[4] >= paymentNeeded;
                boolData[2] = IERC20(slot.paymentToken).allowance(account, address(this)) >= paymentNeeded;
            } else { 
                intData[4] = account.balance;
                boolData[1] = intData[4] > paymentNeeded;
                boolData[2] = true;
            }
            if (account == slot.signer) {
                intData[5] = DataType.ROLE_LAUNCHPAD_SIGNER; 
            } else if (account == slot.feeReceipt) {
                intData[5] = DataType.ROLE_LAUNCHPAD_FEE_RECEIPTS; 
            } else if (
                account == owner() ||
                LibLaunchpadStorage.getStorage().administrators[account]
            ) {
                intData[5] = DataType.ROLE_PROXY_OWNER; 
            }
        } else {
            byteData[0] = bytes(Errors.OK);
        }
    }
    function _checkLaunchpadBuyWithoutRevert(
        DataType.LaunchpadSlot memory slot,
        uint256 alreadyBuyBty,
        uint256 buyQty,
        uint256 maxWhitelistBuy
    ) internal view returns(string memory errCode) {
        if (!slot.enable) {
            return Errors.LPAD_NOT_ENABLE;
        }
        if (slot.targetContract == address(0)) {
            return Errors.LPAD_SLOT_TARGET_CONTRACT_INVALID;
        }
        if (slot.mintSelector == bytes4(0)) {
            return Errors.LPAD_SLOT_ABI_NOT_FOUND;
        }
        if (!slot.storeAccountQtyFlag) {
            if (slot.queryAccountMintedQtySelector == bytes4(0)) {
                return Errors.LPAD_SLOT_ABI_NOT_FOUND;
            }
        }
        if (slot.storeSaleQtyFlag) {
            if ((slot.saleQty + buyQty) > uint256(slot.maxSupply)) {
                return Errors.LPAD_SLOT_QTY_NOT_ENOUGH_TO_BUY;
            }
        }
        if (block.timestamp >= slot.saleEnd) {
            return Errors.LPAD_SLOT_SALE_END;
        }
        if (slot.whiteListModel == DataType.WhiteListModel.NONE) {
            if (block.timestamp < slot.saleStart) {
                return Errors.LPAD_SLOT_SALE_NOT_START;
            }
            if (buyQty + alreadyBuyBty > slot.maxBuyQtyPerAccount) {
                return Errors.LPAD_SLOT_ACCOUNT_MAX_BUY_LIMIT;
            }
        } else {
            if (slot.whiteListSaleStart > 0) { 
                if (block.timestamp < slot.whiteListSaleStart) {
                    return Errors.LPAD_SLOT_WHITELIST_SALE_NOT_START;
                }
                if (block.timestamp < slot.saleStart) {
                    if (buyQty + alreadyBuyBty > maxWhitelistBuy) {
                        return Errors.LPAD_SLOT_WHITELIST_BUY_NUM_LIMIT;
                    }
                } else {
                    if (buyQty + alreadyBuyBty > slot.maxBuyQtyPerAccount) {
                        return Errors.LPAD_SLOT_ACCOUNT_MAX_BUY_LIMIT;
                    }
                }
            } else {
                if (block.timestamp < slot.saleStart) {
                    return Errors.LPAD_SLOT_WHITELIST_SALE_NOT_START;
                }
                if (buyQty + alreadyBuyBty > maxWhitelistBuy) {
                    return Errors.LPAD_SLOT_WHITELIST_BUY_NUM_LIMIT;
                }
            }
        }
        return Errors.OK;
    }
}
pragma solidity ^0.8.0;
interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external returns (bool);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}
pragma solidity ^0.8.17;
library  DataType {
    uint256 constant internal BUY_ADDITIONAL_IDX_WL_MAX_BUY_NUM = 0; 
    uint256 constant internal BUY_ADDITIONAL_IDX_SIMULATION     = 1; 
    uint256 constant internal ROLE_LAUNCHPAD_FEE_RECEIPTS   = 1; 
    uint256 constant internal ROLE_LAUNCHPAD_CONTROLLER     = 2; 
    uint256 constant internal ROLE_PROXY_OWNER              = 4; 
    uint256 constant internal ROLE_LAUNCHPAD_SIGNER         = 8; 
    uint256 constant internal SIMULATION_NONE                       = 0; 
    uint256 constant internal SIMULATION_CHECK                      = 1; 
    uint256 constant internal SIMULATION_CHECK_REVERT               = 2; 
    uint256 constant internal SIMULATION_CHECK_PROCESS_REVERT       = 3; 
    uint256 constant internal SIMULATION_CHECK_SKIP_START_PROCESS_REVERT = 4; 
    uint256 constant internal SIMULATION_CHECK_SKIP_WHITELIST_PROCESS_REVERT = 5; 
    uint256 constant internal SIMULATION_CHECK_SKIP_BALANCE_PROCESS_REVERT = 6; 
    uint256 constant internal SIMULATION_NO_CHECK_PROCESS_REVERT    = 7; 
    enum WhiteListModel {
        NONE,                     
        ON_CHAIN_CHECK,           
        OFF_CHAIN_SIGN,           
        OFF_CHAIN_MERKLE_ROOT     
    }
    struct LaunchpadSlot {
        uint32 saleQty;    
        bytes4 launchpadId; 
        uint8 slotId; 
        bool enable;  
        WhiteListModel whiteListModel;
        uint8 feeType; 
        address feeReceipt;
        uint32 maxSupply; 
        uint16 maxBuyQtyPerAccount; 
        uint16 pricePresale;
        uint16 price;
        uint16 priceUint;
        address paymentToken;
        uint32 saleStart; 
        uint32 saleEnd; 
        uint32 whiteListSaleStart; 
        address signer; 
        bool storeSaleQtyFlag; 
        bool storeAccountQtyFlag; 
        uint8 mintParams;
        uint8 queryAccountMintedQtyParams;
        bytes4 mintSelector;
        bytes4 queryAccountMintedQtySelector;
        address targetContract; 
    }
    struct Launchpad {
        uint8 slotNum;
    }
    struct AccountSlotStats {
        uint16 totalBuyQty; 
    }
    struct BuyParameter {
        bytes4 launchpadId;
        uint256 slotId;
        uint256 quantity;
        uint256 maxWhitelistBuy;
        bytes data;
    }
}
pragma solidity ^0.8.17;
abstract contract FixinTokenSpender {
    uint256 constant private ADDRESS_MASK = ((1 << 160) - 1);
    function _transferERC20From(address token, address owner, address to, uint256 amount) internal {
        uint256 success;
        assembly {
            let ptr := mload(0x40) 
            mstore(ptr, 0x23b872dd00000000000000000000000000000000000000000000000000000000)
            mstore(add(ptr, 0x04), and(owner, ADDRESS_MASK))
            mstore(add(ptr, 0x24), and(to, ADDRESS_MASK))
            mstore(add(ptr, 0x44), amount)
            success := call(gas(), and(token, ADDRESS_MASK), 0, ptr, 0x64, ptr, 32)
            let rdsize := returndatasize()
            success := and(
                success,                             
                or(
                    iszero(rdsize),                  
                    and(
                        iszero(lt(rdsize, 32)),      
                        eq(mload(ptr), 1)            
                    )
                )
            )
        }
        require(success != 0, "_transferERC20/TRANSFER_FAILED");
    }
    function _transferERC20(address token, address to, uint256 amount) internal {
        uint256 success;
        assembly {
            let ptr := mload(0x40) 
            mstore(ptr, 0xa9059cbb00000000000000000000000000000000000000000000000000000000)
            mstore(add(ptr, 0x04), and(to, ADDRESS_MASK))
            mstore(add(ptr, 0x24), amount)
            success := call(gas(), and(token, ADDRESS_MASK), 0, ptr, 0x44, ptr, 32)
            let rdsize := returndatasize()
            success := and(
                success,                             
                or(
                    iszero(rdsize),                  
                    and(
                        iszero(lt(rdsize, 32)),      
                        eq(mload(ptr), 1)            
                    )
                )
            )
        }
        require(success != 0, "_transferERC20/TRANSFER_FAILED");
    }
    function _transferEth(address recipient, uint256 amount) internal {
        assembly {
            if amount {
                if iszero(call(gas(), recipient, amount, 0, 0, 0, 0)) {
                    mstore(0, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                    mstore(0x20, 0x0000002000000000000000000000000000000000000000000000000000000000)
                    mstore(0x40, 0x0000001c5f7472616e736665724574682f5452414e534645525f4641494c4544)
                    mstore(0x60, 0)
                    revert(0, 0x64)
                }
            }
        }
    }
}
