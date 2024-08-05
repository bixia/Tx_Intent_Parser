
pragma solidity >=0.6.0 <0.8.0;
interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}
pragma solidity >=0.6.0 <0.8.0;
library SafeMath {
    function tryAdd(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        uint256 c = a + b;
        if (c < a) return (false, 0);
        return (true, c);
    }
    function trySub(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        if (b > a) return (false, 0);
        return (true, a - b);
    }
    function tryMul(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        if (a == 0) return (true, 0);
        uint256 c = a * b;
        if (c / a != b) return (false, 0);
        return (true, c);
    }
    function tryDiv(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        if (b == 0) return (false, 0);
        return (true, a / b);
    }
    function tryMod(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        if (b == 0) return (false, 0);
        return (true, a % b);
    }
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");
        return c;
    }
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a, "SafeMath: subtraction overflow");
        return a - b;
    }
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) return 0;
        uint256 c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");
        return c;
    }
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b > 0, "SafeMath: division by zero");
        return a / b;
    }
    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b > 0, "SafeMath: modulo by zero");
        return a % b;
    }
    function sub(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b <= a, errorMessage);
        return a - b;
    }
    function div(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b > 0, errorMessage);
        return a / b;
    }
    function mod(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b > 0, errorMessage);
        return a % b;
    }
}
pragma solidity >=0.6.0 <0.8.0;
abstract contract EIP712 {
    bytes32 private immutable _CACHED_DOMAIN_SEPARATOR;
    uint256 private immutable _CACHED_CHAIN_ID;
    bytes32 private immutable _HASHED_NAME;
    bytes32 private immutable _HASHED_VERSION;
    bytes32 private immutable _TYPE_HASH;
    constructor(string memory name, string memory version) internal {
        bytes32 hashedName = keccak256(bytes(name));
        bytes32 hashedVersion = keccak256(bytes(version));
        bytes32 typeHash = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
        _HASHED_NAME = hashedName;
        _HASHED_VERSION = hashedVersion;
        _CACHED_CHAIN_ID = _getChainId();
        _CACHED_DOMAIN_SEPARATOR = _buildDomainSeparator(typeHash, hashedName, hashedVersion);
        _TYPE_HASH = typeHash;
    }
    function _domainSeparatorV4() internal view virtual returns (bytes32) {
        if (_getChainId() == _CACHED_CHAIN_ID) {
            return _CACHED_DOMAIN_SEPARATOR;
        } else {
            return _buildDomainSeparator(_TYPE_HASH, _HASHED_NAME, _HASHED_VERSION);
        }
    }
    function _buildDomainSeparator(bytes32 typeHash, bytes32 name, bytes32 version) private view returns (bytes32) {
        return keccak256(
            abi.encode(
                typeHash,
                name,
                version,
                _getChainId(),
                address(this)
            )
        );
    }
    function _hashTypedDataV4(bytes32 structHash) internal view virtual returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparatorV4(), structHash));
    }
    function _getChainId() private view returns (uint256 chainId) {
        this; 
        assembly {
            chainId := chainid()
        }
    }
}
pragma solidity >=0.6.0 <0.8.0;
library ECDSA {
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        if (signature.length != 65) {
            revert("ECDSA: invalid signature length");
        }
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
        return recover(hash, v, r, s);
    }
    function recover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, "ECDSA: invalid signature 's' value");
        require(v == 27 || v == 28, "ECDSA: invalid signature 'v' value");
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "ECDSA: invalid signature");
        return signer;
    }
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }
}
pragma solidity >=0.6.2 <0.8.0;
library Address {
    function isContract(address account) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(account) }
        return size > 0;
    }
    function sendValue(address payable recipient, uint256 amount) internal {
        require(address(this).balance >= amount, "Address: insufficient balance");
        (bool success, ) = recipient.call{ value: amount }("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }
    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
      return functionCall(target, data, "Address: low-level call failed");
    }
    function functionCall(address target, bytes memory data, string memory errorMessage) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0, errorMessage);
    }
    function functionCallWithValue(address target, bytes memory data, uint256 value) internal returns (bytes memory) {
        return functionCallWithValue(target, data, value, "Address: low-level call with value failed");
    }
    function functionCallWithValue(address target, bytes memory data, uint256 value, string memory errorMessage) internal returns (bytes memory) {
        require(address(this).balance >= value, "Address: insufficient balance for call");
        require(isContract(target), "Address: call to non-contract");
        (bool success, bytes memory returndata) = target.call{ value: value }(data);
        return _verifyCallResult(success, returndata, errorMessage);
    }
    function functionStaticCall(address target, bytes memory data) internal view returns (bytes memory) {
        return functionStaticCall(target, data, "Address: low-level static call failed");
    }
    function functionStaticCall(address target, bytes memory data, string memory errorMessage) internal view returns (bytes memory) {
        require(isContract(target), "Address: static call to non-contract");
        (bool success, bytes memory returndata) = target.staticcall(data);
        return _verifyCallResult(success, returndata, errorMessage);
    }
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionDelegateCall(target, data, "Address: low-level delegate call failed");
    }
    function functionDelegateCall(address target, bytes memory data, string memory errorMessage) internal returns (bytes memory) {
        require(isContract(target), "Address: delegate call to non-contract");
        (bool success, bytes memory returndata) = target.delegatecall(data);
        return _verifyCallResult(success, returndata, errorMessage);
    }
    function _verifyCallResult(bool success, bytes memory returndata, string memory errorMessage) private pure returns(bytes memory) {
        if (success) {
            return returndata;
        } else {
            if (returndata.length > 0) {
                assembly {
                    let returndata_size := mload(returndata)
                    revert(add(32, returndata), returndata_size)
                }
            } else {
                revert(errorMessage);
            }
        }
    }
}
pragma solidity 0.7.6;
interface IStarNFT {
    function isOwnerOf(address, uint256) external view returns (bool);
    function getNumMinted() external view returns (uint256);
    function mint(address account, uint256 powah) external returns (uint256);
    function mintBatch(address account, uint256 amount, uint256[] calldata powahArr) external returns (uint256[] memory);
    function burn(address account, uint256 id) external;
    function burnBatch(address account, uint256[] calldata ids) external;
}
pragma solidity 0.7.6;
import {Address} from "Address.sol";
import {SafeMath} from "SafeMath.sol";
import {IERC20} from "IERC20.sol";
import {EIP712} from "EIP712.sol";
import {ECDSA} from "ECDSA.sol";
import {IStarNFT} from "IStarNFT.sol"; 
contract SpaceStationV2 is EIP712 {
    using Address for address;
    using SafeMath for uint256;
    event EventActivateCampaign(uint256 _cid);
    event EventClaim(
        uint256 _cid,
        uint256 _dummyId,
        uint256 _nftID,
        IStarNFT _starNFT,
        address _sender
    );
    event EventClaimCapped(
        uint256 _cid,
        uint256 _dummyId,
        uint256 _nftID,
        IStarNFT _starNFT,
        address _sender,
        uint256 _minted,
        uint256 _cap
    );
    event EventClaimBatch(
        uint256 _cid,
        uint256[] _dummyIdArr,
        uint256[] _nftIDArr,
        IStarNFT _starNFT,
        address _sender
    );
    event EventClaimBatchCapped(
        uint256 _cid,
        uint256[] _dummyIdArr,
        uint256[] _nftIDArr,
        IStarNFT _starNFT,
        address _sender,
        uint256 _minted,
        uint256 _cap
    );
    event EventForge(
        uint256 _cid,
        uint256 _dummyId,
        uint256 _nftID,
        IStarNFT _starNFT,
        address _sender
    );
    modifier onlyCampaignSetter() {
        _validateOnlyCampaignSetter();
        _;
    }
    modifier onlyManager() {
        _validateOnlyManager();
        _;
    }
    modifier onlyTreasuryManager() {
        _validateOnlyTreasuryManager();
        _;
    }
    modifier onlyNoPaused() {
        _validateOnlyNotPaused();
        _;
    }
    struct CampaignFeeConfig {
        address erc20; 
        uint256 erc20Fee; 
        uint256 platformFee; 
    }
    bool public paused;
    address public galaxy_signer;
    address public campaign_setter;
    address public manager;
    address public treasury_manager;
    mapping(uint256 => CampaignFeeConfig) public campaignFeeConfigs;
    mapping(uint256 => bool) public hasMinted;
    mapping(uint256 => uint256) public numMinted;
    constructor(
        address _galaxy_signer,
        address _campaign_setter,
        address _contract_manager,
        address _treasury_manager
    ) EIP712("Galaxy", "1.0.0") {
        galaxy_signer = _galaxy_signer;
        campaign_setter = _campaign_setter;
        manager = _contract_manager;
        treasury_manager = _treasury_manager;
    }
    function activateCampaign(
        uint256 _cid,
        uint256 _platformFee,
        uint256 _erc20Fee,
        address _erc20
    ) external onlyCampaignSetter {
        _setFees(_cid, _platformFee, _erc20Fee, _erc20);
        emit EventActivateCampaign(_cid);
    }
    function claim(
        uint256 _cid,
        IStarNFT _starNFT,
        uint256 _dummyId,
        uint256 _powah,
        address _mintTo,
        bytes calldata _signature
    ) public payable onlyNoPaused {
        require(!hasMinted[_dummyId], "Already minted");
        require(
            _verify(
                _hash(_cid, _starNFT, _dummyId, _powah, _mintTo),
                _signature
            ),
            "Invalid signature"
        );
        hasMinted[_dummyId] = true;
        _payFees(_cid, 1);
        uint256 nftID = _starNFT.mint(_mintTo, _powah);
        emit EventClaim(_cid, _dummyId, nftID, _starNFT, _mintTo);
    }
    function claim(
        uint256 _cid,
        IStarNFT _starNFT,
        uint256 _dummyId,
        uint256 _powah,
        bytes calldata _signature
    ) external payable onlyNoPaused {
        claim(_cid, _starNFT, _dummyId, _powah, msg.sender, _signature);
    }
    function claimBatch(
        uint256 _cid,
        IStarNFT _starNFT,
        uint256[] calldata _dummyIdArr,
        uint256[] calldata _powahArr,
        address _mintTo,
        bytes calldata _signature
    ) public payable onlyNoPaused {
        require(
            _dummyIdArr.length > 0,
            "Array(_dummyIdArr) should not be empty"
        );
        require(
            _powahArr.length == _dummyIdArr.length,
            "Array(_powahArr) length mismatch"
        );
        for (uint256 i = 0; i < _dummyIdArr.length; i++) {
            require(!hasMinted[_dummyIdArr[i]], "Already minted");
            hasMinted[_dummyIdArr[i]] = true;
        }
        require(
            _verify(
                _hashBatch(_cid, _starNFT, _dummyIdArr, _powahArr, _mintTo),
                _signature
            ),
            "Invalid signature"
        );
        _payFees(_cid, _dummyIdArr.length);
        uint256[] memory nftIdArr = _starNFT.mintBatch(
            _mintTo,
            _powahArr.length,
            _powahArr
        );
        emit EventClaimBatch(_cid, _dummyIdArr, nftIdArr, _starNFT, _mintTo);
    }
    function claimBatch(
        uint256 _cid,
        IStarNFT _starNFT,
        uint256[] calldata _dummyIdArr,
        uint256[] calldata _powahArr,
        bytes calldata _signature
    ) external payable onlyNoPaused {
        claimBatch(_cid, _starNFT, _dummyIdArr, _powahArr, msg.sender, _signature);
    }
    function claimCapped(
        uint256 _cid,
        IStarNFT _starNFT,
        uint256 _dummyId,
        uint256 _powah,
        uint256 _cap,
        address _mintTo,
        bytes calldata _signature
    ) public payable onlyNoPaused {
        require(!hasMinted[_dummyId], "Already minted");
        require(numMinted[_cid] < _cap, "Reached cap limit");
        require(
            _verify(
                _hashCapped(_cid, _starNFT, _dummyId, _powah, _cap, _mintTo),
                _signature
            ),
            "Invalid signature"
        );
        hasMinted[_dummyId] = true;
        numMinted[_cid] = numMinted[_cid] + 1;
        _payFees(_cid, 1);
        uint256 nftID = _starNFT.mint(_mintTo, _powah);
        uint256 minted = numMinted[_cid];
        emit EventClaimCapped(_cid, _dummyId, nftID, _starNFT, _mintTo, minted, _cap);
    }
    function claimCapped(
        uint256 _cid,
        IStarNFT _starNFT,
        uint256 _dummyId,
        uint256 _powah,
        uint256 _cap,
        bytes calldata _signature
    ) external payable onlyNoPaused {
        claimCapped(_cid, _starNFT, _dummyId, _powah, _cap, msg.sender, _signature);
    }
    function claimBatchCapped(
        uint256 _cid,
        IStarNFT _starNFT,
        uint256[] calldata _dummyIdArr,
        uint256[] calldata _powahArr,
        uint256 _cap,
        address _mintTo,
        bytes calldata _signature
    ) public payable onlyNoPaused {
        require(
            _dummyIdArr.length > 0,
            "Array(_dummyIdArr) should not be empty"
        );
        require(
            _powahArr.length == _dummyIdArr.length,
            "Array(_powahArr) length mismatch"
        );
        require(
            numMinted[_cid] + _dummyIdArr.length <= _cap,
            "Reached cap limit"
        );
        for (uint256 i = 0; i < _dummyIdArr.length; i++) {
            require(!hasMinted[_dummyIdArr[i]], "Already minted");
            hasMinted[_dummyIdArr[i]] = true;
        }
        require(
            _verify(
                _hashBatchCapped(
                    _cid,
                    _starNFT,
                    _dummyIdArr,
                    _powahArr,
                    _cap,
                    _mintTo
                ),
                _signature
            ),
            "Invalid signature"
        );
        numMinted[_cid] = numMinted[_cid] + _dummyIdArr.length;
        _payFees(_cid, _dummyIdArr.length);
        uint256[] memory nftIdArr = _starNFT.mintBatch(
            _mintTo,
            _powahArr.length,
            _powahArr
        );
        uint256 minted = numMinted[_cid];
        emit EventClaimBatchCapped(_cid, _dummyIdArr, nftIdArr, _starNFT, _mintTo, minted, _cap);
    }
    function claimBatchCapped(
        uint256 _cid,
        IStarNFT _starNFT,
        uint256[] calldata _dummyIdArr,
        uint256[] calldata _powahArr,
        uint256 _cap,
        bytes calldata _signature
    ) external payable onlyNoPaused {
        claimBatchCapped(_cid, _starNFT, _dummyIdArr, _powahArr, _cap, msg.sender, _signature);
    }
    function forge(
        uint256 _cid,
        IStarNFT _starNFT,
        uint256[] calldata _nftIDs,
        uint256 _dummyId,
        uint256 _powah,
        address _mintTo,
        bytes calldata _signature
    ) public payable onlyNoPaused {
        require(!hasMinted[_dummyId], "Already minted");
        require(
            _verify(
                _hashForge(
                    _cid,
                    _starNFT,
                    _nftIDs,
                    _dummyId,
                    _powah,
                    _mintTo
                ),
                _signature
            ),
            "Invalid signature"
        );
        hasMinted[_dummyId] = true;
        for (uint256 i = 0; i < _nftIDs.length; i++) {
            require(
                _starNFT.isOwnerOf(_mintTo, _nftIDs[i]),
                "Not the owner"
            );
        }
        _starNFT.burnBatch(_mintTo, _nftIDs);
        _payFees(_cid, 1);
        uint256 nftID = _starNFT.mint(_mintTo, _powah);
        emit EventForge(_cid, _dummyId, nftID, _starNFT, _mintTo);
    }
    function forge(
        uint256 _cid,
        IStarNFT _starNFT,
        uint256[] calldata _nftIDs,
        uint256 _dummyId,
        uint256 _powah,
        bytes calldata _signature
    ) external payable onlyNoPaused {
        forge(_cid, _starNFT, _nftIDs, _dummyId, _powah, msg.sender, _signature);
    }
    receive() external payable {
        (bool success, ) = treasury_manager.call{value: msg.value}(
            new bytes(0)
        );
        require(success, "Transfer failed");
    }
    fallback() external payable {
        if (msg.value > 0) {
            (bool success, ) = treasury_manager.call{value: msg.value}(new bytes(0));
            require(success, "Transfer failed");
        }
    }
    function updateGalaxySigner(address newAddress) external onlyManager {
        require(
            newAddress != address(0),
            "Galaxy signer address must not be null address"
        );
        galaxy_signer = newAddress;
    }
    function updateCampaignSetter(address newAddress) external onlyManager {
        require(
            newAddress != address(0),
            "Campaign setter address must not be null address"
        );
        campaign_setter = newAddress;
    }
    function updateManager(address newAddress) external onlyManager {
        require(
            newAddress != address(0),
            "Manager address must not be null address"
        );
        manager = newAddress;
    }
    function updateTreasureManager(address payable newAddress)
    external
    onlyTreasuryManager
    {
        require(
            newAddress != address(0),
            "Treasure manager must not be null address"
        );
        treasury_manager = newAddress;
    }
    function setPause(bool _paused) external onlyManager {
        paused = _paused;
    }
    function _hash(
        uint256 _cid,
        IStarNFT _starNFT,
        uint256 _dummyId,
        uint256 _powah,
        address _account
    ) public view returns (bytes32) {
        return
        _hashTypedDataV4(
            keccak256(
                abi.encode(
                    keccak256(
                        "NFT(uint256 cid,address starNFT,uint256 dummyId,uint256 powah,address account)"
                    ),
                    _cid,
                    _starNFT,
                    _dummyId,
                    _powah,
                    _account
                )
            )
        );
    }
    function _hashCapped(
        uint256 _cid,
        IStarNFT _starNFT,
        uint256 _dummyId,
        uint256 _powah,
        uint256 _cap,
        address _account
    ) public view returns (bytes32) {
        return
        _hashTypedDataV4(
            keccak256(
                abi.encode(
                    keccak256(
                        "NFT(uint256 cid,address starNFT,uint256 dummyId,uint256 powah,uint256 cap,address account)"
                    ),
                    _cid,
                    _starNFT,
                    _dummyId,
                    _powah,
                    _cap,
                    _account
                )
            )
        );
    }
    function _hashBatch(
        uint256 _cid,
        IStarNFT _starNFT,
        uint256[] calldata _dummyIdArr,
        uint256[] calldata _powahArr,
        address _account
    ) public view returns (bytes32) {
        return
        _hashTypedDataV4(
            keccak256(
                abi.encode(
                    keccak256(
                        "NFT(uint256 cid,address starNFT,uint256[] dummyIdArr,uint256[] powahArr,address account)"
                    ),
                    _cid,
                    _starNFT,
                    keccak256(abi.encodePacked(_dummyIdArr)),
                    keccak256(abi.encodePacked(_powahArr)),
                    _account
                )
            )
        );
    }
    function _hashBatchCapped(
        uint256 _cid,
        IStarNFT _starNFT,
        uint256[] calldata _dummyIdArr,
        uint256[] calldata _powahArr,
        uint256 _cap,
        address _account
    ) public view returns (bytes32) {
        return
        _hashTypedDataV4(
            keccak256(
                abi.encode(
                    keccak256(
                        "NFT(uint256 cid,address starNFT,uint256[] dummyIdArr,uint256[] powahArr,uint256 cap,address account)"
                    ),
                    _cid,
                    _starNFT,
                    keccak256(abi.encodePacked(_dummyIdArr)),
                    keccak256(abi.encodePacked(_powahArr)),
                    _cap,
                    _account
                )
            )
        );
    }
    function _hashForge(
        uint256 _cid,
        IStarNFT _starNFT,
        uint256[] calldata _nftIDs,
        uint256 _dummyId,
        uint256 _powah,
        address _account
    ) public view returns (bytes32) {
        return
        _hashTypedDataV4(
            keccak256(
                abi.encode(
                    keccak256(
                        "NFT(uint256 cid,address starNFT,uint256[] nftIDs,uint256 dummyId,uint256 powah,address account)"
                    ),
                    _cid,
                    _starNFT,
                    keccak256(abi.encodePacked(_nftIDs)),
                    _dummyId,
                    _powah,
                    _account
                )
            )
        );
    }
    function _verify(bytes32 hash, bytes calldata signature)
    public
    view
    returns (bool)
    {
        return ECDSA.recover(hash, signature) == galaxy_signer;
    }
    function _setFees(
        uint256 _cid,
        uint256 _platformFee,
        uint256 _erc20Fee,
        address _erc20
    ) private {
        require(
            (_erc20 == address(0) && _erc20Fee == 0) ||
            (_erc20 != address(0) && _erc20Fee != 0),
            "Invalid erc20 fee requirement arguments"
        );
        campaignFeeConfigs[_cid] = CampaignFeeConfig(
            _erc20,
            _erc20Fee,
            _platformFee
        );
    }
    function _payFees(uint256 _cid, uint256 amount) private {
        require(amount > 0, "Must mint more than 0");
        CampaignFeeConfig memory feeConf = campaignFeeConfigs[_cid];
        if (feeConf.platformFee > 0) {
            require(
                msg.value >= feeConf.platformFee.mul(amount),
                "Insufficient Payment"
            );
            (bool success, ) = treasury_manager.call{value: msg.value}(
                new bytes(0)
            );
            require(success, "Transfer platformFee failed");
        }
        if (feeConf.erc20Fee > 0) {
            require(
                IERC20(feeConf.erc20).transferFrom(
                    msg.sender,
                    treasury_manager,
                    feeConf.erc20Fee.mul(amount)
                ),
                "Transfer erc20Fee failed"
            );
        }
    }
    function _validateOnlyCampaignSetter() internal view {
        require(msg.sender == campaign_setter, "Only campaignSetter can call");
    }
    function _validateOnlyManager() internal view {
        require(msg.sender == manager, "Only manager can call");
    }
    function _validateOnlyTreasuryManager() internal view {
        require(
            msg.sender == treasury_manager,
            "Only treasury manager can call"
        );
    }
    function _validateOnlyNotPaused() internal view {
        require(!paused, "Contract paused");
    }
}
