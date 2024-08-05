
pragma solidity 0.8.8;
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }
    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }
}
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
library Address {
    function isContract(address account) internal view returns (bool) {
        return account.code.length > 0;
    }
    function sendValue(address payable recipient, uint256 amount) internal {
        require(address(this).balance >= amount, "Address: insufficient balance");
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }
    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0, "Address: low-level call failed");
    }
    function functionCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0, errorMessage);
    }
    function functionCallWithValue(
        address target,
        bytes memory data,
        uint256 value
    ) internal returns (bytes memory) {
        return functionCallWithValue(target, data, value, "Address: low-level call with value failed");
    }
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
    function functionStaticCall(address target, bytes memory data) internal view returns (bytes memory) {
        return functionStaticCall(target, data, "Address: low-level static call failed");
    }
    function functionStaticCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal view returns (bytes memory) {
        (bool success, bytes memory returndata) = target.staticcall(data);
        return verifyCallResultFromTarget(target, success, returndata, errorMessage);
    }
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionDelegateCall(target, data, "Address: low-level delegate call failed");
    }
    function functionDelegateCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal returns (bytes memory) {
        (bool success, bytes memory returndata) = target.delegatecall(data);
        return verifyCallResultFromTarget(target, success, returndata, errorMessage);
    }
    function verifyCallResultFromTarget(
        address target,
        bool success,
        bytes memory returndata,
        string memory errorMessage
    ) internal view returns (bytes memory) {
        if (success) {
            if (returndata.length == 0) {
                require(isContract(target), "Address: call to non-contract");
            }
            return returndata;
        } else {
            _revert(returndata, errorMessage);
        }
    }
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
library SafeERC20 {
    using Address for address;
    function safeTransfer(
        IERC20 token,
        address to,
        uint256 value
    ) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));
    }
    function safeTransferFrom(
        IERC20 token,
        address from,
        address to,
        uint256 value
    ) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));
    }
    function safeApprove(
        IERC20 token,
        address spender,
        uint256 value
    ) internal {
        require(
            (value == 0) || (token.allowance(address(this), spender) == 0),
            "SafeERC20: approve from non-zero to non-zero allowance"
        );
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));
    }
    function safeIncreaseAllowance(
        IERC20 token,
        address spender,
        uint256 value
    ) internal {
        uint256 newAllowance = token.allowance(address(this), spender) + value;
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
    }
    function safeDecreaseAllowance(
        IERC20 token,
        address spender,
        uint256 value
    ) internal {
        unchecked {
            uint256 oldAllowance = token.allowance(address(this), spender);
            require(oldAllowance >= value, "SafeERC20: decreased allowance below zero");
            uint256 newAllowance = oldAllowance - value;
            _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
        }
    }
    function safePermit(
        IERC20Permit token,
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal {
        uint256 nonceBefore = token.nonces(owner);
        token.permit(owner, spender, value, deadline, v, r, s);
        uint256 nonceAfter = token.nonces(owner);
        require(nonceAfter == nonceBefore + 1, "SafeERC20: permit did not succeed");
    }
    function _callOptionalReturn(IERC20 token, bytes memory data) private {
        bytes memory returndata = address(token).functionCall(data, "SafeERC20: low-level call failed");
        if (returndata.length > 0) {
            require(abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");
        }
    }
}
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
interface ISignatureTransfer {
    struct TokenPermissions {
        address token;
        uint256 amount;
    }
    struct PermitTransferFrom {
        TokenPermissions permitted;
        uint256 nonce;
        uint256 deadline;
    }
    struct SignatureTransferDetails {
        address to;
        uint256 requestedAmount;
    }
    struct PermitBatchTransferFrom {
        TokenPermissions[] permitted;
        uint256 nonce;
        uint256 deadline;
    }
    function permitTransferFrom(
        PermitTransferFrom memory permit,
        SignatureTransferDetails calldata transferDetails,
        address owner,
        bytes calldata signature
    ) external;
    function permitTransferFrom(
        PermitBatchTransferFrom memory permit,
        SignatureTransferDetails[] calldata transferDetails,
        address owner,
        bytes calldata signature
    ) external;
}
interface IOdosExecutor {
  function executePath (
    bytes calldata bytecode,
    uint256[] memory inputAmount,
    address msgSender
  ) external payable;
}
contract OdosRouterV2 is Ownable {
  using SafeERC20 for IERC20;
  address constant _ETH = address(0);
  uint256 private constant addressListStart = 
    80084422859880547211683076133703299733277748156566366325829078699459944778998;
  address[] public addressList;
  uint256 public constant REFERRAL_WITH_FEE_THRESHOLD = 1 << 31;
  uint256 public constant FEE_DENOM = 1e18;
  uint256 public swapMultiFee;
  struct permit2Info {
    address contractAddress;
    uint256 nonce;
    uint256 deadline;
    bytes signature;
  }
  struct swapTokenInfo {
    address inputToken;
    uint256 inputAmount;
    address inputReceiver;
    address outputToken;
    uint256 outputQuote;
    uint256 outputMin;
    address outputReceiver;
  }
  struct inputTokenInfo {
    address tokenAddress;
    uint256 amountIn;
    address receiver;
  }
  struct outputTokenInfo {
    address tokenAddress;
    uint256 relativeValue;
    address receiver;
  }
  event Swap(
    address sender,
    uint256 inputAmount,
    address inputToken,
    uint256 amountOut,
    address outputToken,
    int256 slippage,
    uint32 referralCode
  );
  event SwapMulti(
    address sender,
    uint256[] amountsIn,
    address[] tokensIn,
    uint256[] amountsOut,
    address[] tokensOut,
    uint32 referralCode
  );
  struct referralInfo {
    uint64 referralFee;
    address beneficiary;
    bool registered;
  }
  mapping(uint32 => referralInfo) public referralLookup;
  constructor() {
    referralLookup[0].referralFee = 0;
    referralLookup[0].beneficiary = address(0);
    referralLookup[0].registered = true;
    swapMultiFee = 5e14;
  }
  receive() external payable { }
  function swapCompact() 
    external
    payable
    returns (uint256)
  {
    swapTokenInfo memory tokenInfo;
    address executor;
    uint32 referralCode;
    bytes calldata pathDefinition;
    {
      address msgSender = msg.sender;
      assembly {
        function getAddress(currPos) -> result, newPos {
          let inputPos := shr(240, calldataload(currPos))
          switch inputPos
          case 0x0000 {
            newPos := add(currPos, 2)
          }
          case 0x0001 {
            result := and(shr(80, calldataload(currPos)), 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
            newPos := add(currPos, 22)
          }
          default {
            result := sload(add(addressListStart, sub(inputPos, 2)))
            newPos := add(currPos, 2)
          }
        }
        let result := 0
        let pos := 4
        result, pos := getAddress(pos)
        mstore(tokenInfo, result)
        result, pos := getAddress(pos)
        mstore(add(tokenInfo, 0x60), result)
        let inputAmountLength := shr(248, calldataload(pos))
        pos := add(pos, 1)
        if inputAmountLength {
          mstore(add(tokenInfo, 0x20), shr(mul(sub(32, inputAmountLength), 8), calldataload(pos)))
          pos := add(pos, inputAmountLength)
        }
        let quoteAmountLength := shr(248, calldataload(pos))
        pos := add(pos, 1)
        let outputQuote := shr(mul(sub(32, quoteAmountLength), 8), calldataload(pos))
        mstore(add(tokenInfo, 0x80), outputQuote)
        pos := add(pos, quoteAmountLength)
        {
          let slippageTolerance := shr(232, calldataload(pos))
          mstore(add(tokenInfo, 0xA0), div(mul(outputQuote, sub(0xFFFFFF, slippageTolerance)), 0xFFFFFF))
        }
        pos := add(pos, 3)
        executor, pos := getAddress(pos)
        result, pos := getAddress(pos)
        if eq(result, 0) { result := executor }
        mstore(add(tokenInfo, 0x40), result)
        result, pos := getAddress(pos)
        if eq(result, 0) { result := msgSender }
        mstore(add(tokenInfo, 0xC0), result)
        referralCode := shr(224, calldataload(pos))
        pos := add(pos, 4)
        pathDefinition.length := mul(shr(248, calldataload(pos)), 32)
        pathDefinition.offset := add(pos, 1)
      }
    }
    return _swapApproval(
      tokenInfo,
      pathDefinition,
      executor,
      referralCode
    );
  }
  function swap(
    swapTokenInfo memory tokenInfo,
    bytes calldata pathDefinition,
    address executor,
    uint32 referralCode
  )
    external
    payable
    returns (uint256 amountOut)
  {
    return _swapApproval(
      tokenInfo,
      pathDefinition,
      executor,
      referralCode
    );
  }
  function _swapApproval(
    swapTokenInfo memory tokenInfo,
    bytes calldata pathDefinition,
    address executor,
    uint32 referralCode
  )
    internal
    returns (uint256 amountOut)
  {
    if (tokenInfo.inputToken == _ETH) {
      if (tokenInfo.inputAmount == 0) {
        tokenInfo.inputAmount = msg.value;
      } else {
        require(msg.value == tokenInfo.inputAmount, "Wrong msg.value");
      }
    }
    else {
      if (tokenInfo.inputAmount == 0) {
        tokenInfo.inputAmount = IERC20(tokenInfo.inputToken).balanceOf(msg.sender);
      }
      IERC20(tokenInfo.inputToken).safeTransferFrom(
        msg.sender,
        tokenInfo.inputReceiver,
        tokenInfo.inputAmount
      );
    }
    return _swap(
      tokenInfo,
      pathDefinition,
      executor,
      referralCode
    );
  }
  function swapPermit2(
    permit2Info memory permit2,
    swapTokenInfo memory tokenInfo,
    bytes calldata pathDefinition,
    address executor,
    uint32 referralCode
  )
    external
    returns (uint256 amountOut)
  {
    ISignatureTransfer(permit2.contractAddress).permitTransferFrom(
      ISignatureTransfer.PermitTransferFrom(
        ISignatureTransfer.TokenPermissions(
          tokenInfo.inputToken,
          tokenInfo.inputAmount
        ),
        permit2.nonce,
        permit2.deadline
      ),
      ISignatureTransfer.SignatureTransferDetails(
        tokenInfo.inputReceiver,
        tokenInfo.inputAmount
      ),
      msg.sender,
      permit2.signature
    );
    return _swap(
      tokenInfo,
      pathDefinition,
      executor,
      referralCode
    );
  }
  function _swap(
    swapTokenInfo memory tokenInfo,
    bytes calldata pathDefinition,
    address executor,
    uint32 referralCode
  )
    internal
    returns (uint256 amountOut)
  {
    require(tokenInfo.outputMin <= tokenInfo.outputQuote, "Minimum greater than quote");
    require(tokenInfo.outputMin > 0, "Slippage limit too low");
    require(tokenInfo.inputToken != tokenInfo.outputToken, "Arbitrage not supported");
    uint256 balanceBefore = _universalBalance(tokenInfo.outputToken);
    uint256[] memory amountsIn = new uint256[](1);
    amountsIn[0] = tokenInfo.inputAmount;
    IOdosExecutor(executor).executePath{value: msg.value}(pathDefinition, amountsIn, msg.sender);
    amountOut = _universalBalance(tokenInfo.outputToken) - balanceBefore;
    if (referralCode > REFERRAL_WITH_FEE_THRESHOLD) {
      referralInfo memory thisReferralInfo = referralLookup[referralCode];
      _universalTransfer(
        tokenInfo.outputToken,
        thisReferralInfo.beneficiary,
        amountOut * thisReferralInfo.referralFee * 8 / (FEE_DENOM * 10)
      );
      amountOut = amountOut * (FEE_DENOM - thisReferralInfo.referralFee) / FEE_DENOM;
    }
    int256 slippage = int256(amountOut) - int256(tokenInfo.outputQuote);
    if (slippage > 0) {
      amountOut = tokenInfo.outputQuote;
    }
    require(amountOut >= tokenInfo.outputMin, "Slippage Limit Exceeded");
    _universalTransfer(tokenInfo.outputToken, tokenInfo.outputReceiver, amountOut);
    emit Swap(
      msg.sender,
      tokenInfo.inputAmount,
      tokenInfo.inputToken,
      amountOut,
      tokenInfo.outputToken,
      slippage,
      referralCode
    );
  }
  function swapMultiCompact() 
    external
    payable
    returns (uint256[] memory amountsOut)
  {
    address executor;
    uint256 valueOutMin;
    inputTokenInfo[] memory inputs;
    outputTokenInfo[] memory outputs;
    uint256 pos = 6;
    {
      address msgSender = msg.sender;
      uint256 numInputs;
      uint256 numOutputs;
      assembly {
        numInputs := shr(248, calldataload(4))
        numOutputs := shr(248, calldataload(5))
      }
      inputs = new inputTokenInfo[](numInputs);
      outputs = new outputTokenInfo[](numOutputs);
      assembly {
        function getAddress(currPos) -> result, newPos {
          let inputPos := shr(240, calldataload(currPos))
          switch inputPos
          case 0x0000 {
            newPos := add(currPos, 2)
          }
          case 0x0001 {
            result := and(shr(80, calldataload(currPos)), 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
            newPos := add(currPos, 22)
          }
          default {
            result := sload(add(addressListStart, sub(inputPos, 2)))
            newPos := add(currPos, 2)
          }
        }
        executor, pos := getAddress(pos)
        let outputMinAmountLength := shr(248, calldataload(pos))
        pos := add(pos, 1)
        valueOutMin := shr(mul(sub(32, outputMinAmountLength), 8), calldataload(pos))
        pos := add(pos, outputMinAmountLength)
        let result := 0
        let memPos := 0
        for { let element := 0 } lt(element, numInputs) { element := add(element, 1) }
        {
          memPos := mload(add(inputs, add(mul(element, 0x20), 0x20)))
          result, pos := getAddress(pos)
          mstore(memPos, result)
          let inputAmountLength := shr(248, calldataload(pos))
          pos := add(pos, 1)
          if inputAmountLength {
             mstore(add(memPos, 0x20), shr(mul(sub(32, inputAmountLength), 8), calldataload(pos)))
            pos := add(pos, inputAmountLength)
          }
          result, pos := getAddress(pos)
          if eq(result, 0) { result := executor }
          mstore(add(memPos, 0x40), result)
        }
        for { let element := 0 } lt(element, numOutputs) { element := add(element, 1) }
        {
          memPos := mload(add(outputs, add(mul(element, 0x20), 0x20)))
          result, pos := getAddress(pos)
          mstore(memPos, result)
          let outputAmountLength := shr(248, calldataload(pos))
          pos := add(pos, 1)
          mstore(add(memPos, 0x20), shr(mul(sub(32, outputAmountLength), 8), calldataload(pos)))
          pos := add(pos, outputAmountLength)
          result, pos := getAddress(pos)
          if eq(result, 0) { result := msgSender }
          mstore(add(memPos, 0x40), result)
        }
      }
    }
    uint32 referralCode;
    bytes calldata pathDefinition;
    assembly {
      referralCode := shr(224, calldataload(pos))
      pos := add(pos, 4)
      pathDefinition.length := mul(shr(248, calldataload(pos)), 32)
      pathDefinition.offset := add(pos, 1)
    }
    return _swapMultiApproval(
      inputs,
      outputs,
      valueOutMin,
      pathDefinition,
      executor,
      referralCode
    );
  }
  function swapMulti(
    inputTokenInfo[] memory inputs,
    outputTokenInfo[] memory outputs,
    uint256 valueOutMin,
    bytes calldata pathDefinition,
    address executor,
    uint32 referralCode
  )
    external
    payable
    returns (uint256[] memory amountsOut)
  {
    return _swapMultiApproval(
      inputs,
      outputs,
      valueOutMin,
      pathDefinition,
      executor,
      referralCode
    );
  }
  function _swapMultiApproval(
    inputTokenInfo[] memory inputs,
    outputTokenInfo[] memory outputs,
    uint256 valueOutMin,
    bytes calldata pathDefinition,
    address executor,
    uint32 referralCode
  )
    internal
    returns (uint256[] memory amountsOut)
  {
    uint256 expected_msg_value = 0;
    for (uint256 i = 0; i < inputs.length; i++) {
      if (inputs[i].tokenAddress == _ETH) {
        if (inputs[i].amountIn == 0) {
          inputs[i].amountIn = msg.value;
        }
        expected_msg_value = inputs[i].amountIn;
      } 
      else {
        if (inputs[i].amountIn == 0) {
          inputs[i].amountIn = IERC20(inputs[i].tokenAddress).balanceOf(msg.sender);
        }
        IERC20(inputs[i].tokenAddress).safeTransferFrom(
          msg.sender,
          inputs[i].receiver,
          inputs[i].amountIn
        );
      }
    }
    require(msg.value == expected_msg_value, "Wrong msg.value");
    return _swapMulti(
      inputs,
      outputs,
      valueOutMin,
      pathDefinition,
      executor,
      referralCode
    );
  }
  function swapMultiPermit2(
    permit2Info memory permit2,
    inputTokenInfo[] memory inputs,
    outputTokenInfo[] memory outputs,
    uint256 valueOutMin,
    bytes calldata pathDefinition,
    address executor,
    uint32 referralCode
  )
    external
    payable
    returns (uint256[] memory amountsOut)
  {
    ISignatureTransfer.PermitBatchTransferFrom memory permit;
    ISignatureTransfer.SignatureTransferDetails[] memory transferDetails;
    {
      uint256 permit_length = msg.value > 0 ? inputs.length - 1 : inputs.length;
      permit = ISignatureTransfer.PermitBatchTransferFrom(
        new ISignatureTransfer.TokenPermissions[](permit_length),
        permit2.nonce,
        permit2.deadline
      );
      transferDetails = 
        new ISignatureTransfer.SignatureTransferDetails[](permit_length);
    }
    {
      uint256 expected_msg_value = 0;
      for (uint256 i = 0; i < inputs.length; i++) {
        if (inputs[i].tokenAddress == _ETH) {
          if (inputs[i].amountIn == 0) {
            inputs[i].amountIn = msg.value;
          }
          expected_msg_value = inputs[i].amountIn;
        }
        else {
          if (inputs[i].amountIn == 0) {
            inputs[i].amountIn = IERC20(inputs[i].tokenAddress).balanceOf(msg.sender);
          }
          uint256 permit_index = expected_msg_value == 0 ? i : i - 1;
          permit.permitted[permit_index].token = inputs[i].tokenAddress;
          permit.permitted[permit_index].amount = inputs[i].amountIn;
          transferDetails[permit_index].to = inputs[i].receiver;
          transferDetails[permit_index].requestedAmount = inputs[i].amountIn;
        }
      }
      require(msg.value == expected_msg_value, "Wrong msg.value");
    }
    ISignatureTransfer(permit2.contractAddress).permitTransferFrom(
      permit,
      transferDetails,
      msg.sender,
      permit2.signature
    );
    return _swapMulti(
      inputs,
      outputs,
      valueOutMin,
      pathDefinition,
      executor,
      referralCode
    );
  }
  function _swapMulti(
    inputTokenInfo[] memory inputs,
    outputTokenInfo[] memory outputs,
    uint256 valueOutMin,
    bytes calldata pathDefinition,
    address executor,
    uint32 referralCode
  )
    internal
    returns (uint256[] memory amountsOut)
  {
    require(valueOutMin > 0, "Slippage limit too low");
    uint256[] memory amountsIn = new uint256[](inputs.length);
    address[] memory tokensIn = new address[](inputs.length);
    {
      for (uint256 i = 0; i < inputs.length; i++) {
        amountsIn[i] = inputs[i].amountIn;
        tokensIn[i] = inputs[i].tokenAddress;
        for (uint256 j = 0; j < i; j++) {
          require(
            inputs[i].tokenAddress != inputs[j].tokenAddress,
            "Duplicate source tokens"
          );
        }
        for (uint256 j = 0; j < outputs.length; j++) {
          require(
            inputs[i].tokenAddress != outputs[j].tokenAddress,
            "Arbitrage not supported"
          );
        }
      }
    }
    uint256[] memory balancesBefore = new uint256[](outputs.length);
    for (uint256 i = 0; i < outputs.length; i++) {
      for (uint256 j = 0; j < i; j++) {
        require(
          outputs[i].tokenAddress != outputs[j].tokenAddress,
          "Duplicate destination tokens"
        );
      }
      balancesBefore[i] = _universalBalance(outputs[i].tokenAddress);
    }
    IOdosExecutor(executor).executePath{value: msg.value}(pathDefinition, amountsIn, msg.sender);
    referralInfo memory thisReferralInfo;
    if (referralCode > REFERRAL_WITH_FEE_THRESHOLD) {
      thisReferralInfo = referralLookup[referralCode];
    }
    {
      uint256 valueOut;
      uint256 _swapMultiFee = swapMultiFee;
      amountsOut = new uint256[](outputs.length);
      for (uint256 i = 0; i < outputs.length; i++) {
        amountsOut[i] = _universalBalance(outputs[i].tokenAddress) - balancesBefore[i];
        amountsOut[i] = amountsOut[i] * (FEE_DENOM - _swapMultiFee) / FEE_DENOM;
        if (referralCode > REFERRAL_WITH_FEE_THRESHOLD) {
          _universalTransfer(
            outputs[i].tokenAddress,
            thisReferralInfo.beneficiary,
            amountsOut[i] * thisReferralInfo.referralFee * 8 / (FEE_DENOM * 10)
          );
          amountsOut[i] = amountsOut[i] * (FEE_DENOM - thisReferralInfo.referralFee) / FEE_DENOM;
        }
        _universalTransfer(
          outputs[i].tokenAddress,
          outputs[i].receiver,
          amountsOut[i]
        );
        valueOut += amountsOut[i] * outputs[i].relativeValue;
      }
      require(valueOut >= valueOutMin, "Slippage Limit Exceeded");
    }
    address[] memory tokensOut = new address[](outputs.length);
    for (uint256 i = 0; i < outputs.length; i++) {
        tokensOut[i] = outputs[i].tokenAddress;
    }
    emit SwapMulti(
      msg.sender,
      amountsIn,
      tokensIn,
      amountsOut,
      tokensOut,
      referralCode
    );
  }
  function registerReferralCode(
    uint32 _referralCode,
    uint64 _referralFee,
    address _beneficiary
  )
    external
  {
    require(!referralLookup[_referralCode].registered, "Code in use");
    require(_referralFee <= FEE_DENOM / 50, "Fee too high");
    if (_referralCode <= REFERRAL_WITH_FEE_THRESHOLD) {
      require(_referralFee == 0, "Invalid fee for code");
    } else {
      require(_referralFee > 0, "Invalid fee for code");
      require(_beneficiary != address(0), "Null beneficiary");
    }
    referralLookup[_referralCode].referralFee = _referralFee;
    referralLookup[_referralCode].beneficiary = _beneficiary;
    referralLookup[_referralCode].registered = true;
  }
  function setSwapMultiFee(
    uint256 _swapMultiFee
  ) 
    external
    onlyOwner
  {
    require(_swapMultiFee <= FEE_DENOM / 200, "Fee too high");
    swapMultiFee = _swapMultiFee;
  }
  function writeAddressList(
    address[] calldata addresses
  ) 
    external
    onlyOwner
  {
    for (uint256 i = 0; i < addresses.length; i++) {
      addressList.push(addresses[i]);
    }
  }
  function transferRouterFunds(
    address[] calldata tokens,
    uint256[] calldata amounts,
    address dest
  )
    external
    onlyOwner
  {
    require(tokens.length == amounts.length, "Invalid funds transfer");
    for (uint256 i = 0; i < tokens.length; i++) {
      _universalTransfer(
        tokens[i], 
        dest, 
        amounts[i] == 0 ? _universalBalance(tokens[i]) : amounts[i]
      );
    }
  }
  function swapRouterFunds(
    inputTokenInfo[] memory inputs,
    outputTokenInfo[] memory outputs,
    uint256 valueOutMin,
    bytes calldata pathDefinition,
    address executor
  )
    external
    onlyOwner
    returns (uint256[] memory amountsOut)
  {
    uint256[] memory amountsIn = new uint256[](inputs.length);
    address[] memory tokensIn = new address[](inputs.length);
    for (uint256 i = 0; i < inputs.length; i++) {
      tokensIn[i] = inputs[i].tokenAddress;
      amountsIn[i] = inputs[i].amountIn == 0 ? 
        _universalBalance(tokensIn[i]) : inputs[i].amountIn;
      _universalTransfer(
        tokensIn[i],
        inputs[i].receiver,
        amountsIn[i]
      );
    }
    uint256[] memory balancesBefore = new uint256[](outputs.length);
    address[] memory tokensOut = new address[](outputs.length);
    for (uint256 i = 0; i < outputs.length; i++) {
      tokensOut[i] = outputs[i].tokenAddress;
      balancesBefore[i] = _universalBalance(tokensOut[i]);
    }
    IOdosExecutor(executor).executePath{value: 0}(pathDefinition, amountsIn, msg.sender);
    uint256 valueOut;
    amountsOut = new uint256[](outputs.length);
    for (uint256 i = 0; i < outputs.length; i++) {
      amountsOut[i] = _universalBalance(tokensOut[i]) - balancesBefore[i];
      _universalTransfer(
        outputs[i].tokenAddress,
        outputs[i].receiver,
        amountsOut[i]
      );
      valueOut += amountsOut[i] * outputs[i].relativeValue;
    }
    require(valueOut >= valueOutMin, "Slippage Limit Exceeded");
    emit SwapMulti(
      msg.sender,
      amountsIn,
      tokensIn,
      amountsOut,
      tokensOut,
      0
    );
  }
  function _universalBalance(address token) private view returns(uint256) {
    if (token == _ETH) {
      return address(this).balance;
    } else {
      return IERC20(token).balanceOf(address(this));
    }
  }
  function _universalTransfer(address token, address to, uint256 amount) private {
    if (token == _ETH) {
      (bool success,) = payable(to).call{value: amount}("");
      require(success, "ETH transfer failed");
    } else {
      IERC20(token).safeTransfer(to, amount);
    }
  }
}
