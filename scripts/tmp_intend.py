import time
import requests


def ask_openai_for_category(prompt,api_base,api_key,model):
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
        data = {
            "model": model,
            "response_format": { "type": "json_object" },
            "messages": [
                {
                    "role": "system",
                    "content": "You are a helpful assistant designed to output JSON."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        }
        response = requests.post(f'https://{api_base}/v1/chat/completions', headers=headers, json=data)

        response_josn = response.json()
        if 'choices' not in response_josn:
            return ''
        return response_josn['choices'][0]['message']['content']
code="""
function bridgeToV2(BridgeRequestV2 memory _request)
        external
        payable
        nonReentrant
        whenNotPaused
    {
        _bridgeToV2Internal(_request);
    }function _bridgeToV2Internal(BridgeRequestV2 memory _request) internal {
        require(_request.adaptorId != 0, XBridgeErrors.INVALID_ADAPTOR_ID);
        address adaptor = adaptorInfo[_request.adaptorId];
        require(adaptor != address(0), XBridgeErrors.INVALID_ADAPTOR_ADDRESS);
        require(_request.to != address(0), XBridgeErrors.ADDRESS_0);
        require(_request.token != address(0), XBridgeErrors.ADDRESS_0);
        require(_request.amount != 0, XBridgeErrors.AMOUNT_ZERO);

        // doCommission
        CommissionReturn memory vars;
        (vars.commissionAmount, vars.extDataWithoutLast32) = _doCommission(_request.amount, _request.token, _request.extData);
        _request.extData = vars.extDataWithoutLast32;
        uint256 ethValue = msg.value;

        // Extract gas fee details from toChainId
        (uint256 orderId, uint256 gasFeeAmount, uint256 toChainId) = _getGasReceiveAmount(_request.toChainId);
        if (_request.token == XBridgeConstants.NATIVE_TOKEN) {
            require(msg.value >= _request.amount + gasFeeAmount + vars.commissionAmount, XBridgeErrors.INVALID_MSG_VALUE);
            ethValue -= vars.commissionAmount;   // after docommission
            if (gasFeeAmount > 0) {
                (bool success, ) = payable(feeTo).call{value: gasFeeAmount}("");
                require(success, XBridgeErrors.TRANSFER_ETH_FAILD);
                ethValue -= gasFeeAmount;
            }
        } else {
            if (gasFeeAmount > 0) {
                _deposit(msg.sender, feeTo, _request.token, gasFeeAmount);
            }
            _deposit(msg.sender, adaptor, _request.token, _request.amount);
        }

        // Call the outboundBridgeTo function on the selected adaptor
        BridgeAdaptorBase(payable(adaptor)).outboundBridgeTo{value : ethValue}(
            msg.sender,
            _request.to,
            msg.sender, // refund to msg.sender
            _request.token,
            _request.amount,
            toChainId,
            _request.data
        );

        // Construct extension data and emit the LogBridgeTo event
        bytes32[] memory ext = _constructExt(
                                    orderId,
                                    toChainId,
                                    _request.adaptorId,
                                    _request.to,
                                    _request.data,
                                    _request.extData
                                );
        emit LogBridgeTo(
            _request.adaptorId,
            msg.sender,
            _request.to,
            _request.token,
            _request.amount,
            gasFeeAmount,
            ext
        );
    } 

"""
categories="""
swap
claim
bridge To L2
bridge
staking
deposit
depositIntoStrategy
register ENS
refinance
stake
multicall
takeBid
unwrap WETH
assertOwnership
delegateTo
withdraw
mint
wrap WETH
bridge From L2
inscribe
borrow
takeAsk
execute
matchOrder
unstake
startAuction
cancel
wrap stETH
redeem
wrap
vesting
delegate
lock 
"""
prompt=f"""
{code}
The business logic of the above code belongs to which of the following categories?
{categories}
Identify the most suitable 5 categories, ranked from most suitable to least suitable:
and provide explanations.
Your output should be in JSON format, as follows: {{
  "categories": [
    category1:explanation1,
    category2:explanation2,
    category3:explanation3,
    ...
  ]
}}

"""
api_base= "apix.ai-gaochao.cn"  # Replace with your actual OpenAI API base URL
api_key = "sk-xx"  # Replace with your actual OpenAI API key
model="gpt-4o"
time_start = time.time()
print(ask_openai_for_category(prompt,api_base,api_key,model))
time_end = time.time()
print("Time elapsed: ", time_end - time_start)