import pandas as pd
import requests
import subprocess
import time
import os
import json
import re
from dotenv import load_dotenv

# 输入：两个excel文件，former：A，latter：B
# 输出：一个excel文件，包含B中的所有地址，是否收纳（是：加上gas used属性，否：原因（A已有或复杂逻辑说明）），代币查看链接（etherscan链接）
# 1. 对比两个excel，找出增量地址
# 2. 查看是否为Proxy合约
# 3. 对于非Proxy合约，运行命令下载源码
# 4. 写个函数，将源码中approve方法以及它可能调用的其他办法提取出来
# 5. 通过embedding模型，获取approve方法的特征向量，与特定样本计算余弦相似度，进行筛选

load_dotenv()   # Load environment variables

# Etherscan API Key
API_KEY_ETHERSCAN = os.getenv('API_KEY_ETHERSCAN')
URL = os.getenv('URL_ETHERSCAN')

# excel info
excel_path_basic = 'wallet_top100_token_0606.xlsx'
excel_path_incre = 'gas_fee_online_0606.xlsx'
sheet_name_basic = 'approve'
sheet_name_incre = 'top100 - approve_zero'
column_name = 'contract_address'
code_save_path_standard = './TokenReference/'
code_save_path_compare = './TokenCompare/Simple'

def get_incre_address():
    data_basic = pd.read_excel(excel_path_basic, sheet_name=sheet_name_basic)
    data_incre = pd.read_excel(excel_path_incre, sheet_name=sheet_name_incre)

    # extract contract_address, remove NaN and duplicates
    addresses_basic = data_basic[column_name].dropna().unique()
    addresses_incre = data_incre[column_name].dropna().unique()

    # sort out incremental addresses
    incremental_addresses = [address for address in addresses_incre if address not in addresses_basic]
    print(f"Total incremental addresses: {len(incremental_addresses)}")
    return incremental_addresses

# def is_proxy_contract(address):
#     try:
#         params = {
#             'module': 'contract',
#             'action': 'verifyproxycontract',
#             'address': address,
#             'apikey': API_KEY_ETHERSCAN
#         }
#         response = requests.post(URL, params=params)
#         response_json = response.json()
#         print(response_json)
#         # avoid "pending in queue" status results in duplicated requests, so sleep for a while
#         time.sleep(3)

#         if response_json['status'] == '1' and response_json['message'] == 'OK':
#             guid = response_json['result']

#             check_params = {
#                 'module': 'contract',
#                 'action': 'checkproxyverification',
#                 'guid': guid,
#                 'apikey': API_KEY_ETHERSCAN
#             }
#             check_response = requests.get(URL, params=check_params)
#             check_response_json = check_response.json()
#             print(check_response_json)
#             if check_response_json['status'] == '1' and 'implementation contract is found at' in check_response_json['result']:
#                 return True
#             else:
#                 return False
#         else:
#             return False
#     except Exception as e:
#         print(f"Error: {e}")
#         return False

# Fetch contract info from Etherscan
def fetch_contract_info(address):
    params = {
        'module': 'contract',
        'action': 'getsourcecode',
        'address': address,
        'apikey': API_KEY_ETHERSCAN
    }

    try:
        response = requests.get(URL, params=params)
        if response.status_code != 200:
            print(f"HTTP error occurred: {response.status_code}")
            return None

        data = response.json()
        if data['status'] != '1' or data['message'] != 'OK':
            print("API did not return valid contract data")
            return None

        result = data['result'][0]
        is_proxy = bool(int(result['Proxy']))

        if is_proxy:
            return {'is_proxy': True, 'source_code': None, 'name': None}
        else:
            # cmd = [
            #     'sdl', 'get',
            #     '-a', address,
            #     '-k', API_KEY_ETHERSCAN,
            #     '-o', './download'
            # ]
            source_code = result['SourceCode']
            # subprocess.run(cmd, check=True)
            return {'is_proxy': False, 'source_code': source_code if source_code else "No source code found", 'name': result['ContractName']}

    except requests.RequestException as e:
        print(f"An error occurred while fetching data: {str(e)}")
        return None

def download_contract_source(path, address, name):
    dir_path = os.path.join(path, name)
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)

    # Prepare the command to fetch the source code
    cmd = ['cast', 'etherscan-source', '--chain', 1, address]

    max_attempts = 3  # 设定最大重试次数
    for attempt in range(1, max_attempts + 1):
        try:
            # Run the command and capture the output
            result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, text=True)
            source_code = result.stdout

            file_path = os.path.join(dir_path, f"{name}.sol")

            # Write the source code to a file
            with open(file_path, 'w') as file:
                file.write(source_code)

            return f'Source code saved to ./download/{name}.sol'
        except subprocess.CalledProcessError as e:
            print(f"Attempt {attempt}: An error occurred while downloading the source code: {str(e)}")
            time.sleep(5)  # 在重试之前等待
            if attempt == max_attempts:
                print("Failed to download source code after several attempts.")


def remove_solidity_comments(input_file_path, output_file_path):
    with open(input_file_path, 'r') as file:
        source_code = file.read()

    # Remove all multi-line comments
    source_code = re.sub(r'/\*.*?\*/', '', source_code, flags=re.DOTALL)

    # remove all single-line comments
    source_code = re.sub(r'//.*', '', source_code)

    # Remove excess blank lines
    source_code = re.sub(r'\n\s*\n', '\n', source_code)

    # save the modified source code to the output file
    with open(output_file_path, 'w') as file:
        file.write(source_code)

    print("Remove comments done for ", output_file_path)


def main():
    # address_result = get_incre_address()
    # address_result_standard = ['0x64Bc2cA1Be492bE7185FAA2c8835d9b824c8a194', '0x36E66fbBce51e4cD5bd3C62B637Eb411b18949D4', '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2', '0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599']

    # data = pd.read_excel('./input/gas_fee_online_0606.xlsx', sheet_name='top100 - approve_zero')
    # address_list = data['contract_address'].dropna().unique()
    # print("Total addresses: ", len(address_list))
    # for address in address_list:
    #     # Set a delay to avoid rate limiting
    #     time.sleep(5)
    #     result = fetch_contract_info(address)
    #     if result:
    #         if not result['is_proxy']:
    #             download_contract_source(code_save_path_compare, address, result['name'])
    #             print(address, result['name'],"download done.")
    #         else:
    #             print(address, result['name'],"is a proxy contract.")
    #     else:
    #         print("Failed to retrieve contract data.")


    # # remove comments for all the solidity files already download
    for subdir in os.listdir('./testDownload'):
        subdir_path = os.path.join('./testDownload', subdir)
        if os.path.isdir(subdir_path):
            for ssubdir in os.listdir(subdir_path):
                ssubdir_path = os.path.join(subdir_path, ssubdir)
                if os.path.isdir(ssubdir_path):
                    for file in os.listdir(ssubdir_path):
                        file_path = os.path.join(ssubdir_path, file)
                        if file_path.endswith('.sol'):
                            remove_solidity_comments(file_path, file_path)


if __name__ == '__main__':
    main()