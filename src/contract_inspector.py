import os
import re
import pickle
import numpy as np
import requests
import pandas as pd
import http.client
import json
import time
import subprocess
from pathlib import Path
from tqdm import tqdm
from dotenv import load_dotenv
from collections import defaultdict

class ContractInspector:
    def __init__(self, config):
        self.config = config
    
    @staticmethod
    def get_scan_api_key(chain_id):
        keys = {
            '1': os.getenv('ETHERSCAN_API_KEY'),
            '56': os.getenv('BSCSCAN_API_KEY'),
            '137': os.getenv('POLYGONSCAN_API_KEY'),
            '8453': os.getenv('BASESCAN_API_KEY'),
            '59144': os.getenv('LINEASCAN_API_KEY'),
            '42161': os.getenv('ARBITRUMSCAN_API_KEY'),
            '534352': os.getenv('SCROLLSCAN_API_KEY'),
            '10': os.getenv('OPSCAN_API_KEY'),
            '204': os.getenv('OPBNBSCAN_API_KEY'),
            '167000': os.getenv('TAIKOSCAN_API_KEY'),
            '34443': os.getenv('MODE_SCAN_API_KEY'),
            '43114': os.getenv('AVAX_SCAN_API_KEY'),
            '250': os.getenv('FTM_SCAN_API_KEY'),
            '81457': os.getenv('BLAST_SCAN_API_KEY'),
            '200901': os.getenv('BITLAYER_SCAN_API_KEY'),
            '196': os.getenv('XLAYER_SCAN_API_KEY'),
            '5000': os.getenv('MNT_SCAN_API_KEY'),
        }
        return keys.get(str(chain_id))

    def fetch_chain_implementation(self, chain_id, address):
        std_chains = self.config['standard_chains']
        chain_id_str = str(chain_id)
        if chain_id_str in std_chains:
            if chain_id_str == '204':
                return self._get_opbnb_implementation_from_nodereal(chain_id, address)
            return self._get_standard_chain_implementation(chain_id, address)
        elif chain_id_str == '200901':
            return self._get_bitlayer_implementation(chain_id, address)
        elif chain_id_str == '196':
            return self._get_x1_implementation(chain_id, address)
        elif chain_id_str in ['60808', '169']:
            return self._get_manta_bob_implementation(chain_id, address)
        else:
            return None, "Unsupported chain"

    def download_contract_source(self, path, address, chain_id, name):
        # choose the correct method based on the chain ID
        chain_id_str = str(chain_id)
        cast_chains = self.config['cast_chains']
        api_standard_chains = self.config['api_standard_chains']
        if chain_id_str in cast_chains:
            return self._download_contract_source_by_cast(path, address, chain_id, name)
        elif chain_id_str in api_standard_chains:
            return self._download_contract_source_by_api_standard(path, address, chain_id, name)
        elif chain_id_str == '200901':
            return self._download_contract_source_by_api_bitlayer(path, address, chain_id, name)
        elif chain_id_str == '196':
            return self._download_contract_source_by_api_xlayer(path, address, chain_id, name)
        elif chain_id_str in ['169', '60808']:
            return self._download_contract_source_by_api_manta_bob(path, address, chain_id, name)
        else:
            print(f"Unsupported chain ID: {chain_id}")
            return None

    def check_proxy_contract(self, chain_id, address):
        std_chains = self.config['standard_chains']
        chain_id_str = str(chain_id)  # Ensure chain_id is a string
        if chain_id_str in std_chains:
            return self._check_standard_chain(chain_id, address)
        elif chain_id_str == '200901':
            return self._check_bitlayer(chain_id, address)
        elif chain_id_str == '196':
            return self._check_x1(chain_id, address)
        elif chain_id_str in ['60808', '169']:
            return self._check_manta_bob(chain_id, address)
        else:
            return None, "Unsupported chain"

    def _get_standard_chain_implementation(self, chain_id, address, is_proxy_call=False, retries=0):
        chain_config = self.config['chains_url'].get(str(chain_id))
        api_key = ContractInspector.get_scan_api_key(chain_id)

        params = {
            'module': 'contract',
            'action': 'getsourcecode',
            'address': address,
            'apikey': api_key
        }

        try:
            response = requests.get(chain_config['url'], params=params)
            if response.status_code != 200:
                print(f"HTTP error occurred: {response.status_code}")
                if retries < 5:  
                    print(f"Attempting to retry... (Attempt {retries + 1} of 5)")
                    time.sleep(3)
                    return self._get_standard_chain_implementation(chain_id, address, is_proxy_call, retries + 1)
                else:
                    return None, "HTTP error after maximum retries"

            data = response.json()
            if data['status'] != '1' or data['message'] != 'OK':
                print(f"API did not return valid contract data for {address} on chain {chain_id}")
                return None, data['result']

            result = data['result'][0]
            is_proxy = bool(int(result['Proxy']))

            if is_proxy:
                imple_address = result['Implementation']
                print(f"Proxy contract found, implementation address: {imple_address}")
                if is_proxy_call:
                    print(f"Multiple proxy layers detected at {address}, which is not supported.")
                    if result['SourceCode']:
                        return address, None
                    else:
                        return None, "Multiple proxy layers and no source code"
                return self._get_standard_chain_implementation(chain_id, imple_address, is_proxy_call=True)
            else:
                if not result['SourceCode']:
                    if is_proxy_call:
                        print(f"No source code found for proxy at {address}")
                        return None, "No source code for proxy"
                    else:
                        print(f"No source code found for {address}")
                        return None, "No source code"
                else:
                    return address, None

        except requests.RequestException as e:
            print(f"An error occurred while fetching data: {str(e)}")
            return None, "Request error"
        

    def _get_opbnb_implementation_from_nodereal(self, chain_id, address, is_proxy_call=False, retries=0):
        # Retrieve API key from environment variables
        api_key = os.getenv('OPBNBSCAN_API_KEY_NODEREAL')

        # Base URL for the API
        base_url = 'https://open-platform.nodereal.io/'

        # API key embedded directly in the path
        api_path = f'{api_key}/'

        # Endpoint for getting source code of a contract
        endpoint = 'op-bnb-mainnet/contract/'

        # Complete URL including the endpoint and API key
        url = f'{base_url}{api_path}{endpoint}'

        # Parameters for the GET request
        params = {
            'action': 'getsourcecode',
            'address': address
        }

        try:
            response = requests.get(url, params=params)
            if response.status_code != 200:
                print(f"HTTP error occurred: {response.status_code}")
                if retries < 5: 
                    print(f"Attempting to retry... (Attempt {retries + 1} of 5)")
                    time.sleep(3)
                    return self._get_opbnb_implementation_from_nodereal(chain_id, address, is_proxy_call, retries + 1)
                else:
                    return None, "HTTP error after maximum retries"

            data = response.json()
            if data['status'] != '1' or data['message'] != 'OK':
                print(f"API did not return valid contract data for {address} on chain {chain_id}")
                return None, data['result']

            result = data['result']
    
            if not result.get('SourceCode'):
                return None, "No source code"
            else:
                return address, None

        except requests.RequestException as e:
            print(f"An error occurred while fetching data: {str(e)}")
            return None, "Request error"


    def _get_bitlayer_implementation(self, chain_id, address, is_proxy_call=False, retries=0):
        chain_config = self.config['chains_url'].get(str(chain_id))

        params = {
            'module': 'contract',
            'action': 'getsourcecode',
            'address': address
        }

        try:
            response = requests.get(chain_config['url'], params=params)
            if response.status_code != 200:
                print(f"HTTP error occurred: {response.status_code}")
                if retries < 5:
                    print(f"Attempting to retry... (Attempt {retries + 1} of 5)")
                    time.sleep(3)
                    return self._get_bitlayer_implementation(chain_id, address, is_proxy_call, retries + 1)
                else:
                    return None, "HTTP error after maximum retries"

            data = response.json()
            if str(data.get('status')) != "1" or data.get('message') != 'OK' or (not data.get('result')):
                print(f"API did not return valid contract data for {address} on chain {chain_id}")
                return None, data

            result = data['result'][0]
            if not result.get('SourceCode'):
                if is_proxy_call:
                    print(f"No source code found for proxy at {address}")
                    return None, "No source code for proxy"
                else:
                    print(f"No source code found for {address}")
                    return None, "No source code"

            proxy_value = result.get('proxy', '0')
            if proxy_value.isdigit():
                is_proxy = bool(int(proxy_value))
            else:
                is_proxy = False

            if is_proxy:
                imple_address = result.get('Implementation')
                print(f"Proxy contract found, implementation address: {imple_address}")
                if is_proxy_call:
                    print(f"Multiple proxy layers detected at {address}, which is not supported.")
                    if result['SourceCode']:
                        return address, None
                    else:
                        return None, "Multiple proxy layers and no source code"
                return self._get_bitlayer_implementation(chain_id, imple_address, is_proxy_call=True)

            else:
                return address, None

        except requests.RequestException as e:
            print(f"An error occurred while fetching data: {str(e)}")
            return None, "Request error"

    #xlayer
    def _get_x1_implementation(self, chain_id, address, is_proxy_call=False, retries=0):
        chain_config = self.config['chains_url'].get(str(chain_id))
        api_key = ContractInspector.get_scan_api_key(chain_id)

        headers = {
            'OK-ACCESS-KEY': api_key
        }
        
        params = {
            'module': 'contract',
            'action': 'getsourcecode',
            'address': address
        }

        try:
            response = requests.get(chain_config['url'], headers=headers, params=params)
            if response.status_code != 200:
                print(f"HTTP error occurred: {response.status_code}")
                if retries < 5:
                    print(f"Attempting to retry... (Attempt {retries + 1} of 5)")
                    time.sleep(3)
                    return self._get_x1_implementation(chain_id, address, is_proxy_call, retries + 1)
                else:
                    return None, "HTTP error after maximum retries"

            data = response.json()
            print("Data return: ", data)
            if data['status'] != '1' or data['message'] != 'OK':
                print("API did not return valid contract data")
                return None, data['result']

            result = data['result'][0]
            is_proxy = bool(int(result['Proxy']))

            if is_proxy:
                imple_address = result['Implementation']
                print(f"Proxy contract found, implementation address: {imple_address}")
                # Recursively check if the implementation contract is open-source
                if is_proxy_call:
                    print(f"Multiple proxy layers detected at {address}, which is not supported.")
                    if result['SourceCode']:
                        return address, None
                    else:
                        return None, "Multiple proxy layers and no source code"
                return self._get_x1_implementation(chain_id, imple_address, is_proxy_call=True)
            else:
                if not result['SourceCode']:
                    if is_proxy_call:
                        print(f"No source code found for proxy at {address}")
                        return None, "No source code for proxy"
                    else:
                        print(f"No source code found for {address}")
                        return None, "No source code"
                else:
                    return address, None

        except requests.RequestException as e:
            print(f"An error occurred while fetching data: {str(e)}")
            return None, "Request error"


    def _get_manta_bob_implementation(self, chain_id, address, is_proxy_call=False, retries=0):
        chain_config = self.config['chains_url'].get(str(chain_id))

        params = {
            'module': 'contract',
            'action': 'getsourcecode',
            'address': address
        }

        try:
            response = requests.get(chain_config['url'], params=params)
            if response.status_code != 200:
                print(f"HTTP error occurred: {response.status_code}")
                if retries < 5:
                    print(f"Attempting to retry... (Attempt {retries + 1} of 5)")
                    time.sleep(3)
                    return self._get_manta_bob_implementation(chain_id, address, is_proxy_call, retries + 1)
                else:
                    return None, "HTTP error after maximum retries"

            data = response.json()
            print("Data returned: ", data)  # This can be removed or changed to logging based on production needs
            if data['status'] != '1' or data['message'] != 'OK':
                print("API did not return valid contract data")
                return None, data['result']

            result = data['result'][0]

            if 'SourceCode' not in result or not result['SourceCode']:
                if is_proxy_call:
                    print(f"No source code found for proxy at {address}")
                    return None, "No source code for proxy"
                else:
                    print(f"No source code found for {address}")
                    return None, "No source code"

            is_proxy = result.get('IsProxy', 'false').lower() == 'true'
            if is_proxy:
                imple_address = result.get('ImplementationAddress')
                if imple_address:
                    print(f"Proxy contract found, implementation address: {imple_address}")
                    # Recursively check if the implementation contract is open-source
                    return self._get_manta_bob_implementation(chain_id, imple_address, is_proxy_call=True)
                else:
                    print(f"No implementation address found for proxy contract at {address}")
                    return None, "No implementation address"
            else:
                return address, None

        except requests.RequestException as e:
            print(f"An error occurred while fetching data: {str(e)}")
            return None, "Request error"

    # Download the source code of a contract from cast command
    def _download_contract_source_by_cast(self, path, address, chainId, name):
        dir_path = os.path.join(path, str(chainId), name)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)

        print("Processing contract: ", address, "on chain: ", chainId)
        # Prepare the command to fetch the source code
        cmd = ['cast', 'etherscan-source', '--chain', str(chainId), '--etherscan-api-key', ContractInspector.get_scan_api_key(chainId), address]

        max_attempts = 5  
        for attempt in range(1, max_attempts + 1):
            try:
                # Run the command and capture the output
                result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, text=True)
                source_code = result.stdout

                file_path = os.path.join(dir_path, f"{name}.sol")

                # Write the source code to a file
                with open(file_path, 'w') as file:
                    file.write(source_code)

                return f"Source code saved to {file_path}"
            except subprocess.CalledProcessError as e:
                print(f"Attempt {attempt}: An error occurred while downloading the source code: {str(e)}")
                time.sleep(2) 
                if attempt == max_attempts:
                    print("Failed to download source code after several attempts.")
                    return "Failed to download source code."

    def _download_contract_source_by_api_standard(self, path, address, chainId, name):
        dir_path = os.path.join(path, str(chainId), name)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)

        chain_config = self.config['chains_url'].get(str(chainId))
        api_key = ContractInspector.get_scan_api_key(chainId)

        params = {
            'module': 'contract',
            'action': 'getsourcecode',
            'address': address,
            'apikey': api_key
        }

        retry_limit = 5
        attempts = 0

        while attempts < retry_limit:
            try:
                response = requests.get(chain_config['url'], params=params)
                if response.status_code == 200:
                    break
                else:
                    print(f"HTTP error occurred: {response.status_code}")
                    attempts += 1
                    time.sleep(2)
                    if attempts == retry_limit:
                        return "Failed after maximum retry attempts."
                    continue
            except requests.RequestException as e:
                print(f"An error occurred while fetching data: {str(e)}")
                attempts += 1
                if attempts == retry_limit:
                    return "Failed after maximum retry attempts."

        try:
            data = response.json()
            result = data['result'][0]
            content = result['SourceCode']
        except (requests.RequestException, json.JSONDecodeError) as e:
            if str(chainId) == '204':
                return self._download_contract_source_by_api_opbnb(path, address, chainId, name)
            else:
                return f"An error occurred: {str(e)}"
            
        try:
            fixed_content = content[1:-1]
            json_data = json.loads(fixed_content)
            solidity_source = ''
            for key, value in json_data['sources'].items():
                solidity_source += value['content'] + '\n'
        except json.JSONDecodeError as e1:
            # If JSON decoding fails, assign content directly to solidity_source
            solidity_source = content
        except KeyError as e:
            return f"Error extracting Solidity code: {e}"

        file_path = os.path.join(dir_path, f"{name}.sol")

        with open(file_path, 'w') as file:
            file.write(solidity_source)

        return f"Solidity source code has been successfully written to {file_path}"

    def _download_contract_source_by_api_bitlayer(self, path, address, chainId, name):
        dir_path = os.path.join(path, str(chainId), name)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)

        chain_config = self.config['chains_url'].get(str(chainId))

        params = {
            'module': 'contract',
            'action': 'getsourcecode',
            'address': address
        }

        retry_limit = 5
        attempts = 0

        while attempts < retry_limit:
            try:
                response = requests.get(chain_config['url'], params=params)
                if response.status_code == 200:
                    break
                else:
                    print(f"HTTP error occurred: {response.status_code}")
                    attempts += 1
                    time.sleep(2)
                    if attempts == retry_limit:
                        return "Failed after maximum retry attempts."
                    continue
            except requests.RequestException as e:
                print(f"An error occurred while fetching data: {str(e)}")
                attempts += 1
                if attempts == retry_limit:
                    return "Failed after maximum retry attempts."

        try:
            data = response.json()
            result = data['result'][0]
            content = result['SourceCode']
        except (requests.RequestException, json.JSONDecodeError) as e:
            return f"An error occurred: {str(e)}"

        try:
            # fixed_content = content[1:-1]
            fixed_content = content
            json_data = json.loads(fixed_content)
        except json.JSONDecodeError as e:
            return f"Error parsing JSON data: {e}"

        try:
            solidity_source = ''
            if 'sources' in json_data:
                for key, value in json_data['sources'].items():
                    solidity_source += value['content'] + '\n'
            else:
                for key, value in json_data.items():
                    solidity_source += value['content'] + '\n'
        except KeyError as e:
            return f"Error extracting Solidity code: {e}"

        file_path = os.path.join(dir_path, f"{name}.sol")

        with open(file_path, 'w') as file:
            file.write(solidity_source)

        return f"Solidity source code has been successfully written to {file_path}"

    def _download_contract_source_by_api_xlayer(self, path, address, chainId, name):
        dir_path = os.path.join(path, str(chainId), name)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)

        chain_config = self.config['chains_url'].get(str(chainId))
        api_key = ContractInspector.get_scan_api_key(chainId)

        headers = {
            'OK-ACCESS-KEY': api_key
        }

        params = {
            'module': 'contract',
            'action': 'getsourcecode',
            'address': address
        }

        retry_limit = 5
        attempts = 0

        while attempts < retry_limit:
            try:
                response = requests.get(chain_config['url'], headers=headers, params=params)
                if response.status_code == 200:
                    break
                else:
                    print(f"HTTP error occurred: {response.status_code}")
                    attempts += 1
                    time.sleep(2)
                    if attempts == retry_limit:
                        return "Failed after maximum retry attempts."
                    continue
            except requests.RequestException as e:
                print(f"An error occurred while fetching data: {str(e)}")
                attempts += 1
                if attempts == retry_limit:
                    return "Failed after maximum retry attempts."

        try:
            data = response.json()
            result = data['result'][0]
            content = result['SourceCode']
        except (requests.RequestException, json.JSONDecodeError) as e:
            return f"An error occurred: {str(e)}"

        try:
            # fixed_content = content[1:-1]
            json_data = json.loads(content)
            solidity_source = ''
            for key, value in json_data['sources'].items():
                solidity_source += value['content'] + '\n'
        except json.JSONDecodeError as e1:
            # If JSON decoding fails, assign content directly to solidity_source
            solidity_source = content
        except KeyError as e:
            return f"Error extracting Solidity code: {e}"

        file_path = os.path.join(dir_path, f"{name}.sol")

        with open(file_path, 'w') as file:
            file.write(solidity_source)

        return f"Solidity source code has been successfully written to {file_path}"

    def _download_contract_source_by_api_manta_bob(self, path, address, chainId, name):
        dir_path = os.path.join(path, str(chainId), name)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)

        chain_config = self.config['chains_url'].get(str(chainId))

        params = {
            'module': 'contract',
            'action': 'getsourcecode',
            'address': address
        }

        retry_limit = 5
        attempts = 0

        while attempts < retry_limit:
            try:
                response = requests.get(chain_config['url'], params=params)
                if response.status_code == 200:
                    break
                else:
                    print(f"HTTP error occurred: {response.status_code}")
                    attempts += 1
                    time.sleep(2)
                    if attempts == retry_limit:
                        return "Failed after maximum retry attempts."
                    continue
            except requests.RequestException as e:
                print(f"An error occurred while fetching data: {str(e)}")
                attempts += 1
                if attempts == retry_limit:
                    return "Failed after maximum retry attempts."


        data = response.json()
        # print("data return: ", data)
        result = data['result'][0]

        if 'SourceCode' not in result:
            return None
        
        content = result['SourceCode']
        additional_content = result.get('AdditionalSources', None)

        file_path = os.path.join(dir_path, f"{name}.sol")

        with open(file_path, 'w') as file:
            file.write(content)
            # Write additional sources if available
            if additional_content:
                for separated_file in additional_content:
                    file.write(separated_file['SourceCode'])

        return f"Solidity source code has been successfully written to {file_path}"

    def _download_contract_source_by_api_opbnb(self, path, address, chainId, name):
        dir_path = os.path.join(path, str(chainId), name)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)

        # Retrieve API key from environment variables
        api_key = os.getenv('OPBNBSCAN_API_KEY_NODEREAL')
        base_url = 'https://open-platform.nodereal.io/'

        # API key embedded directly in the path
        api_path = f'{api_key}/'
        endpoint = 'op-bnb-mainnet/contract/'

        # Complete URL including the endpoint and API key
        url = f'{base_url}{api_path}{endpoint}'

        # Parameters for the GET request
        params = {
            'action': 'getsourcecode',
            'address': address
        }

        retry_limit = 5
        attempts = 0

        while attempts < retry_limit:
            try:
                response = requests.get(url, params=params)
                if response.status_code == 200:
                    break
                else:
                    print(f"HTTP error occurred: {response.status_code}")
                    attempts += 1
                    time.sleep(2)
                    if attempts == retry_limit:
                        return "Failed after maximum retry attempts."
                    continue
            except requests.RequestException as e:
                print(f"An error occurred while fetching data: {str(e)}")
                attempts += 1
                if attempts == retry_limit:
                    return "Failed after maximum retry attempts."

        try:
            data = response.json()
            content = data['result']
        except (requests.RequestException, json.JSONDecodeError) as e:
            return f"An error occurred: {str(e)}"

        fixed_content = content['SourceCode']

        if isinstance(fixed_content, dict):
            solidity_source = ''
            for key, value in fixed_content.items():
                solidity_source += value + '\n'
        else:
            solidity_source = fixed_content

        file_path = os.path.join(dir_path, f"{name}.sol")

        with open(file_path, 'w') as file:
            file.write(solidity_source)

        return f"Solidity source code has been successfully written to {file_path}"

    def _check_standard_chain(self, chain_id, address, retries=0):
        chain_config = self.config['chains_url'].get(str(chain_id))
        api_key = ContractInspector.get_scan_api_key(chain_id)

        params = {
            'module': 'contract',
            'action': 'getsourcecode',
            'address': address,
            'apikey': api_key
        }

        try:
            response = requests.get(chain_config['url'], params=params)
            if response.status_code != 200:
                print(f"HTTP error occurred: {response.status_code}")
                if retries < 5:  # 检查是否达到最大重试次数
                    print(f"Attempting to retry... (Attempt {retries + 1} of 5)")
                    time.sleep(3)
                    return self._check_standard_chain(chain_id, address, retries + 1)
                else:
                    return False

            data = response.json()
            if data['status'] == '1' and data['message'] == 'OK':
                contract_name = data['result'][0].get('ContractName', '')
                if 'Proxy' in contract_name:
                    return True
            return False

        except requests.RequestException as e:
            print(f"An error occurred while fetching data: {str(e)}")
            return False

    def _check_bitlayer(self, chain_id, address, retries=0):
        chain_config = self.config['chains_url'].get(str(chain_id))

        params = {
            'module': 'contract',
            'action': 'getsourcecode',
            'address': address
        }

        try:
            response = requests.get(chain_config['url'], params=params)
            if response.status_code != 200:
                print(f"HTTP error occurred: {response.status_code}")
                if retries < 5:  # 检查是否达到最大重试次数
                    print(f"Attempting to retry... (Attempt {retries + 1} of 5)")
                    time.sleep(3)
                    return self._check_bitlayer(chain_id, address, retries + 1)
                else:
                    return False

            data = response.json()
            if str(data.get('status')) == "1" and data['message'] == 'OK':
                contract_name = data['result'][0].get('ContractName', '')
                if 'Proxy' in contract_name:
                    return True
            return False

        except requests.RequestException as e:
            print(f"An error occurred while fetching data: {str(e)}")
            return False

    def _check_x1(self, chain_id, address, retries=0):
        chain_config = self.config['chains_url'].get(str(chain_id))
        api_key = ContractInspector.get_scan_api_key(chain_id)

        headers = {
            'OK-ACCESS-KEY': api_key
        }

        params = {
            'module': 'contract',
            'action': 'getsourcecode',
            'address': address
        }

        try:
            response = requests.get(chain_config['url'], headers=headers, params=params)
            if response.status_code != 200:
                print(f"HTTP error occurred: {response.status_code}")
                if retries < 5:  # 检查是否达到最大重试次数
                    print(f"Attempting to retry... (Attempt {retries + 1} of 5)")
                    time.sleep(3)
                    return self._check_x1(chain_id, address, retries + 1)
                else:
                    return False

            data = response.json()
            if data['status'] == '1' and data['message'] == 'OK':
                contract_name = data['result'][0].get('ContractName', '')
                if 'Proxy' in contract_name:
                    return True
            return False

        except requests.RequestException as e:
            print(f"An error occurred while fetching data: {str(e)}")
            return False

    def _check_manta_bob(self, chain_id, address, retries=0):
        chain_config = self.config['chains_url'].get(str(chain_id))
        params = {
            'module': 'contract',
            'action': 'getsourcecode',
            'address': address
        }

        try:
            response = requests.get(chain_config['url'], params=params)
            if response.status_code != 200:
                print(f"HTTP error occurred: {response.status_code}")
                if retries < 5:  
                    print(f"Attempting to retry... (Attempt {retries + 1} of 5)")
                    time.sleep(3)
                    return self._check_manta_bob(chain_id, address, retries + 1)
                else:
                    return False

            data = response.json()
            if data['status'] == '1' and data['message'] == 'OK':
                contract_name = data['result'][0].get('ContractName', '')
                if 'Proxy' in contract_name:
                    return True
            return False

        except requests.RequestException as e:
            print(f"An error occurred while fetching data: {str(e)}")
            return False
