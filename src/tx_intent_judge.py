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
from project_parser import parse_project
from function_trace_analyser import analyze_target_functions, analyze_target_functions_within_contract
from selector_extractor import calculate_selector_from_sig, extract_sig
from tqdm import tqdm
from dotenv import load_dotenv

load_dotenv()   # Load environment variables

INPUT_PATH = './data/source/交易类型解析.xlsx'
TOP10_PATH = './data/source/top100.xlsx'
SOURCE_CODE_PATH = './data/code'
PARSING_RESULT_PATH = './data/parsing_result'

# Params for OpenAI API
API_KEY = os.getenv('OPENAI_API_KEY')
API_BASE = os.getenv('OPENAI_API_BASE')
MODEL = os.getenv('PRE_TRAIN_MODEL')

# Etherscan API Key
API_KEY_ETHERSCAN = os.getenv('API_KEY_ETHERSCAN')
URL = os.getenv('URL_ETHERSCAN')

with open('chain_config.json', 'r') as f:
    config = json.load(f)

def get_scan_api_key(chain_id):
    keys = {
        '1': os.getenv('ETHERSCAN_API_KEY'),
        '56': os.getenv('BSCSCAN_API_KEY'),
        '137': os.getenv('POLYGONSCAN_API_KEY'),
        '8453': os.getenv('BASESCAN_API_KEY'),
        '59144': os.getenv('LINEASCAN_API_KEY'),
        '42161': os.getenv('ARBITRUMSCAN_API_KEY'),
    }
    return keys.get(str(chain_id))

def get_methodId_from_excel(file_path, sheet, address):
    data = pd.read_excel(file_path, sheet_name=sheet)
    result = data[data['to_address'] == address]
    return result['method_id'].tolist()

# Use cast command to get the signature from methodId
def get_signature_from_id(methodId):
    cmd = ['cast', '4byte', methodId]
    max_retries = 3
    attempt = 0

    while attempt < max_retries:
        try:
            result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, text=True)
            func_sig = result.stdout
            func_name = func_sig.split('(')[0]
            print("get sig from id", methodId, func_name)
            return func_name
        except subprocess.CalledProcessError as e:
            print(f"Attempt {attempt + 1}: An error occurred: {str(e)} for {methodId}")
            attempt += 1

    print("Failed to get signature after 3 attempts.")
    return None

# Scan the source code file to find the signature which matches the methodId
def search_signature_from_id(source_code_file, parsing_result, methodId):
    with open(source_code_file, 'r') as file:
        source_code = file.read()

    for func in parsing_result:
        origin_sig = extract_sig(func['content'])
        if origin_sig:
            if calculate_selector_from_sig(origin_sig, source_code) == methodId:
                print("search sig from id: ", origin_sig)
                return origin_sig.split('(')[0]
    
    return None

# Get the implementation address of a contract or the original contract address if not proxy
def get_imple_info(chain_id, address): 
    chain_config = config['chains'].get(str(chain_id))
    if not chain_config:
        print(f"Unsupported chain ID: {chain_id}")
        return None
    
    api_key = get_scan_api_key(chain_id)
    if not api_key:
        print(f"API key not found for chain ID: {chain_id}")
        return None

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
            return None

        data = response.json()
        if data['status'] != '1' or data['message'] != 'OK':
            print("API did not return valid contract data")
            return None

        result = data['result'][0]
        is_proxy = bool(int(result['Proxy']))

        if is_proxy:
            imple_address = result['Implementation']
            print(f"Proxy contract found, implementation address: {imple_address}")
            return imple_address
        else:
            if not result['SourceCode']:
                print(f"No source code found for {address}")
                return None
            else:
                return address

    except requests.RequestException as e:
        print(f"An error occurred while fetching data: {str(e)}")
        return None  
    
# Download the source code of a contract from cast command
def download_contract_source(path, address, chainId, name):
    dir_path = os.path.join(path, str(chainId), name)
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)

    # Prepare the command to fetch the source code
    cmd = ['cast', 'etherscan-source', '--chain', str(chainId), '--etherscan-api-key', get_scan_api_key(chainId), address]

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
            time.sleep(5) 
            if attempt == max_attempts:
                print("Failed to download source code after several attempts.")
                return "Failed to download source code."

def fetch_response(code_snippet, method_names):
    conn = http.client.HTTPSConnection(f'{API_BASE}')
    headers = {
        'Authorization': f'Bearer {API_KEY}',
        'User-Agent': 'Apifox/1.0.0 (https://apifox.com)',
        'Content-Type': 'application/json'
    }

    prompt = f"""
    You are an engineer skilled in on-chain transaction analysis. 
    Your task is to analyze the intent of a given transaction involving specific code snippets and the smart contract being called, then categorize it accordingly. 
    Please select the most fitting category from the following predefined options: Swap, Deposit, Withdraw, Bridge, Claim, Stake, Mint, Multicall, Delegate, buy/sell NFT,  and wrap/unwrap. 
    Extra attentions should be paid when dealing with the case for different types of deposits. For instance, typical 'deposit' actions just refer to transferring assets into a smart contract. While 'depositETH' often involves depositing native tokens (like ETH) and could indicate a bridging activity where the asset is transferred across different blockchain.
    If none of these categories accurately describe the transaction's intent, succinctly summarize it using one or two brief words or just extract key keywords from the function name and use them as the category.    
    """

    format = f"""
    Please answer the code snippet belongs to which category. Your output must be in JSON format, as follows:
    {{ "Category": "Swap", "Reason": "The code swap the input token for certain output token" }}
    In your response, ensure that the reason is succinct and clearly communicates the key rationale behind the categorization.
    """

    content = f"""
    {method_names} are called with the following code snippet: {code_snippet}
    """

    data = json.dumps({
        "model": "gpt-4o",
        "messages": [
            {
                "role": "system",
                "content": prompt
            },
            {
                "role": "user",
                "content": content
            },
            {
                "role": "user",
                "content": format
            }
        ]
    })

    try:
        conn.request("POST", "/v1/chat/completions", data, headers)
        res = conn.getresponse()
        response_data = res.read()

        response_json = json.loads(response_data.decode("utf-8"))
        # print("Response received successfully: ", response_json)
        json_string = response_json['choices'][0]['message']['content']
        # print("JSON string: ", json_string, type(json_string))

        # Standardize the JSON string to get the category and reason
        pattern = r'"Category"\s*:\s*"([^"]*)",\s*"Reason"\s*:\s*"([^"]*)"'
        match = re.search(pattern, json_string)
        if match:
            category = match.group(1)
            reason = match.group(2)
            print(f"Category: {category}, Reason: {reason}")
            return category, reason
        else:
            print("Failed to extract judgment and reason from the response.")
            return None, None
    except json.JSONDecodeError:
        print("Failed to decode JSON response")
        return None, None
    except Exception as e:
        print(f"Error fetching response: {e}")
        return None, None
    finally:
        conn.close()

# Main logic where the source code is parsed then analyzed using OpenAI API
def parse_solidity_files_using_chat():
    # parse all solidity files in the directory
    base_path = SOURCE_CODE_PATH
    excel_path = TOP10_PATH
    results = pd.read_excel(excel_path)
    results.set_index(['to_address', 'method_id'], inplace=True)

    for chainId in tqdm(os.listdir(base_path), desc="Processing Chain IDs"):
        chainId_path = os.path.join(base_path, chainId)
        if not os.path.isdir(chainId_path):
            continue

        if chainId != '1':
            continue

        filtered_data = results[(results['chain_id'] == int(chainId)) & (results['Imple_address'].notna())]

        for (to_address, methodId), row in filtered_data.iterrows():
            address_path = os.path.join(chainId_path, to_address)
            # print(f"Processing {address_path}")
            if not os.path.isdir(address_path):
                continue

            all_functions, _ = parse_project(address_path)

            intermediate_path = os.path.join(PARSING_RESULT_PATH, str(chainId), f"{to_address}.txt")
            os.makedirs(os.path.dirname(intermediate_path), exist_ok=True)

            with open(intermediate_path, 'w') as f:
                for func in all_functions:
                    f.write(str(func) + '\n')

            # methodId = get_methodId(to_address)[0]
            function_name = get_signature_from_id(methodId)
            if not function_name:
                source_code_path = os.path.join(address_path, f"{to_address}.sol")
                function_name = search_signature_from_id(source_code_path, all_functions, methodId)
                if not function_name:
                    results.loc[(to_address, methodId), ['Function', 'Category', 'Reason', 'Code']] = ["None", "None", "None", "None"]
                    continue
            print(f"Function name found for {to_address}: {function_name}")


            related_functions = analyze_target_functions_within_contract(all_functions, f"{function_name}")
            if not related_functions:
                results.loc[(to_address, methodId), ['Function', 'Category', 'Reason', 'Code']] = ["None", "None", "None", "None"]
                continue
            print(f"Related functions found for {function_name}: {related_functions}")

            related_functions_content = [func for func in all_functions if func['name'] in related_functions]
            contents = ''.join([func['content'] for func in related_functions_content])

            label, reason = fetch_response(contents, related_functions)
            results.loc[(to_address, methodId), ['Function', 'Category', 'Reason', 'Code']] = [function_name, label, reason, contents]

            time.sleep(1)

    # Save the updated DataFrame back to the same Excel file
    results.to_excel(excel_path)
    print(f"Results updated and saved to {excel_path}")


def main():
    ### Get imple address
    # df = pd.read_excel('./input/交易类型解析.xlsx')

    # # Add a new column to store the implementation address
    # df['Imple_address'] = None

    # for index, row in df.iterrows():
    #     imple_address = get_imple_info(row['chain_id'], row['to_address'])
    #     df.at[index, 'Imple_address'] = imple_address

    # df.to_excel('./input/交易类型解析.xlsx', index=False)

    ### Download contract source code
    # for index, row in df.iterrows():
    #     imple_address = row['Imple_address']
    #     print("Unique imple len", len(df['Imple_address']),len(df['Imple_address'].unique()))
    #     chainId = row['chain_id']
        # Check if the implementation address is not None
        # if pd.notna(imple_address):
            # Download the source code
            # result = download_contract_source('./testDownload', imple_address, chainId, f"{row['to_address']}")
            # print(result)

    parse_solidity_files_using_chat()



if __name__ == '__main__':
    main()
