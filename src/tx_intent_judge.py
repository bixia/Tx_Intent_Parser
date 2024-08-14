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
from tqdm import tqdm
from dotenv import load_dotenv
from contract_inspector import ContractInspector
from selector_extractor import SelectorExtractor
from function_trace_analyser import TraceAnalyser

load_dotenv()   # Load environment variables

INPUT_PATH = './data/source/未解析top1000_0808.xlsx'
SOURCE_CODE_PATH = './data/code'
PARSING_RESULT_PATH = './data/parsing_result'

# Params for OpenAI API
API_KEY = os.getenv('OPENAI_API_KEY')
API_BASE = os.getenv('OPENAI_API_BASE')

with open('chain_config.json', 'r') as f:
    config = json.load(f)

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
            time.sleep(1)

    print("Failed to get signature after 3 attempts.")
    return None

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

def fetch_classification(code_snippet, method_names):
    conn = http.client.HTTPSConnection(f'{API_BASE}')
    headers = {
        'Authorization': f'Bearer {API_KEY}',
        'User-Agent': 'Apifox/1.0.0 (https://apifox.com)',
        'Content-Type': 'application/json'
    }

    prompt = os.getenv('PROMPT_TEXT')

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

    attempts = 0
    while attempts < 5:
        try:
            conn.request("POST", "/v1/chat/completions", data, headers)
            res = conn.getresponse()
            response_data = res.read()

            response_json = json.loads(response_data.decode("utf-8"))
            print("Response received successfully: ", response_json)
            json_string = response_json['choices'][0]['message']['content']

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
            attempts += 1
            if attempts == 5:
                print("Maximum retry attempts reached.")
            continue
        except Exception as e:
            print(f"Error fetching response: {e}")
            attempts += 1
            if attempts == 5:
                print("Maximum retry attempts reached.")
            continue
        finally:
            conn.close()
    
    return None, None

# Main logic where the source code is parsed then analyzed using OpenAI API
def parse_and_classify_solidity_code():
    # parse all solidity files in the directory
    base_path = SOURCE_CODE_PATH
    excel_path = INPUT_PATH
    results = pd.read_excel(excel_path)
    results.set_index(['address', 'method_id'], inplace=True)

    selector_extractor = SelectorExtractor()
    func_analyser = TraceAnalyser()

    for chainId in tqdm(os.listdir(base_path), desc="Processing Chain IDs"):
        chainId_path = os.path.join(base_path, chainId)
        if not os.path.isdir(chainId_path):
            continue

        filtered_data = results[(results['chain_id'] == int(chainId)) & (results['Imple_address'].notna())]

        for (to_address, methodId), row in filtered_data.iterrows():
            # Continue if mehtodId or to_address is not available
            if pd.isna(methodId) or pd.isna(to_address):
                continue

            print(f"Processing {to_address} with methodId: {methodId} on chain {chainId}")

            address_path = os.path.join(str(chainId_path), to_address)
            # print(f"Processing {address_path}")
            if not os.path.isdir(address_path):
                continue

            all_functions, _ = parse_project(address_path)

            intermediate_path = os.path.join(PARSING_RESULT_PATH, str(chainId), f"{to_address}.txt")
            os.makedirs(os.path.dirname(intermediate_path), exist_ok=True)

            with open(intermediate_path, 'w') as f:
                for func in all_functions:
                    f.write(str(func) + '\n')

            function_name = get_signature_from_id(methodId)
            if not function_name or not any(function_name in func['name'] for func in all_functions):
                source_code_path = os.path.join(address_path, f"{to_address}.sol")
                if not os.path.exists(source_code_path):
                    results.loc[(to_address, methodId), ['Function', 'Category', 'Reason', 'Code']] = [pd.NA, pd.NA, pd.NA, pd.NA]
                    continue
                function_name = selector_extractor.search_signature_from_id(source_code_path, all_functions, methodId)
                if not function_name:
                    results.loc[(to_address, methodId), ['Function', 'Category', 'Reason', 'Code']] = [pd.NA, pd.NA, pd.NA, pd.NA]
                    continue
            print(f"Function name found for {to_address}: {function_name}")

            # Use regex to match the specific function name and type
            if 'and' in function_name.toLowerCase():
                continue
            else:
                if 'unwrap' in function_name.toLowerCase():
                    results.loc[(to_address, methodId), ['Function', 'Category', 'Reason', 'Code']] = [function_name, 'unwrap', 'Regex', '']
                    continue
                if 'wrap' in function_name.toLowerCase():
                    results.loc[(to_address, methodId), ['Function', 'Category', 'Reason', 'Code']] = [function_name, 'wrap', 'Regex', '']
                    continue
                if 'exitmarket' in function_name.toLowerCase():
                    results.loc[(to_address, methodId), ['Function', 'Category', 'Reason', 'Code']] = [function_name, 'exit market', 'Regex', '']
                    continue
                if 'entermarket' in function_name.toLowerCase():
                    results.loc[(to_address, methodId), ['Function', 'Category', 'Reason', 'Code']] = [function_name, 'enter market', 'Regex', '']
                    continue
                if methodId == '0x74694a2b':
                    results.loc[(to_address, methodId), ['Function', 'Category', 'Reason', 'Code']] = [function_name, 'register ens', 'Regex', '']
                    continue
                if 'farming' in function_name.toLowerCase():
                    results.loc[(to_address, methodId), ['Function', 'Category', 'Reason', 'Code']] = [function_name, 'farming', 'Regex', '']
                    continue
                if 'query' in function_name.toLowerCase():
                    results.loc[(to_address, methodId), ['Function', 'Category', 'Reason', 'Code']] = [function_name, 'query', 'Regex', '']
                    continue
                if 'migrate' in function_name.toLowerCase():
                    results.loc[(to_address, methodId), ['Function', 'Category', 'Reason', 'Code']] = [function_name, 'migrate', 'Regex', '']
                    continue
                if 'shiporder' in function_name.toLowerCase():
                    results.loc[(to_address, methodId), ['Function', 'Category', 'Reason', 'Code']] = [function_name, 'ship order', 'Regex', '']
                    continue
                if 'earlyexit' in function_name.toLowerCase():
                    results.loc[(to_address, methodId), ['Function', 'Category', 'Reason', 'Code']] = [function_name, 'exit early', 'Regex', '']
                    continue
                if 'buycover' in function_name.toLowerCase():
                    results.loc[(to_address, methodId), ['Function', 'Category', 'Reason', 'Code']] = [function_name, 'buy cover', 'Regex', '']
                    continue


            # 加入后处理，将得到的非白名单结果，再次调用gpt进行判断给出置信分


            related_functions = func_analyser.analyze_target_functions_within_contract(all_functions, f"{function_name}")
            if not related_functions:
                results.loc[(to_address, methodId), ['Function', 'Category', 'Reason', 'Code']] = [function_name, pd.NA, pd.NA, pd.NA]
                continue
            print(f"Related functions found for {function_name}: {related_functions}")

            related_functions_content = [next(func['content'] for func in all_functions if func['name'] == name) for name in related_functions]
            contents = '\n'.join(related_functions_content)

            label, reason = fetch_classification(contents, related_functions)
            results.loc[(to_address, methodId), ['Function', 'Category', 'Reason', 'Code']] = [function_name, label, reason, contents]

            # Save the updated DataFrame back to the same Excel file
            try:
                results.to_excel(excel_path, merge_cells=False)
            except Exception as e:
                print(f"Error when trying to save to Excel: {e}")
            time.sleep(0.5)

    print(f"Results updated and saved to {excel_path}")

def fetch_confidence_score(project_name, project_intro, function_name, classification):
    conn = http.client.HTTPSConnection(f'{API_BASE}')
    headers = {
        'Authorization': f'Bearer {API_KEY}',
        'User-Agent': 'Apifox/1.0.0 (https://apifox.com)',
        'Content-Type': 'application/json'
    }

    content = f"""
    Project Name: {project_name}
    Project Introduction: {project_intro}
    Classified Functions: {function_name}
    Classifications: {classification}
    """

    prompt_text = f"""
    You are an engineer skilled in on-chain transaction analysis. 
    Your task is to assign a confidence score to the classification of transaction behavior.
    You will be given a project name, a brief introduction to the project, the function names, and the classification of those functions.You need to provide a confidence score from 1 to 10 for this classification, without decimals.
    """

    format = f"""
    Please format your response as follows:
    'Confidence Score: <score>'    
    """

    data = json.dumps({
        "model": "gpt-4o",
        "messages": [
            {
                "role": "system",
                "content": prompt_text
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

    attempts = 0
    max_attempts = 5
    while attempts < max_attempts:
        try:
            conn.request("POST", "/v1/chat/completions", data, headers)
            res = conn.getresponse()
            response_data = res.read()
            response_json = json.loads(response_data.decode("utf-8"))
            json_string = response_json['choices'][0]['message']['content']
            print(f"Response received successfully: {json_string}")

            # Parse the confidence score correctly from the response string
            match = re.search(r'Confidence Score: (\d+)', json_string)
            if match:
                confidence_score = int(match.group(1))
                return confidence_score
            else:
                print("Failed to find a confidence score in the response.")
                attempts += 1
        except Exception as e:
            attempts += 1
            print(f"Attempt {attempts}: Error while fetching confidence score: {e}")
            if attempts >= max_attempts:
                print("Maximum retry attempts reached.")
                return None
            time.sleep(1)  # Wait for a second before retrying
        finally:
            conn.close()


def main():
    ### 1. Get imple address
    df = pd.read_excel(INPUT_PATH, sheet_name='Sheet1')

    ## Add a new column to store the implementation address
    df['Imple_address'] = None
    df['Info'] = None

    contract_inspector = ContractInspector(config)

    for index, row in df.iterrows():
        # if row['address'] != '0x9960dfe37283a69e43aaba87f91d161694151779':
        #     continue

        imple_address, info = contract_inspector.fetch_chain_implementation(row['chain_id'], row['address'])
        time.sleep(0.5)
        df.at[index, 'Imple_address'] = imple_address
        df.at[index, 'Info'] = info
        print("Handle ", row['chain_id'], row['address'])
        df.to_excel(INPUT_PATH, sheet_name='Sheet1', index=False)


    ### 2. Download contract source code
    for index, row in df.iterrows():
        imple_address = row['Imple_address']
        # print("Unique imple len", len(df['Imple_address']),len(df['Imple_address'].unique()))
        chainId = row['chain_id']
        # if str(chainId) in ['1', '56', '137', '59144', '8453', '42161', '534352', '10', '34443', '43114', '250', '5000']:
        #     continue
        # Check if the implementation address is not None
        if pd.notna(imple_address):
            # Download the source code
            print(f"Downloading source code for {row['address']} on chain {chainId}")
            contract_inspector.download_contract_source(SOURCE_CODE_PATH, imple_address, chainId, f"{row['address']}")


    ### 3. remove comments for all the solidity files already download
    for subdir in os.listdir(SOURCE_CODE_PATH):
        subdir_path = os.path.join(SOURCE_CODE_PATH, subdir)
        if os.path.isdir(subdir_path):
            for ssubdir in os.listdir(subdir_path):
                ssubdir_path = os.path.join(subdir_path, ssubdir)
                if os.path.isdir(ssubdir_path):
                    for file in os.listdir(ssubdir_path):
                        file_path = os.path.join(ssubdir_path, file)
                        if file_path.endswith('.sol'):
                            remove_solidity_comments(file_path, file_path)


    # ### 4. pasring solidity files, extract core functions and using gpt to analyse
    parse_and_classify_solidity_code()

    ### 5. get confidence score for the results from gpt
    for index, row in df.iterrows():
        protocol_name = row['protocol_name']
        project_intro = row['description']
        function_name = row['Function']
        classification = row['Category']
        if pd.isna(classification):
            continue
        # Fetch the confidence score for the classification
        confidence_score = fetch_confidence_score(protocol_name, project_intro, function_name, classification)
        df.at[index, 'Confidence'] = confidence_score
        print(f"Confidence score for {protocol_name}: {confidence_score}")
        time.sleep(0.5)

    # ### 6. Check proxy contract info, determine those cant be analysed
    time.sleep(3)
    for index, row in df.iterrows():
        if row['address'] == row['Imple_address'] and pd.isna(row['Category']):
            chain_id = row['chain_id']
            to_address = row['address']
            print(f"Checking proxy contract for {to_address} on chain {chain_id}")
            if contract_inspector.check_proxy_contract(chain_id, to_address):
                df.at[index, 'Reason'] = "Cant get proxy addr"

    df.to_excel(INPUT_PATH, index=False)


if __name__ == '__main__':
    main()

