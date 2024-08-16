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
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
from contract_inspector import ContractInspector
from selector_extractor import SelectorExtractor
from function_trace_analyser import TraceAnalyser

load_dotenv()   # Load environment variables

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


# Main logic where the source code is parsed then analyzed using OpenAI API
def parse_and_classify_solidity_code(chain_id, method_id, to_address, address_path, results_df):
    selector_extractor = SelectorExtractor()
    func_analyser = TraceAnalyser()

    print(f"Processing {to_address} with methodId: {method_id} on chain {chain_id}")
    
    if not os.path.isdir(address_path):
        return results_df

    # parse the project and get all functions
    all_functions, _ = parse_project(address_path)

    # Save the functions to a file for future reference
    intermediate_path = os.path.join(PARSING_RESULT_PATH, str(chain_id), f"{to_address}.txt")
    os.makedirs(os.path.dirname(intermediate_path), exist_ok=True)
    with open(intermediate_path, 'w') as f:
        for func in all_functions:
            f.write(str(func) + '\n')

    # get the function name from the methodId
    function_name = get_signature_from_id(method_id)
    if not function_name or not any(function_name in func['name'] for func in all_functions):
        source_code_path = os.path.join(address_path, f"{to_address}.sol")
        if not os.path.exists(source_code_path):
            return {'address': to_address, 'method_id': method_id, 'Function': pd.NA, 'Category': pd.NA, 'Reason': pd.NA, 'Code': pd.NA}
        function_name = selector_extractor.search_signature_from_id(source_code_path, all_functions, method_id)
        if not function_name:
            return {'address': to_address, 'method_id': method_id, 'Function': pd.NA, 'Category': pd.NA, 'Reason': pd.NA, 'Code': pd.NA}
    
    function_name_lower = function_name.lower()
    categories = {
        'unwrap': 'unwrap',
        'wrap': 'wrap',
        'exitmarket': 'exit market',
        'entermarket': 'enter market',
        'farming': 'farming',
        'query': 'query',
        'migrate': 'migrate',
        'shiporder': 'ship order',
        'earlyexit': 'exit early',
        'buycover': 'buy cover'
    }
    
    for key, value in categories.items():
        if key in function_name_lower:
            return {'address': to_address, 'method_id': method_id, 'Function': function_name, 'Category': value, 'Reason': 'Regex', 'Code': ''}
    
    related_functions = func_analyser.analyze_target_functions_within_contract(all_functions, f"{function_name}")
    if not related_functions:
        return {'address': to_address, 'method_id': method_id, 'Function': function_name, 'Category': pd.NA, 'Reason': pd.NA, 'Code': pd.NA}

    related_functions_content = [next(func['content'] for func in all_functions if func['name'] == name) for name in related_functions]
    contents = '\n'.join(related_functions_content)

    label, reason = fetch_classification(contents, related_functions)
    return {'address': to_address, 'method_id': method_id, 'Function': function_name, 'Category': label, 'Reason': reason, 'Code': contents}

# Do the preprocessing and classification for each chain
def process_and_classify(chain_id, base_path, results_df):
    chain_id_path = os.path.join(base_path, chain_id)
    updated_rows = []
    if not os.path.isdir(chain_id_path):
        return updated_rows

    filtered_data = results_df[(results_df['chain_id'] == int(chain_id)) & (results_df['Imple_address'].notna())]
    for (to_address, method_id), row in filtered_data.iterrows():
        if pd.isna(method_id) or pd.isna(to_address):
            continue

        address_path = os.path.join(chain_id_path, to_address)
        updated_row = parse_and_classify_solidity_code(chain_id, method_id, to_address, address_path, row)
        if updated_row is not None:
            updated_rows.append(updated_row)
    
    return updated_rows


# Task 1
def handle_implementation(chain_id, group_df, df):
    contract_inspector = ContractInspector(config)
    try:
        for index, row in group_df.iterrows():
            imple_address, info = contract_inspector.fetch_chain_implementation(chain_id, row['address'])
            time.sleep(0.5)
            df.at[index, 'Imple_address'] = imple_address
            df.at[index, 'Info'] = info
            print(f"Handled {chain_id}, {row['address']}")
    except Exception as e:
        print(f"Error processing chain {chain_id}: {e}")

# Task 2
def handle_sourcecode(chain_id, group_df):
    contract_inspector = ContractInspector(config)
    for index, row in group_df.iterrows():
        imple_address = row['Imple_address']
        if pd.notna(imple_address):
            print(f"Downloading source code for {row['address']} on chain {chain_id}")
            try:
                contract_inspector.download_contract_source(SOURCE_CODE_PATH, imple_address, chain_id, f"{row['address']}")
            except Exception as e:
                print(f"Error downloading source code for {row['address']} on chain {chain_id}: {e}")

# Task 3
def handle_classification(df, filepath):
    base_path = SOURCE_CODE_PATH
    # Ensure the DataFrame contains the necessary columns
    if 'address' not in df.columns or 'method_id' not in df.columns:
        raise ValueError("DataFrame must contain 'address' and 'method_id' columns.")
    df.set_index(['address', 'method_id'], inplace=True)

    all_updates = []
    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(process_and_classify, chain_id, base_path, df.copy()) for chain_id in os.listdir(base_path) if os.path.isdir(os.path.join(base_path, chain_id))]
        for future in futures:
            all_updates.extend(future.result())

    for update in all_updates:
        if update:
            # Update the DataFrame with the new values
            update_keys = [k for k in update.keys() if k not in ['address', 'method_id']]
            df.loc[(update['address'], update['method_id']), update_keys] = [update[k] for k in update_keys]

    try:
        df.to_excel(filepath, index=True, merge_cells=False)  
        print(f"Results updated and saved to {filepath}")
        # Reset the index after saving
        df.reset_index(inplace=True)
    except Exception as e:
        print(f"Error when trying to save to Excel: {e}")

# Task 4
def handle_confidence_score(chain_id, group_df, df):
    try:
        for index, row in group_df.iterrows():
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
    except Exception as e:
        print(f"Error processing chain {chain_id}: {e}")

# Task 5
def handle_proxy_contracts_check(chain_id, group_df, df):
    contract_inspector = ContractInspector(config)
    try:
        for index, row in group_df.iterrows():
            if row['address'] == row['Imple_address'] and pd.isna(row['Category']):
                to_address = row['address']
                print(f"Checking proxy contract for {to_address} on chain {chain_id}")
                # Check if the implementation address is a proxy contract and not able to get the imple address
                if contract_inspector.check_proxy_contract(chain_id, to_address):
                    df.at[index, 'Reason'] = "Can't get proxy addr"
    except Exception as e:
        print(f"Error processing chain {chain_id} when check proxy contracts: {e}")

