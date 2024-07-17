import os, sys
import re
import pickle
import numpy as np
import requests
import pandas as pd
from pathlib import Path
from tqdm import tqdm
from dotenv import load_dotenv
from web3 import Web3
from Crypto.Hash import keccak

def flatten_struct(arg_type, structs, parent_name=""):
    # Base case: if the type is not a struct, just return it as is
    if arg_type not in structs:
        return [(arg_type, parent_name.strip())]

    # Recursive case: expand the struct into its basic types
    fields = structs[arg_type]
    result = []
    for field_name, field_type in fields.items():
        full_field_name = f"{parent_name} {field_name}".strip()
        expanded_fields = flatten_struct(field_type, structs, full_field_name)
        result.extend(expanded_fields)
    return result

# def replace_structs_in_signature(signature, structs):
#     parts = signature.split('(')
#     func_name = parts[0].strip()
#     args = parts[1][:-1]  # Remove the closing parenthesis
#     arg_list = args.split(',')
#     replaced_args = []

#     for arg in arg_list:
#         arg_type = arg.strip()
#         # Flatten the struct to get all basic type fields
#         flattened_fields = flatten_struct(arg_type, structs, "")
#         # Extend the signature with type of each field only, names are not included in selector calculation
#         replaced_args.extend(ftype for ftype, fname in flattened_fields)

#     new_signature = f"{func_name}({','.join(replaced_args)})"
#     return new_signature

def replace_structs_in_signature(signature, structs):
    parts = signature.split('(')
    func_name = parts[0].strip()
    args = parts[1][:-1]  # Remove the closing parenthesis
    arg_list = args.split(',')
    replaced_args = []

    for arg in arg_list:
        arg_type = arg.strip()
        # Flatten the struct to get all basic type fields
        flattened_fields = flatten_struct(arg_type, structs, "")

        if arg_type in structs:
            # If it's a struct, group the types within parentheses
            type_list = (ftype for ftype, fname in flattened_fields)
            replaced_args.append(f"({','.join(type_list)})")
        else:
            # For non-struct types, just add the type
            replaced_args.extend(ftype for ftype, fname in flattened_fields)

    new_signature = f"{func_name}({', '.join(replaced_args)})"
    # Remove any extra spaces and commas
    new_signature = new_signature.replace(" ", "").replace(",)", ")")
    return new_signature

def parse_structs(source_code):
    struct_pattern = r"struct\s+(\w+)\s*{([^}]+)}"
    structs = {}
    matches = re.finditer(struct_pattern, source_code, re.MULTILINE)
    for match in matches:
        struct_name = match.group(1)
        fields = match.group(2).strip()
        field_pattern = r"(\w[\w\s\[\]]*)\s+(\w+);"
        fields_dict = {field_name.strip(): field_type.strip() for field_type, field_name in re.findall(field_pattern, fields)}
        structs[struct_name] = fields_dict
    return structs

def calculate_selector(signature):
    # print(f"Calculating selector for signature: {signature}")
    return Web3.keccak(text=signature)[:4].hex()

def compute_selector(function_str):
    pattern = r'function (\w+)\(([^)]*)\)'
    match = re.search(pattern, function_str)
    if not match:
        return None

    func_name = match.group(1)
    params = match.group(2)

    param_types = []
    for param in params.split(','):
        # extract the type
        type_match = re.match(r'\s*(\w+)', param.strip())
        if type_match:
            param_types.append(type_match.group(1))
    
    # create the function signature
    signature = f"{func_name}({','.join(param_types)})"
    print(f"Function signature: {signature}")
    # calculate the selector
    k = keccak.new(digest_bits=256)
    k.update(signature.encode())
    hash_bytes = k.digest()

    # return the first 4 bytes of the hash as the selector
    return hash_bytes[:4].hex()

def calculate_selector_from_sig(origin_signature, source_code):
    structs = parse_structs(source_code)
    signature_with_basic_types = replace_structs_in_signature(origin_signature, structs)
    return calculate_selector(signature_with_basic_types)

def extract_sig(function_str):
    if 'internal' in function_str or 'private' in function_str:
        return None

    # extract function name and parameters
    pattern = r'function (\w+)\(([^)]*)\)'
    match = re.search(pattern, function_str)
    if not match:
        return None

    func_name = match.group(1)
    params = match.group(2)

    # Only save the params type
    param_types = []
    for param in params.split(','):
        type_match = re.match(r'\s*(\w+)', param.strip())
        if type_match:
            param_types.append(type_match.group(1))
    
    signature = f"{func_name}({','.join(param_types)})"
    return signature

def main():
    #Test use
    file_path = './data/code/1/0x0a32372381ea32a441d46553f879e4de7027b011/0x0a32372381ea32a441d46553f879e4de7027b011.sol'

    with open(file_path, 'r') as file:
        solidity_code = file.read()
        
    # print(parse_structs(solidity_code))

    signature = "claim(address,TokenClaim)"

    res = calculate_selector_from_sig(signature, solidity_code)

    print("Function Selector:", res)
    
if __name__ == '__main__':
    main()