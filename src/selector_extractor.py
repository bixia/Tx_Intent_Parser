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

class SelectorExtractor:
    def __init__(self):
        pass

    # Scan the source code file to find the signature which matches the methodId
    def search_signature_from_id(self, source_code_file, parsing_result, methodId):
        with open(source_code_file, 'r') as file:
            source_code = file.read()
        print(f"Searching signature for {methodId}")
        for func in parsing_result:
            origin_sig = self._extract_sig(func['content'])
            print("origin sig: ", origin_sig)
            if origin_sig:
                selectors = self._calculate_selector_from_sig(origin_sig, source_code)
                if methodId in selectors:  
                    print("search sig from id: ", origin_sig, methodId)
                    return origin_sig.split('(')[0]
        
        return None

    # flatten the struct type to basic types
    def _flatten_struct(self, arg_type, structs, parent_name=""):
        is_array = arg_type.endswith('[]')
        if is_array:
            arg_type = arg_type[:-2]  # Remove the array suffix to handle the element type

        if arg_type == "address payable":
            arg_type = "address"

        if arg_type not in structs:
            # Handle basic types and non-struct types
            basic_type = (arg_type, parent_name.strip())
            return [(basic_type[0] + '[]', basic_type[1]) if is_array else basic_type]

        # Handle struct types
        fields = structs[arg_type]
        result = []
        field_results = []
        for field_name, field_type in fields.items():
            full_field_name = f"{parent_name} {field_name}".strip()

            if field_type == "address payable":
                field_type = "address"

            expanded_fields = self._flatten_struct(field_type, structs, full_field_name)
            field_results.extend(expanded_fields)
        
        # Combine all fields into a single tuple to represent the struct
        field_types = [ftype for ftype, _ in field_results]
        struct_representation = ','.join(field_types)
        complete_struct_representation = f"({struct_representation})"  # Encapsulate struct representation in parenthesis
        if is_array:
            complete_struct_representation += '[]'  # Append '[]' if it's an array

        return [(complete_struct_representation, parent_name.strip())]

    # replace the struct type with basic types
    def _replace_structs_interfaces_and_enums_in_signature(self, signature, structs, interfaces, enums):
        parts = signature.split('(')
        func_name = parts[0].strip()
        args = parts[1][:-1]  # Remove the closing parenthesis
        arg_list = [arg.strip() for arg in args.split(',') if arg.strip()]
        print(f"Arg list: {arg_list}")
        all_combinations = [[]]

        for arg in arg_list:
            is_array = arg.endswith('[]')
            arg_type = arg[:-2] if is_array else arg
            new_combinations = []
            print(f"Arg type: {arg_type}")
            # deal with the case where same struct for different definition
            matching_structs = [s for s in structs if s['name'] == arg_type]
            if matching_structs:
                print("macting_structs:", matching_structs)
                for struct in matching_structs:
                    flattened_fields = self._flatten_struct(arg_type, {struct['name']:struct['fields']}, "")
                    # print("flattened_fields:", flattened_fields)
                    replaced_arg = ','.join(f"{ftype} {fname}" for ftype, fname in flattened_fields)
                    if is_array:
                        replaced_arg += '[]'
                    for combination in all_combinations:
                        new_combinations.append(combination + [replaced_arg])
            elif arg_type in interfaces or arg_type in enums:
                replacement = ("address[]" if arg_type in interfaces else "uint8[]") if is_array else ("address" if arg_type in interfaces else "uint8")
                for combination in all_combinations:
                    new_combinations.append(combination + [replacement])
            else:
                for combination in all_combinations:
                    new_combinations.append(combination + [arg_type if not is_array else arg_type + '[]'])

            all_combinations = new_combinations

        return [f"{func_name}({', '.join(args)})" for args in all_combinations]

    # parse the struct, interface, enum and type from the source code
    def _parse_structs_interfaces_and_enums(self, source_code):
        struct_pattern = r"struct\s+(\w+)\s*{([^}]+)}"
        interface_pattern = r"(?:interface|contract|abstract\s+contract)\s+(\w+)(?:\s+is\s+(\w+(?:,\s*\w+)*))?\s*{"
        enum_pattern = r"enum\s+(\w+)\s*{([^}]+)}"
        type_pattern = r"type\s+(\w+)\s+is\s+(\w+);"
        
        structs = []
        interfaces = []
        enums = []
        types = {}

        # Parse structs
        matches = re.finditer(struct_pattern, source_code, re.MULTILINE)
        for match in matches:
            struct_name = match.group(1)
            fields = match.group(2).strip()
            field_pattern = r"(\w[\w\s\[\]]*)\s+(\w+);"
            fields_dict = {field_name.strip(): field_type.strip() for field_type, field_name in re.findall(field_pattern, fields)}
            structs.append({'name': struct_name, 'fields': fields_dict})

        # Parse interfaces, contracts, and abstract contracts
        matches = re.finditer(interface_pattern, source_code, re.MULTILINE)
        for match in matches:
            interface_name = match.group(1)
            interfaces.append(interface_name.strip())

        # Parse enums
        matches = re.finditer(enum_pattern, source_code, re.MULTILINE)
        for match in matches:
            enum_name = match.group(1)
            enums.append(enum_name.strip())

        # Parse type aliases
        matches = re.finditer(type_pattern, source_code, re.MULTILINE)
        for match in matches:
            type_name = match.group(1)
            base_type = match.group(2)
            types[type_name.strip()] = base_type.strip()

        return structs, interfaces, enums, types

    def _calculate_selector(self, signature):
        formatted_signature = signature.replace(" ", "")  # Remove all spaces
        selector = Web3.keccak(text=formatted_signature)[:4].hex()
        print(f"Calculating selector for signature: {formatted_signature} {selector}")
        return selector

    def _calculate_selector_from_sig(self, origin_signature, source_code):
        origin_signature = re.sub(r"\buint\b", "uint256", origin_signature)

        structs, interfaces, enums, types = self._parse_structs_interfaces_and_enums(source_code)

        signatures_with_basic_types = self._replace_structs_interfaces_and_enums_in_signature(origin_signature, structs, interfaces, enums)
        
        selectors = []
        for signature in signatures_with_basic_types:
            # Replace "uint" with "uint256" to match the Solidity type
            final_signature = re.sub(r"\buint\b", "uint256", signature)
            
            # Replace enums with "uint8"
            for enum in enums:
                final_signature = re.sub(rf"\b{enum}\b", "uint8", final_signature)
            
            # Replace interfaces with "address"
            for interface in interfaces:
                final_signature = re.sub(rf"\b{interface}\b", "address", final_signature)
            
            # Replace types with their base types
            for type_name, base_type in types.items():
                final_signature = re.sub(rf"\b{type_name}\b", base_type, final_signature)
            
            # Calculate the selector for the final signature
            selector = self._calculate_selector(final_signature)
            selectors.append(selector)
        
        print(f"Final Signatures and Selectors: {selectors}")
        return selectors


    def _extract_sig(self, function_str):
        if 'internal' in function_str or 'private' in function_str:
            return None
        print(f"Function string: {function_str}")

        pattern = r'function (\w+)\(([^)]*)\)'
        match = re.search(pattern, function_str)
        if not match:
            return None

        func_name = match.group(1)
        params = match.group(2).strip()

        if not params:
            signature = f"{func_name}()"
            print(f"Function signature: {signature}")
            return signature

        param_types = []
        # Extract the type of each parameter
        type_pattern = r'\s*(\w+(?:\.\w+)?(?:\s*\[\s*\]\s*)*)(?:\s+memory|\s+storage|\s+calldata)?\s+\w+'
        for param in params.split(','):
            type_match = re.search(type_pattern, param.strip())
            if type_match:
                param_type = type_match.group(1)
                # Extract the last part of the type (after the last dot) if it's a complex type
                if '.' in param_type:
                    param_type = param_type.split('.')[-1]
                param_type = param_type.replace(' ', '')
                param_types.append(param_type)
            else:
                # If the type cannot be extracted, use 'UnknownType' as a placeholder
                param_types.append('UnknownType')

        signature = f"{func_name}({','.join(param_types)})"
        print(f"Function signature: {signature}")
        return signature
