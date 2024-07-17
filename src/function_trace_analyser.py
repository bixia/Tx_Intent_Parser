import re
import os, sys
import numpy as np
import requests
import pandas as pd
import json
import time
from pathlib import Path
from sklearn.metrics.pairwise import cosine_similarity
from project_parser import parse_project
from tqdm import tqdm
from dotenv import load_dotenv

load_dotenv()   # Load environment variables

def extract_function_calls(content):
    # extract function calls from the content
    pattern = re.compile(r'\b(\w+)\s*\(')
    return pattern.findall(content)

def build_call_graph(all_functions):
    # build a call graph from all functions
    call_graph = {}
    names_to_functions = {func['name']: func for func in all_functions}  
    for func in all_functions:
        calls = extract_function_calls(func['content'])
        qualified_calls = []
        for call in calls:
            # for each call, check if it is a function in the project
            qualified_calls.extend([name for name in names_to_functions if name.endswith(f".{call}")])
        call_graph[func['name']] = qualified_calls
    return call_graph

def build_call_graph_within_contract(all_functions):
    # build a call graph from all functions in the same contract
    call_graph = {}
    names_to_functions = {func['name']: func for func in all_functions}  
    for func in all_functions:
        calls = extract_function_calls(func['content'])
        contract_name = func['name'].split('.')[0]
        qualified_calls = []
        for call in calls:
            # for each call, check if it is a function in the project
            qualified_calls.extend([name for name in names_to_functions if (name.endswith(f".{call}") and name.startswith(contract_name))])
        call_graph[func['name']] = qualified_calls
    return call_graph    

def collect_all_called_functions(function_name, call_graph, visited=None):
    # collect all functions called by the given function
    if visited is None:
        visited = set()

    if function_name in visited:
        return visited

    visited.add(function_name)
    for called_function in call_graph.get(function_name, []):
        collect_all_called_functions(called_function, call_graph, visited)
    return visited

def analyze_target_functions(all_functions, function_name):
    # analyze all functions called by the approve functions
    approve_functions = [func for func in all_functions if func['name'].endswith(f'.{function_name}')]
    call_graph = build_call_graph(all_functions)
    all_related_functions = set()

    for approve_func in approve_functions:
        related_functions = collect_all_called_functions(approve_func['name'], call_graph)
        all_related_functions.update(related_functions)

    return all_related_functions

def analyze_target_functions_within_contract(all_functions, function_name):
    # analyze all functions called by the approve functions
    approve_functions = [func for func in all_functions if func['name'].endswith(f'.{function_name}')]
    call_graph = build_call_graph_within_contract(all_functions)
    all_related_functions = set()

    for approve_func in approve_functions:
        related_functions = collect_all_called_functions(approve_func['name'], call_graph)
        all_related_functions.update(related_functions)

    return all_related_functions

def main():
    all_functions, _ = parse_project('./data/code/1/0x0a32372381ea32a441d46553f879e4de7027b011')
    res = analyze_target_functions(all_functions, "claim")
    print(res)

if __name__ == "__main__":
    main()


