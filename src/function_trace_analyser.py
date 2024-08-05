import re
import os, sys
import numpy as np
import requests
import pandas as pd
import json
from project_parser import parse_project
from tqdm import tqdm
from dotenv import load_dotenv

load_dotenv()   # Load environment variables

class TraceAnalyser:
    def __init__(self):
        pass

    def analyze_target_functions(self, all_functions, function_name):
        # analyze all functions called by the approve functions
        approve_functions = [func for func in all_functions if func['name'].endswith(f'.{function_name}')]
        call_graph = self._build_call_graph(all_functions)
        all_related_functions = []

        for approve_func in approve_functions:
            related_functions = self._collect_all_called_functions(approve_func['name'], call_graph)
            all_related_functions.extend(related_functions)

        return all_related_functions

    def analyze_target_functions_within_contract(self, all_functions, function_name):
        # analyze all functions called by the approve functions
        approve_functions = [func for func in all_functions if func['name'].endswith(f'.{function_name}') or func['name'].endswith(f'._{function_name}')]
        call_graph = self._build_call_graph_within_contract(all_functions)
        all_related_functions = []

        for approve_func in approve_functions:
            related_functions = self._collect_all_called_functions(approve_func['name'], call_graph)
            all_related_functions.extend(related_functions)

        return all_related_functions

    def _extract_function_calls(self, content):
        # extract function calls from the content
        pattern = re.compile(r'\b(\w+)\s*\(') 
        return pattern.findall(content)

    def _build_call_graph(self, all_functions):
        # build a call graph from all functions
        call_graph = {}
        names_to_functions = {func['name']: func for func in all_functions}  
        for func in all_functions:
            calls = self._extract_function_calls(func['content'])
            qualified_calls = []
            for call in calls:
                # for each call, check if it is a function in the project
                qualified_calls.extend([name for name in names_to_functions if name.endswith(f".{call}")])
            call_graph[func['name']] = qualified_calls
        return call_graph

    def _build_call_graph_within_contract(self, all_functions):
        # build a call graph from all functions in the same contract
        call_graph = {}
        names_to_functions = {func['name']: func for func in all_functions}  
        for func in all_functions:
            calls = self._extract_function_calls(func['content'])
            contract_name = func['name'].split('.')[0]
            qualified_calls = []
            for call in calls:
                # for each call, check if it is a function in the project
                qualified_calls.extend([name for name in names_to_functions if (name.endswith(f".{call}") and name.startswith(contract_name))])
            call_graph[func['name']] = qualified_calls
        return call_graph   

    def _collect_all_called_functions(self, function_name, call_graph, visited=None):
        # collect all functions called by the given function in order
        if visited is None:
            visited = set()
            
        ordered_functions = []
        
        if function_name in visited:
            return ordered_functions

        visited.add(function_name)
        ordered_functions.append(function_name)
        for called_function in call_graph.get(function_name, []):
            ordered_functions.extend(self._collect_all_called_functions(called_function, call_graph, visited))
            
        return ordered_functions


def main():
    analyser = TraceAnalyser()
    all_functions, _ = parse_project('./data/code/1/0x1b70Ff1e5152FDb8425A2B84b098DF2F9C1DF54E')
    res = analyser.analyze_target_functions_within_contract(all_functions, "bridgeTo")
    print(res)

if __name__ == "__main__":
    main()


