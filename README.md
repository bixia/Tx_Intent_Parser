# Tx-Intent-parser

## Notice

This project is designed to assist in determining the intent of transactions. The input is the contract address and the method ID used during the interaction, and the output is the likely category of this interaction. The main focus is on the `data` and `src` directories. 


### data
1. Excel spreadsheets to be processed
2. Contract source code pulled from various blockchains
3. List of contract functions parsed into a specific format


### src
1. 'project_parser' is used to parse all the functions within the contract and output them in a specific manner
2. 'function_trace_analyser' is used to analyse and filter out the call trace when calling a specific function
3. 'selector_extractor' is used to analyses all the function in the contract and found out whose signature matches the method ID
4. 'contract_inspector' contains all the process to deal with api to get necessary info
5. 'tx_intent_judge' contains the core workflow





