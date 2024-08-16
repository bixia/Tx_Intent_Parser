# main_execution.py

import pandas as pd
from concurrent.futures import ThreadPoolExecutor

from tx_intent_judge import handle_implementation, handle_sourcecode, handle_classification, handle_confidence_score, handle_proxy_contracts_check


def update_implementation_addresses(df, filepath):
    df['Imple_address'] = None
    df['Info'] = None
    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(handle_implementation, chain_id, group, df) for chain_id, group in df.groupby('chain_id')]
        for future in futures:
            future.result()
    df.to_excel(filepath, sheet_name='Sheet1', index=False)

def download_sources(df, filepath):
    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(handle_sourcecode, chain_id, group) for chain_id, group in df.groupby('chain_id')]
        for future in futures:
            future.result()

def process_all_data(df, filepath):
    handle_classification(df, filepath)

def update_confidence_scores(df, filepath):
    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(handle_confidence_score, chain_id, group, df) for chain_id, group in df.groupby('chain_id')]
        for future in futures:
            result = future.result()
    df.to_excel(filepath, sheet_name='Sheet1', index=False)

def check_proxy_contracts(df, filepath):
    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(handle_proxy_contracts_check, chain_id, group, df) for chain_id, group in df.groupby('chain_id')]
        for future in futures:
            result = future.result()
    df.to_excel(filepath, sheet_name='Sheet1', index=False)

def main():
    filepath = './data/source/label_vault_20240731的副本 copy.xlsx'
    df = pd.read_excel(filepath, sheet_name='Sheet1')
    df['Imple_address'] = None
    df['Info'] = None

    update_implementation_addresses(df, filepath)
    print("update_implementation_addresses done")

    download_sources(df, filepath)
    print("download_sources done")

    process_all_data(df, filepath)
    print("process_all_data done")

    update_confidence_scores(df, filepath)
    print("update_confidence_scores done")

    check_proxy_contracts(df, filepath)
    print("check_proxy_contracts done")

if __name__ == '__main__':
    main()
