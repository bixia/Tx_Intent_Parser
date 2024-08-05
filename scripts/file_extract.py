import pandas as pd

# def extract_and_deduplicate_addresses(input_file, output_file):
#     # read the Excel file
#     xls = pd.ExcelFile(input_file)
#     all_addresses = set()  # remove duplicates

#     # scan all sheets
#     for sheet_name in xls.sheet_names:
#         df = pd.read_excel(xls, sheet_name=sheet_name)
#         if 'contract_address' in df.columns:
#             print(f"Found {len(df['contract_address'].dropna().unique())} unique contract addresses in {sheet_name}")
#             all_addresses.update(df['contract_address'].dropna().unique())

#     # convert the set to a DataFrame
#     unique_addresses_df = pd.DataFrame(list(all_addresses), columns=['Unique Contract Addresses'])

#     unique_addresses_df.to_excel(output_file, index=False)

# # Usage
# input_file = './input/gas_fee_online_analysis_week.xlsx'  
# output_file = 'addresses_all.xlsx'  
# extract_and_deduplicate_addresses(input_file, output_file)


def process_excel(input_file, sheets):
    # Save the results
    results = []
    
    # Scan all sheets
    for sheet in sheets:
        df = pd.read_excel(input_file, sheet_name=sheet)
        # filter out rows that are not '简单' or '复杂'
        filtered_df = df[df['is_transfer_simple'].isin(['简单', '复杂'])].copy()
        
        # check if the column name is 'token_name' or 'method_name'
        if 'token_name' in df.columns:
            filtered_df['token'] = filtered_df['token_name']
        elif 'method_name' in df.columns:
            filtered_df['token'] = filtered_df['method_name']
        
        filtered_df = filtered_df[['contract_address', 'token', 'is_transfer_simple']]
        results.append(filtered_df)
    
    # Merge all results
    final_df = pd.concat(results).drop_duplicates(subset='contract_address')

    final_df.to_excel('transfer_results.xlsx', index=False)

input_file = './input/gas_fee_online_analysis_week.xlsx'  
sheets = ['transfer_20240701', 'transfer_20240624', 'transfer_20240610', 'transfer_20240603', 'transfer_20240527'] 
process_excel(input_file, sheets)