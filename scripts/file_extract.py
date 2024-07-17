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
    # 用于存储每个sheet处理结果的列表
    results = []
    
    # 遍历每个指定的sheet
    for sheet in sheets:
        # 读取当前sheet的数据
        df = pd.read_excel(input_file, sheet_name=sheet)
        # 筛选is_transfer_simple为"简单"或"复杂"的行，并立即创建一个副本
        filtered_df = df[df['is_transfer_simple'].isin(['简单', '复杂'])].copy()
        
        # 检查列名并根据存在的列设置additional_info列的值
        if 'token_name' in df.columns:
            filtered_df['token'] = filtered_df['token_name']
        elif 'method_name' in df.columns:
            filtered_df['token'] = filtered_df['method_name']
        
        # 选择需要的列
        filtered_df = filtered_df[['contract_address', 'token', 'is_transfer_simple']]
        # 添加到结果列表中
        results.append(filtered_df)
    
    # 合并所有结果
    final_df = pd.concat(results).drop_duplicates(subset='contract_address')
    
    # 保存到新的Excel文件中
    final_df.to_excel('transfer_results.xlsx', index=False)

# 示例调用函数
input_file = './input/gas_fee_online_analysis_week.xlsx'  # 这里替换为你的文件名
sheets = ['transfer_20240701', 'transfer_20240624', 'transfer_20240610', 'transfer_20240603', 'transfer_20240527']  # 替换为你的具体sheet名
process_excel(input_file, sheets)