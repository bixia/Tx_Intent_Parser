from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import ElementClickInterceptedException
import time

def safe_click(driver, element):
    # try to scroll to the element and click
    try:
        driver.execute_script("arguments[0].scrollIntoView(true);", element)
        element.click()
    except ElementClickInterceptedException:
        # Use JS to click if element is not clickable
        driver.execute_script("arguments[0].click();", element)

def process_page(driver, url, name):
    save_path = './func_code/'
    file_path = f'{save_path}{name}.fc'
    driver.get(url)
    WebDriverWait(driver, 10).until(
        EC.presence_of_all_elements_located((By.CSS_SELECTOR, 'div[class*="file"], pre > code.language-func.hljs'))
    )

    # Capture the page code
    try:
        code_block = driver.find_element(By.CSS_SELECTOR, 'pre > code.language-func.hljs')
        code_text = code_block.text
        with open(file_path, 'a') as file:
            file.write(f"Page Code for {url}:\n{code_text}\n\n")
        print("Page code captured for:", url)
    except Exception as e:
        print("No direct page code found or no visible code in active tab for:", url)

    # Capture the files code that not present in the page code
    file_entries = driver.find_elements(By.CSS_SELECTOR, 'div[class*="file"]')
    print(f"Total files for {url}: {len(file_entries)}")
    for entry in file_entries:
        try:
            safe_click(driver, entry)
            WebDriverWait(driver, 10).until(
                EC.visibility_of_element_located((By.CSS_SELECTOR, 'pre > code.language-func.hljs'))
            )
            code_block = driver.find_element(By.CSS_SELECTOR, 'pre > code.language-func.hljs')
            code_text = code_block.text

            with open(file_path, 'a') as file:
                file.write(f"File: {entry.text} from {url}\n{code_text}\n\n")
        except Exception as e:
            print(f"Failed to process file {entry.text} from {url}: {str(e)}")


def generate_url(token):
    return f"https://tonviewer.com/{token}?section=code"

def main():

    tokens = [
    'UQCI2sZ8zq25yub6rHEY8FwPqV3zbCqS5oasOdljENCjhxsp',
    # 'UQC1K9u8EafeJCmMBk2WF-_NoYFTuVUi411XzrebbOLqk5Lv',
    # 'UQD6AggIcZP1n3CLDKTkoKChXcW2oCEXazd8FFG0lR7coR15',
    # 'UQDJIAD1elCEHT2tH5WpTteRsTpUX92y0INFY1cvKXWXyO1P',
    # 'UQDC9uOuzMps591jsucsiJe4mGKa4jeKusdnm6S1QemhW2Yj',
    # 'UQAne7vn6Y4ohSv3IP4pEr9FHTJKjtj50IRCY9ga5RMlmdMQ',
    # 'UQDNPoPmbB76ZiksHFa8w28UK-fznkHSb6wV9_Lpq5lpnfwS'
    ]

    driver = webdriver.Chrome()
    try:
        for token in tokens:
            url = generate_url(token)
            process_page(driver, url, token)
            time.sleep(1)
    finally:
        driver.quit()

if __name__ == '__main__':
    main()