original_text = """

"""

# Use repr() to encode the text
encoded_text = repr(original_text)

with open('encoded_text.txt', 'w') as file:
    # Remove the quotes at the beginning and end of the encoded text
    file.write(encoded_text[1:-1])

print("Encoded text has been written to 'encoded_text.txt'")
