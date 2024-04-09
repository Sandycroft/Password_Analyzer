from flask import Flask, render_template, request

import re
import requests

app = Flask(__name__)

def check_common_password(password):
    """
    Checks if the password is too common (exists in a list of common passwords).
    You can replace this with your own list or use an online API.
    """
    common_passwords_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt"
    response = requests.get(common_passwords_url)
    if response.status_code == 200:
        common_passwords = response.text.splitlines()
        if password in common_passwords:
            return True
    return False

def check_dictionary_word(password):
    """
    Checks if the password is a dictionary word.
    You can replace this with your own dictionary or use an online API.
    """
    dictionary_url = "https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt"
    response = requests.get(dictionary_url)
    if response.status_code == 200:
        dictionary_words = response.text.splitlines()
        if password.lower() in dictionary_words:
            return True
    return False

def password_analyzer(password):
    # Place special characters between every two letters
    password = re.sub(r'(?<=[a-zA-Z])(?=[a-zA-Z])', '*', password)

    # Check for series of four numbers in order
    sequential_numbers = re.search(r"\d{4}", password)

    # Check length
    length_error = len(password) < 8
    # Check for at least one uppercase letter
    uppercase_error = not re.search(r"[A-Z]", password)
    # Check for at least one lowercase letter
    lowercase_error = not re.search(r"[a-z]", password)
    # Check for at least one digit
    digit_error = not re.search(r"\d", password)
    # Check for at least one special character
    special_error = not re.search(r"[\W_]", password)
    
    errors = []
    
    if length_error:
        errors.append("Password should be at least 8 characters.")
    if uppercase_error:
        errors.append("Password should contain at least one uppercase letter.")
    if lowercase_error:
        errors.append("Password should contain at least one lowercase letter.")
    if digit_error:
        errors.append("Password should contain at least one digit.")
    if special_error:
        errors.append("Password should contain at least one special character (!@#$%^&*(),.?\":{}|<>)")
    if sequential_numbers:
        errors.append("Avoid using a series of four numbers in order (e.g., 1234, 5678).")

    common_password = check_common_password(password)
    if common_password:
        errors.append("Password is too common. Please choose a less common password.")
    
    dictionary_word = check_dictionary_word(password)
    if dictionary_word:
        errors.append("Password should not be a dictionary word.")
    
    suggestions = []
    if len(password) >= 4 and len(password) <= 10:
        suggestions.append("Consider using a longer password.")
    if not uppercase_error and not lowercase_error:
        suggestions.append("Mix uppercase and lowercase letters.")
    if not digit_error:
        suggestions.append("Include numbers in your password.")
    if not special_error:
        suggestions.append("Add special characters like !@#$%^&*(),.?\":{}|<>")
    if not sequential_numbers:
        suggestions.append("Avoid using a series of four numbers in order.")
    
    if errors:
        # Provide a minimum of 10 suggestions for weak passwords
        if len(errors) > 1:
            suggestions.extend([
                "Avoid using easily guessable information (e.g., birthdates, names).",
                "Avoid repeating characters or sequences (e.g., aaa, 123).",
                "Use a passphrase instead of a single word.",
                "Include a mix of letters, numbers, and special characters.",
                "Change your password regularly for added security."
            ])
        return False, errors, suggestions[:10]
    else:
        return True, ["Password is strong."], suggestions

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        password = request.form['password']
        is_strong, messages, suggestions = password_analyzer(password)
        return render_template('result.html', is_strong=is_strong, messages=messages, suggestions=suggestions)
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
