import requests
import tkinter as tk
from tkinter.ttk import * #themed tkinter
from tkinter import *
from tkinter import messagebox
from urllib.parse import urlparse

def run_tests():
    target_url = url_entry.get()
    if len(target_url)<3:
        messagebox.showinfo("Invalid URL!",f" please insert a valid URL.")
    if not target_url.startswith("https://" or "http://"):
        messagebox.showinfo("Invalid URL!", f" Please insert a valid URL.\n https:// or www is missing.")
    else:
        # Define payloads and actions
        payloads = ["<script>alert('XSS')</script>",
                    "<img src='#' onerror='alert(\"XSS\")'>",
                    '<script>window.location.href="https://www.google.com"</script>',
                    ]
        sql_payloads = [
            "' OR 1=1 --",
            "'; DROP TABLE users --",
            "=(select(0)from(select(sleep(5)))v)"
                        ]
        actions = [ {"url": "/change_password", "method": "POST"},
                    {"url": "/update_email", "method": "POST"},
                 ]#csrf_vulnerability

        # Initialize flag
        flag = 0

        import time
        progress['value'] = 20
        root.update_idletasks()
        time.sleep(1)

        known_suspicious_domains = ['.tk', '.ml', '.ga', '.cf', '.gq', '.to',
                                    '000webhostapp.com', '.cz', '.ie', '.ac']
        parsed_url = urlparse(target_url)
        domain = parsed_url.netloc
        for suspicious_domain in known_suspicious_domains:
            if suspicious_domain in domain:
                flag=1

        progress['value'] = 40
        root.update_idletasks()
        time.sleep(1)

        blacklist = ['https://malicious.com', 'http://evil.org', 'http://subtitleseeker.com',
                     'http://financereports.co', 'http://tryteens.com', 'http://subtitleseekerxyz.com', 'http://ffupdate.org','http://cek.ac.in/',
                     'http://iranact.co', 'http://creativebookmark.com', 'http://ffupdate.org', 'http://vegweb.com','https://cek.ac.in/', 'http://vegweb.com', 'http://delgets.com','cek.ac.in/', 'http://totalpad.com']
        for bl in blacklist:
            if target_url == bl:
                flag=1
        progress['value'] = 50
        root.update_idletasks()
        time.sleep(1)

        if flag==0:
            # Iterate through payloads and actions, performing tests
            for payload in payloads:
                # Send a GET request with the payload
                response = requests.get(target_url + "?input=" + payload)
                # Check if the payload is reflected in the response
                if payload in response.text:
                    flag=1
                else:
                    flag=0

            progress['value'] = 60
            root.update_idletasks()
            time.sleep(1)

            for sql_payload in sql_payloads:
                # Send a GET request with the payload
                response = requests.get(target_url + "?username=" + sql_payload + "&password=test")

                # Check if the response indicates a successful SQL injection
                if "Login successful" in response.text:
                    flag=1
                else:
                    flag = 0
            # for action in actions:
            # Create a session to maintain cookies
            session = requests.Session()
            # Iterate through the actions and send requests
            for action in actions:
                url = target_url + action["url"]
                method = action["method"]

                # Prepare the request headers and data
                headers = {
                    "User-Agent": "Google Chrome",
                }

                # Send the request
                if method == "GET":
                    response = session.get(url, headers=headers)
                elif method == "POST":
                    data = {"param1": "value1", "param2": "value2"}  # Modify as needed
                    response = session.post(url, data=data, headers=headers)

                # Check if the response indicates a potential CSRF issue (e.g., unauthorized action)
                if "Unauthorized" in response.text:
                    flag=1
                else:
                    flag= 0

        progress['value'] = 80
        root.update_idletasks()
        time.sleep(1)
        progress['value'] = 100

        # Show results using message boxes
        if flag==1:
            messagebox.showwarning(f"NOT SECURED!", f"This site is vulnerable!\nYour Data might be at risk!")
        if flag==0:
            messagebox.showinfo("XSS results", "No XSS vulnerabilities were found!")
            messagebox.showinfo("SQL Injection Results", "No SQL Injection vulnerabilities were found!")
            messagebox.showinfo("CSRF Results", "No CSRF vulnerabilities were found!")


# Create the GUI window
root = tk.Tk()
root.title("Security Testing Tool")
root.geometry("350x150")
#Disable the resizable Property
root.resizable(False, False)
#Adding image icon
photo = PhotoImage(file="cs.png")
root.iconphoto(False, photo)
# Create and place GUI elements
url_label = tk.Label(root, text="Enter the URL:",width=50,font="calibri 10 bold")
url_label.pack()
url_entry = tk.Entry(root, width=50)
url_entry.pack()
url_label=tk.Label(root, text="Progress:",width=40,font="calibri 10 bold",anchor="w")
url_label.pack()
progress = Progressbar(root, orient=HORIZONTAL,length=300, mode='determinate')
progress.pack(pady=10)

test_button = tk.Button(root, text="Run Tests", command=run_tests, cursor='hand2',
                        font=('calibri', 10, 'bold'),height=2,width= 10,borderwidth=1, relief='ridge')
test_button.bind("<Enter>", func=lambda e: test_button.config(foreground="red"))
# background color on leaving widget
test_button.bind("<Leave>", func=lambda e: test_button.config(foreground="black"))
test_button.pack()

# Start the GUI main loop
root.mainloop()
