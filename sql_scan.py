import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

class SQLInjectionScannerApp:
    def __init__(self, master):
        self.master = master
        master.title("SQL Injection Scanner")

        self.url_label = tk.Label(master, text="Enter URL:")
        self.url_label.pack()

        self.url_entry = tk.Entry(master, width=40)
        self.url_entry.pack()

        self.scan_button = tk.Button(master, text="Scan", command=self.sql_injection_scan)

        self.scan_button.pack()

        self.output_text = scrolledtext.ScrolledText(master, width=60, height=10)
        self.output_text.pack()

    def get_forms(self, url):
        soup = BeautifulSoup(requests.get(url).content, "html.parser")
        return soup.find_all("form")

    def form_details(self, form):
        details_of_form = {}
        action = form.attrs.get("action")
        method = form.attrs.get("method", "get")
        inputs = []

        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value", "")
            inputs.append({
                "type": input_type,
                "name": input_name,
                "value": input_value,
            })

        details_of_form['action'] = action
        details_of_form['method'] = method
        details_of_form['inputs'] = inputs
        return details_of_form

    def vulnerable(self, response):
        errors = {"quoted string not properly terminated",
                  "unclosed quotation mark after the charachter string",
                  "you have an error in you SQL syntax"
                  }
        for error in errors:
            if error in response.content.decode().lower():
                return True
        return False

    def sql_injection_scan(self):
        url_to_be_checked = self.url_entry.get()
        forms = self.get_forms(url_to_be_checked)
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, f"[+] Detected {len(forms)} forms on {url_to_be_checked}.\n")

        for form in forms:
            details = self.form_details(form)

            for i in "\"'":
                data = {}
                for input_tag in details["inputs"]:
                    if input_tag["type"] == "hidden" or input_tag["value"]:
                        data[input_tag['name']] = input_tag["value"] + i
                    elif input_tag["type"] != "submit":
                        data[input_tag['name']] = f"test{i}"

                if details["method"] == "post":
                    res = requests.post(url_to_be_checked, data=data)
                elif details["method"] == "get":
                    res = requests.get(url_to_be_checked, params=data)

                if self.vulnerable(res):
                    self.output_text.insert(tk.END, f"SQL injection attack vulnerability in link: {url_to_be_checked}\n")
                    messagebox.showwarning("Vulnerability Found", "SQL injection attack vulnerability detected!")
                else:
                    self.output_text.insert(tk.END, "No SQL injection attack vulnerability detected\n")
                    messagebox.showinfo("No Vulnerability", "No SQL injection attack vulnerability detected.")

if __name__ == "__main__":
    root = tk.Tk()
    app = SQLInjectionScannerApp(root)
    root.mainloop()
