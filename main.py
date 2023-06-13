import tkinter as tk
from tkinter import filedialog
from tkinter import ttk
import requests
import json

# VirusTotal API key (replace with your own)
API_KEY = "put your api key within the quotes."

# Function to handle the file scan
def scan_file():
    file_path = filedialog.askopenfilename()

    if file_path:
        url = "https://www.virustotal.com/vtapi/v2/file/scan"
        params = {"apikey": API_KEY}
        files = {"file": (file_path, open(file_path, "rb"))}

        response = requests.post(url, files=files, params=params)

        if response.status_code == 200:
            result_label.config(text="Scan request submitted successfully!")
            report_label.config(state=tk.NORMAL)
            report_label.delete("1.0", tk.END)
            report_label.insert(tk.END, "Scanning file...\n")
            report_label.config(state=tk.DISABLED)

            resource = json.loads(response.content.decode())["resource"]
            retrieve_report(resource)
        else:
            result_label.config(text="Failed to submit scan request.")
    else:
        result_label.config(text="No file selected.")

# Function to retrieve the scan report
def retrieve_report(resource):
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    params = {"apikey": API_KEY, "resource": resource}

    response = requests.get(url, params=params)

    if response.status_code == 200:
        report = json.loads(response.content.decode())
        display_report(report)
    else:
        report_label.config(state=tk.NORMAL)
        report_label.delete("1.0", tk.END)
        report_label.insert(tk.END, "Failed to retrieve scan report.")
        report_label.config(state=tk.DISABLED)

# Function to display the scan report
def display_report(report):
    report_label.config(state=tk.NORMAL)
    report_label.delete("1.0", tk.END)

    positives = report["positives"]
    total = report["total"]
    scan_results = report["scans"]

    report_text = f"Scan Results: {positives}/{total} positive detections\n\n"
    report_text += "Individual Scan Results:\n"

    for scanner, result in scan_results.items():
        report_text += f"{scanner}: {result['result']}\n"

    report_label.insert(tk.END, report_text)
    report_label.config(state=tk.DISABLED)
    report_scrollbar.set(0.0, 0.0)

# Create the main window
window = tk.Tk()
window.title("VirusTotal File Scanner")

# Configure the window's size and background color
window.geometry("400x500")
window.configure(bg="#f0f0f0")

# Create and configure the header label
header_label = tk.Label(window, text="VirusTotal File Scanner", font=("Arial", 18, "bold"), fg="#333333", bg="#f0f0f0")
header_label.pack(pady=20)

# Create and configure the file selection button
file_button = tk.Button(window, text="Select File", font=("Arial", 12), bg="#333333", fg="#ffffff", command=scan_file)
file_button.pack(pady=10)

# Create and configure the result label
result_label = tk.Label(window, text="", font=("Arial", 12), fg="#333333", bg="#f0f0f0")
result_label.pack(pady=10)

# Create the report frame with scrollbar
report_frame = tk.Frame(window, bg="#f0f0f0")
report_frame.pack(pady=20, fill=tk.BOTH, expand=True)

report_label = tk.Text(report_frame, font=("Arial", 12), fg="#333333", bg="#f0f0f0", height=8, width=40, bd=0)
report_label.pack(side=tk.LEFT, fill=tk.BOTH, padx=(0, 10))

report_scrollbar = ttk.Scrollbar(report_frame, orient=tk.VERTICAL, command=report_label.yview)
report_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

report_label.config(yscrollcommand=report_scrollbar.set)
report_label.config(state=tk.DISABLED)

# Center the window on the screen
window.eval('tk::PlaceWindow . center')

# Start the GUI event loop
window.mainloop()
