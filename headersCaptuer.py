import tkinter as tk
from tkinter import ttk, messagebox
import requests
from ttkthemes import ThemedTk

class HttpHeaderViewer(ThemedTk):
    def __init__(self):
        super().__init__(theme="arc")
        self.set_theme("arc")
        self.title('Live HTTP Headers')
        self.prepared_request = None
        self.modified_headers = None

        # URL Input
        self.url_label = ttk.Label(self, text="Enter URL:")
        self.url_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        self.url_input = ttk.Entry(self, width=50)
        self.url_input.grid(row=0, column=1, columnspan=2, padx=5, pady=5)

        # Request Method Selection
        self.method_label = ttk.Label(self, text="Select Method:")
        self.method_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")

        self.selected_method = tk.StringVar()
        self.selected_method.set("GET")

        self.get_radio = ttk.Radiobutton(self, text="GET", variable=self.selected_method, value="GET")
        self.get_radio.grid(row=1, column=1, padx=5, pady=5)

        self.post_radio = ttk.Radiobutton(self, text="POST", variable=self.selected_method, value="POST")
        self.post_radio.grid(row=1, column=2, padx=5, pady=5)

        # Fetch Button
        self.fetch_button = ttk.Button(self, text="Fetch", command=self.fetch_headers)
        self.fetch_button.grid(row=0, column=3, padx=5, pady=5)

        # Headers Frame
        self.headers_frame = tk.Frame(self)
        self.headers_frame.grid(row=2, column=0, columnspan=4, padx=5, pady=5)

        # Response Headers
        self.response_headers_label = ttk.Label(self, text="Response Headers:")
        self.response_headers_label.grid(row=3, column=0, padx=5, pady=5, sticky="w")

        self.response_headers_text = tk.Text(self, width=60, height=10)
        self.response_headers_text.grid(row=4, column=0, columnspan=4, padx=5, pady=5)

        # Response Content
        self.response_content_label = ttk.Label(self, text="Response Content:")
        self.response_content_label.grid(row=5, column=0, padx=5, pady=5, sticky="w")

        self.response_content_text = tk.Text(self, width=60, height=10)
        self.response_content_text.grid(row=6, column=0, columnspan=4, padx=5, pady=5)

        # Send Button
        self.send_button = ttk.Button(self, text="Send", command=self.send_request)
        self.send_button.grid(row=7, column=0, columnspan=4, padx=5, pady=5)
        self.send_button.config(state=tk.DISABLED)

    def fetch_headers(self):
        url = self.url_input.get()
        if not url:
            messagebox.showwarning('Error', 'Please enter a URL')
            return

        method = self.selected_method.get()

        try:
            with requests.Session() as session:
                request = requests.Request(method, url)
                self.prepared_request = session.prepare_request(request)
                request_headers = self.prepared_request.headers
                self.create_header_entries(request_headers, self.headers_frame)
                self.send_button.config(state=tk.NORMAL)
        except Exception as e:
            messagebox.showerror('Error', f'Failed to fetch headers: {e}')

    def create_header_entries(self, headers, parent):
        for widget in parent.winfo_children():
            widget.destroy()

        for i, (header, value) in enumerate(headers.items()):
            label = ttk.Label(parent, text=f"{header}:")
            label.grid(row=i, column=0, padx=5, pady=2, sticky="w")

            entry = ttk.Entry(parent, width=50)
            entry.insert(0, value)
            entry.grid(row=i, column=1, padx=5, pady=2)

    def send_request(self):
        if not self.prepared_request:
            messagebox.showwarning('Error', 'No request to send')
            return

        try:
            modified_headers = {}
            for widget in self.headers_frame.winfo_children():
                if isinstance(widget, ttk.Entry):
                    header_name = widget.cget("text")
                    header_value = widget.get()
                    if header_name.strip() and header_value.strip():
                        modified_headers[header_name.strip()] = header_value.strip()

            session = requests.Session()

            if modified_headers:
                self.prepared_request.headers.update(modified_headers)

            response = session.send(self.prepared_request)

            response_headers = '\n'.join(f'{k}: {v}' for k, v in response.headers.items() if k and v)
            self.response_headers_text.delete('1.0', tk.END)
            self.response_headers_text.insert(tk.END, response_headers)

            self.response_content_text.delete('1.0', tk.END)
            self.response_content_text.insert(tk.END, response.text)

            self.send_button.config(state=tk.DISABLED)
        except requests.exceptions.RequestException as e:
            messagebox.showerror('Error', f'Failed to send request: {e}')



if __name__ == '__main__':
    app = HttpHeaderViewer()
    app.mainloop()
