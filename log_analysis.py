import re
from collections import defaultdict
import csv

# File path for the log file
log_file = 'sample.log'

# Define the threshold for suspicious activity
FAILED_LOGIN_THRESHOLD = 10

# Initialize dictionaries to store data
ip_requests = defaultdict(int)
endpoints = defaultdict(int)
failed_logins = defaultdict(int)

# Regular expression patterns for extracting data
ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'
endpoint_pattern = r'\"[A-Z]+\s+([^\s]+)\s+HTTP/1.1\"'
failed_login_pattern = r'POST\s+/login\s+HTTP/1.1"\s+401'

# Function to process log file
def process_log():
    with open(log_file, 'r') as file:
        for line in file:
            # Extract IP address
            ip_match = re.search(ip_pattern, line)
            if ip_match:
                ip = ip_match.group(1)
                ip_requests[ip] += 1
            
            # Extract endpoint
            endpoint_match = re.search(endpoint_pattern, line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoints[endpoint] += 1

            # Detect failed login attempts
            if re.search(failed_login_pattern, line):
                failed_logins[ip] += 1

# Function to display and save results
def display_and_save_results():
    # Sort IP requests and endpoints
    sorted_ips = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)
    most_accessed_endpoint = max(endpoints.items(), key=lambda x: x[1], default=('', 0))

    # Print IP request counts
    print("Requests per IP:")
    print(f"{'IP Address':<20} {'Request Count'}")
    for ip, count in sorted_ips:
        print(f"{ip:<20} {count}")

    # Print most accessed endpoint
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    # Print suspicious activity
    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20} {'Failed Login Attempts'}")
    for ip, count in failed_logins.items():
        if count > FAILED_LOGIN_THRESHOLD:
            print(f"{ip:<20} {count}")

    # Save results to CSV
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write Requests per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in sorted_ips:
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        # Write Suspicious Activity
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in failed_logins.items():
            if count > FAILED_LOGIN_THRESHOLD:
                writer.writerow([ip, count])

# Run the log processing
process_log()

# Display results and save to CSV
display_and_save_results()
