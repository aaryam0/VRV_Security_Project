# VRV Security’s Python Intern Assignment

## Assignment: Log Analysis Script

### **Objective**

The goal of this assignment is to assess your ability to write a Python script that processes log files to extract and analyze key information. This assignment evaluates your proficiency in **file handling**, **string manipulation**, and **data analysis**, which are essential skills for cybersecurity-related programming tasks.

---

### **Core Requirements**

Your Python script should implement the following functionalities:

1. **Count Requests per IP Address**:
    - Parse the provided log file to extract all IP addresses.
    - Calculate the number of requests made by each IP address.
    - Sort and display the results in descending order of request counts.
    - Example output:
        
        ```bash
        IP Address           Request Count
        192.168.1.1          234
        203.0.113.5          187
        10.0.0.2             92
        ```
        
2. **Identify the Most Frequently Accessed Endpoint**:
    - Extract the endpoints (e.g., URLs or resource paths) from the log file.
    - Identify the endpoint accessed the highest number of times.
    - Provide the endpoint name and its access count.
    - Example output:
        
        ```bash
        Most Frequently Accessed Endpoint:
        /home (Accessed 403 times)
        ```
        
3. **Detect Suspicious Activity**:
    - Identify potential brute force login attempts by:
        - Searching for log entries with failed login attempts (e.g., HTTP status code `401` or a specific failure message like "Invalid credentials").
        - Flagging IP addresses with failed login attempts exceeding a configurable threshold (default: 10 attempts).
    - Display the flagged IP addresses and their failed login counts.
    - Example output:
        
        ```less
        Suspicious Activity Detected:
        IP Address           Failed Login Attempts
        192.168.1.100        56
        203.0.113.34         12
        ```
        
4. **Output Results**:
    - Display the results in a clear, organized format in the terminal.
    - Save the results to a CSV file named `log_analysis_results.csv` with the following structure:
        - **Requests per IP**: Columns: `IP Address`, `Request Count`
        - **Most Accessed Endpoint**: Columns: `Endpoint`, `Access Count`
        - **Suspicious Activity**: Columns: `IP Address`, `Failed Login Count`

---

### **Sample Log File**

Here is a sample log file you will use for this assignment. Save it as `sample.log`:

```bash
192.168.1.1 - - [03/Dec/2024:10:12:34 +0000] "GET /home HTTP/1.1" 200 512
203.0.113.5 - - [03/Dec/2024:10:12:35 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:36 +0000] "GET /about HTTP/1.1" 200 256
192.168.1.1 - - [03/Dec/2024:10:12:37 +0000] "GET /contact HTTP/1.1" 200 312
198.51.100.23 - - [03/Dec/2024:10:12:38 +0000] "POST /register HTTP/1.1" 200 128
203.0.113.5 - - [03/Dec/2024:10:12:39 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
192.168.1.100 - - [03/Dec/2024:10:12:40 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:41 +0000] "GET /dashboard HTTP/1.1" 200 1024
198.51.100.23 - - [03/Dec/2024:10:12:42 +0000] "GET /about HTTP/1.1" 200 256
192.168.1.1 - - [03/Dec/2024:10:12:43 +0000] "GET /dashboard HTTP/1.1" 200 1024
203.0.113.5 - - [03/Dec/2024:10:12:44 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
203.0.113.5 - - [03/Dec/2024:10:12:45 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
192.168.1.100 - - [03/Dec/2024:10:12:46 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:47 +0000] "GET /profile HTTP/1.1" 200 768
192.168.1.1 - - [03/Dec/2024:10:12:48 +0000] "GET /home HTTP/1.1" 200 512
198.51.100.23 - - [03/Dec/2024:10:12:49 +0000] "POST /feedback HTTP/1.1" 200 128
203.0.113.5 - - [03/Dec/2024:10:12:50 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
192.168.1.1 - - [03/Dec/2024:10:12:51 +0000] "GET /home HTTP/1.1" 200 512
198.51.100.23 - - [03/Dec/2024:10:12:52 +0000] "GET /about HTTP/1.1" 200 256
203.0.113.5 - - [03/Dec/2024:10:12:53 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
192.168.1.100 - - [03/Dec/2024:10:12:54 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:55 +0000] "GET /contact HTTP/1.1" 200 512
198.51.100.23 - - [03/Dec/2024:10:12:56 +0000] "GET /home HTTP/1.1" 200 512
192.168.1.100 - - [03/Dec/2024:10:12:57 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
203.0.113.5 - - [03/Dec/2024:10:12:58 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:59 +0000] "GET /dashboard HTTP/1.1" 200 1024
192.168.1.1 - - [03/Dec/2024:10:13:00 +0000] "GET /about HTTP/1.1" 200 256
198.51.100.23 - - [03/Dec/2024:10:13:01 +0000] "POST /register HTTP/1.1" 200 128
203.0.113.5 - - [03/Dec/2024:10:13:02 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
192.168.1.100 - - [03/Dec/2024:10:13:03 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:13:04 +0000] "GET /profile HTTP/1.1" 200 768
198.51.100.23 - - [03/Dec/2024:10:13:05 +0000] "GET /about HTTP/1.1" 200 256
192.168.1.1 - - [03/Dec/2024:10:13:06 +0000] "GET /home HTTP/1.1" 200 512
198.51.100.23 - - [03/Dec/2024:10:13:07 +0000] "POST /feedback HTTP/1.1" 200 128
```

