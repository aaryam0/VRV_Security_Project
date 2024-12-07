# VRV_Security_Project

# VRV Security’s Python Intern Assignment

### **Introduction to VRV Security**

VRV Security, founded in 2020 in Chennai, Tamil Nadu, is a global powerhouse in AI-driven cybersecurity solutions. With a presence in over 12 countries, we have rapidly expanded to protect digital assets for Fortune 500 companies and government organizations. In 2024, our company valuation soared to $400 million, and we continue to set new benchmarks in cybersecurity. We deliver more than 500,000 hours of proactive threat monitoring annually and have secured over 1 million endpoints worldwide. Trusted by over 200 international clients across 5 continents, our expert team ensures unparalleled security and client satisfaction.

### **What We Do**

Our advanced cybersecurity offerings are built on AI and cloud technologies, tailored to protect modern digital infrastructures. Our key services include:

1. **AI-Dependent Services and Solutions VAPT**: Leveraging artificial intelligence, we perform comprehensive Vulnerability Assessment and Penetration Testing (VAPT) to identify and mitigate threats efficiently.
2. **Cloud Infrastructure VAPT**: We secure cloud environments by assessing vulnerabilities, ensuring robust defense mechanisms for sensitive data and applications.
3. **Threat Monitoring & SOC**: Our Security Operations Center (SOC) provides 24/7 threat monitoring, incident response, and real-time analytics to safeguard against evolving cyber threats.
4. **Company Infrastructure & Services VAPT**: We specialize in protecting complex enterprise infrastructure with tailor-made security strategies to prevent unauthorized access and data breaches.

### **Our Mission**

At VRV Security, our mission is to redefine cybersecurity by delivering adaptive, AI-driven solutions that anticipate and mitigate threats before they materialize. We aim to set the gold standard in proactive threat management and ensure our clients operate in a secure and resilient digital landscape. Our commitment to innovation and excellence has earned us a 95% client retention rate, a testament to our reliable and effective security measures. We strive to continue pushing boundaries and staying at the forefront of global cybersecurity.

---

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

---

### **Evaluation Criteria**

1. **Functionality**
    - The script processes the provided log file correctly and fulfills all requirements.
    - All sections of the analysis are implemented: IP request counts, most accessed endpoint, and suspicious activity detection.
2. **Code Quality**
    - Clear, well-organized, and modular code.
    - Proper use of comments, meaningful variable names, and adherence to Python best practices.
3. **Performance**
    - The script handles the provided log file efficiently and can scale to larger files without significant delays.
4. **Output**
    - Correctly formatted output in both the terminal and the saved CSV file.
    - The CSV file structure matches the specified format.
