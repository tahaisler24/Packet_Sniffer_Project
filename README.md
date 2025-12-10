# 🕵️ Python Based Packet Sniffer

A lightweight network traffic analyzer built from scratch using Python's native `socket` and `struct` libraries.

This project was developed to understand the **OSI Model** and **TCP/IP** stack at a low level. Instead of using high-level libraries like Scapy, I used **Raw Sockets** to capture and manually parse binary data from the network card.

## 🚀 Features

* **Raw Socket Implementation:** Connects directly to the network driver using `AF_PACKET`.
* **Manual Binary Parsing:** Unpacks Ethernet, IPv4, and TCP headers using bitwise operations.
* **HTTP Filter:** Specifically monitors and captures traffic on **Port 80**.
* **Data Visualization:** Displays captured payloads in both **Hex** and **ASCII** (readable text) formats.
* **Clean Architecture:** Modular code structure with separate functions for each protocol layer.

## 🛠️ How It Works (The Logic)

1.  **Ethernet Layer:** Captures the raw frame and extracts MAC addresses.
2.  **IP Layer:** Analyzes the IP header to find Source and Destination IP addresses.
3.  **Transport Layer (TCP):** Extracts Port numbers to identify the service (e.g., HTTP).
4.  **Application Layer:** Decodes the payload to show real user data (like form inputs).

## 📋 Requirements

* **Operating System:** Linux (Kali Linux, Ubuntu, etc.)
    * *Note: This tool uses Raw Sockets, which functions differently on Windows. Linux is required.*
* **Language:** Python 3.x
* **Privileges:** Root / Sudo access is required to listen to the network interface.

## ▶️ Installation & Usage

1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/tahaisler24/Packet_Sniffer_Project.git](https://github.com/tahaisler24/Packet_Sniffer_Project.git)
    cd Packet_Sniffer_Project
    ```

2.  **Run the Tool:**
    Since it accesses the network card directly, you must run it with `sudo`:
    ```bash
    sudo python3 main.py
    ```

3.  **Test It:**
    Open a web browser or use `curl` to visit an HTTP site:
    ```bash
    # Example test
    curl [http://testphp.vulnweb.com/login.php](http://testphp.vulnweb.com/login.php)
    ```

4.  **Stop:**
    Press `CTRL + C` to stop the sniffer.

## 📸 Example Output

```text
[*] Sniffer Started! Listening for HTTP traffic (Port 80)...

[HTTP Captured] 192.168.1.15:44556 -> 44.228.249.3:80
    POST /userinfo.php HTTP/1.1
    Host: testphp.vulnweb.com
    ...
    username=admin&password=secret123
