# 🔐 Network Log Analysis System

A C++ application designed to process, analyze, and monitor network security logs.  
It parses log data, detects anomalies, identifies suspicious traffic patterns, and generates a dashboard for security reporting.

---

# 📖 Overview
The Network Log Analysis System provides a framework for monitoring and analyzing network activity.  
It helps detect unusual behavior, failed login attempts, blocked IPs, and other anomalies that may indicate security threats.  
The project was created to practice **C++ programming, file handling, and security analysis concepts**.

---

# 🛠️ Technologies
- **C++** – core programming language  
- **File Handling** – for reading and parsing log files  
- **Text-based Visualization** – histograms and reports  
- **HTML Export** – generates a security dashboard  

---



# ✨ Features
- 📂 **Log Parsing** – efficiently reads and processes comma-separated log files  
- 🔍 **Security Analysis**  
  - Detects excessive request frequencies  
  - Identifies failed login attempts  
  - Flags blocked IP addresses  
  - Alerts on unexpected system shutdowns  
- 📊 **Data Visualization** – generates text-based histograms and exports an HTML dashboard  
- ♻️ **Log Rotation** – automatically manages log file sizes by archiving old data  
- ⚡ **Automated Monitoring** – continuous monitoring mode for new incoming logs  

---

# 🔄 Process
1. **Planning & Design** – defined detection rules and thresholds.  
2. **Log Parsing** – implemented functions to read and validate CSV log files.  
3. **Security Analysis** – added detection for anomalies (failed logins, blocked IPs, traffic spikes).  
4. **Visualization** – created text-based histograms and HTML dashboard export.  
5. **Testing & Monitoring** – tested with simulated logs and added live monitoring mode.  

---

# 📚 What I Learned
- Advanced **C++ file handling** and parsing techniques  
- Designing modular code with header (`.h`) and implementation (`.cpp`) files  
- Applying **security concepts** like anomaly detection and log rotation  
- Building **text-based dashboards** and exporting reports to HTML  
- Managing continuous monitoring loops for real-time analysis  

---

# 🔧 How It Can Be Improved
- Add **graphical visualization** (charts/graphs) using libraries like Qt or SFML  
- Integrate with a **database** for storing and querying logs  
- Enhance **real-time monitoring** with multithreading for performance  
- Implement **alert notifications** (e.g., email or system pop-ups)  
- Add **machine learning models** for predictive anomaly detection  

---

# 📂 Project Structure
- `logs.h` – header file containing class definitions, global configurations, and function declarations  
- `logs.cpp` – implementation file with core logic for defined functions  
- `main.cpp` – entry point of the application; manages program flow and user interaction  
- `config.txt` – configuration file for sensitivity thresholds (e.g., failed login limits)  

---

# ⚙️ Compilation
To compile the project, use the following command:

```bash
g++ main.cpp logs.cpp -o log_analyzer
.\log_analyzer (For Windows)
./log_analyzer (Linux/MacOS/Git )


