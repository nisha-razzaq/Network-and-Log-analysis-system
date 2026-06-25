### **Network Log Analysis System**

This C++ application is designed to process, analyze, and monitor network security logs. It parses log data, detects anomalies, identifies suspicious traffic patterns, and generates a dashboard for security reporting.



##### Features

###### Log Parsing: Efficiently reads and processes comma-separated log files.

##### 

###### Security Analysis: \* Detects excessive request frequencies.



Identifies failed login attempts.



Flags blocked IP addresses.



Alerts on unexpected system shutdowns.



Data Visualization: Generates text-based histograms and exports a comprehensive HTML security dashboard.



Log Rotation: Automatically manages log file sizes by archiving old data.



Automated Monitoring: Includes a continuous monitoring mode to watch for new incoming logs.



##### Project Structure

logs.h: Header file containing the class definition, global configurations, and function declarations.



logs.cpp: Implementation file containing the core logic for all defined functions.



main.cpp: Entry point of the application; manages the program flow and user interaction.



config.txt: Configuration file for setting sensitivity thresholds (e.g., failed login limits).



##### Compilation

To compile the project, use the following command in your terminal:



##### Bash

g++ main.cpp logs.cpp -o log_analyzer

###### Usage

Configuration: Ensure config.txt exists in the same directory (or the system will use default values).



Execution: Run the compiled binary:



Bash (For Windows)

.\log_analyzer

Bash (For Git Bash / Linux / MacOS)

 ./log_analyzer

Operation: Use the menu system (as defined in your main loop) to choose between parsing logs, running analyses, or entering live monitoring mode.

