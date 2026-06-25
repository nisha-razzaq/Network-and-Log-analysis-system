#include "logs.h"
#include<iostream>
#include<fstream>
#include<cstdlib>
#include<ctime>
#include<string>
#include<iomanip>
#include<sstream>
#include<vector>
#include<set>
#include<map>
#include <thread> 
#include <chrono>
using namespace std;

int cfg_failed_login = 5;
int cfg_spike_threshold = 3;
int cfg_request_limit = 100;
void rotateLogs()
 {
    
    string archiveName = "archive_log_" + to_string(time(0)) + ".csv";
    if (rename("log_file.csv", archiveName.c_str()) == 0) 
    {
        cout << "\n[SYSTEM] Log file rotated successfully to: " << archiveName << endl;
    }
    else
    {
        cout << "\n[SYSTEM] Failed to rotate log file." << endl;
    }
}

void databaselogs(int size)   //Random generator (helps to generate large datasets)
{    
    if (size > 500) 
    {
    rotateLogs();
    }
    srand(time(0));
    ofstream file("log_file.csv");
    if(file.is_open())
    { 
        vector<string> s_IPs = {"192.168.1.10", "192.168.0.25", "10.0.0.5", "10.1.2.3", "172.16.0.100", "172.20.5.7", "192.168.100.200", "10.10.10.50" };
        vector<string> d_IPs = {"203.0.113.5", "198.51.100.25", "8.8.8.8", "8.8.4.4", "93.184.216.34", "151.101.1.69", "172.217.16.142", "185.199.108.153" };
        vector<string> e_types= {"Login", "Logout", "File Access", "Data Update", "System Shutdown", "Access Denied", "Connection Lost", "Error"};
        vector<int> s_codes  = {200, 201, 301, 400, 401, 403, 404, 500};
        vector<string> d_messages = {"Login Successful","Logout Completed","File Access Granted", "Data Updated", "System Shutdown Initiated", "Access Denied", "Connection Lost", "Critical Error Occurred"};
        for(int i=0;i<size;i++)
        {
            string date = "2026-06-" + to_string(rand()%10+20); //creating dates randomly bw 20-29
            string timeh = "10:" + to_string(rand()%10+10) + ":";
            string time = timeh + to_string(rand()%10+10);
            string s_IP = s_IPs[rand()%s_IPs.size()]; //creating a random no less than arrays size
                                                      // and choosing that random no's index value
            string d_IP = d_IPs[rand()%d_IPs.size()];
            string e_type = e_types[rand()%e_types.size()];
            int s_code = s_codes[rand()%s_codes.size()];
            string d_message = d_messages[rand()%d_messages.size()];
            file << date << " " << time << "," << s_IP << "," << d_IP << "," << e_type << "," << s_code << "," << d_message << endl;
            
        }    
    
      cout << size << " records created sucessfully !! " << endl;
    }

    else
    {
        cout<< "File couldn't open !! " << endl;
    }
   
}
vector<logs>  parsing() // using a comma based parsing
{  
   vector<logs> storage ;
   int linecount=1;
   int t_records=0; //total records
   int v_records=0; //total records 
   int e_records=0; //empty record   
   int f_records=0; //faulty records
   ifstream file("log_file.csv");
   if(file.is_open())
   {
    // cout << setw(18) << "Time stamp" << setw(17) << "Source IP's" << setw(20) << "Destination IP's"<< setw(20)<< "Event Type" << setw(17) << "Status code" << setw(30) << "Display Information" << endl;
    string line;
    while(getline(file,line))
    {    
        logs l1 ; //creating object of class logs
         try  //using a standard c++ container to protect progarm crash incase of errors
    {
        if(line.empty())  //handling empty record
        {   
            e_records++;
            t_records++;
            continue;
        }
        string holder;
        stringstream ss(line); //placing line in ss var
        getline(ss,holder, ',');
        l1.set_timestamp(holder);
        getline(ss,holder, ',');
        l1.set_s_IP(holder);
        getline(ss,holder, ',');
        l1.set_d_IP(holder) ;
        getline(ss,holder, ',');
        l1.set_e_type(holder) ;
        getline(ss,holder, ',');
        l1.set_s_code (stoi(holder));   //using conversion from string to int as holder is a string type
        getline(ss,holder, ',');
        l1.set_d_message(holder) ;
        // cout << setw(18) << l1.get_timestamp() << setw(17) << l1.get_s_IP() << setw(20) << l1.get_d_IP() << setw(20)<<l1.get_e_type() << setw(17) <<l1.get_s_code() << setw(30) << l1.get_d_message() << endl;
        linecount++;
        v_records++;
        t_records++;
        storage.push_back(l1); // storing records in a vector so program speed remains fast 

    }
     catch(exception& error) //runs in case of any error found in records
   {
    cout << "Error occurs at line " << linecount << endl;
    f_records++;
    linecount++;
    t_records++;
    
      
   }


   }
   if(t_records==0)
   cout << "No records found in the file !! " << endl ;
    
   cout << "Parsing done sucessfully !! " << endl ;
   cout << "Total Records: " << t_records << endl;
   cout << "Valuable Records: " << v_records << endl;
   cout << "Faulty Records: " << f_records << endl;
   cout << "Empty Records: " << e_records << endl;

  
   }
   else
   {
    cout << "File can't be accessed !! " << endl;
   }
   return storage; // returning storage for further analysis purposes

}

void analyze(const vector<logs>& storage)
{    
    cout << "Total Requests:  " << storage.size() << endl;
    set<string> ipcount; //using set container to keep track of unique ips
    for(const auto& logs: storage)
    {
        ipcount.insert(logs.get_s_IP()) ;
    }
    cout << "Unique IP Addresse's: " << ipcount.size() << endl;
    map<string, int> f_ip;
    for(const auto& logs: storage)
    {
        f_ip[logs.get_s_IP()]++ ;
    }
    printHistogram(f_ip, "Request Frequency by IP");
    int maxcount=0;
    string active_ip;
    for(const auto& [ip,count] : f_ip)
    {
        if(count> maxcount)
        {
            maxcount = count;
            active_ip = ip;
        }
        
        
    }
    cout << "Most active IP : " << active_ip << " occurs " << maxcount << " times" << endl ;
    cout << "Request Frequency: " << endl;
    for(const auto& [ip,count]: f_ip) // f_ip already storing frequency of ips
    {
      cout <<setw(15)<< ip << setw(10) << " occurs " << setw(5) << count << setw(8) << " times " << endl;

    }
    cout << "Error Frequency: " << endl;
    map<string , int > error_count;
    for(const auto& logs : storage)
    {   if(logs.get_s_code()>=400)
        error_count[logs.get_s_IP()]++;
    }
    printHistogram(error_count, "Error Frequency by IP");
    generateHTMLReport(storage,f_ip, error_count);
    for(const auto& [ip,count] : error_count )
    {
        cout << setw(15) << ip << setw(15) << " error occurs " << count << setw(8) << " times " << endl ;
    }
    
    map<string , int > hours ;
    for(const auto& logs:storage)
    {
        string hour = logs.get_timestamp().substr(11,2);
        hours[hour]++;
    } 
    int total = 0;
    for(const auto& [hour,count] : hours)
     {
    total += count;
     }
    double average = static_cast<double>(total) / hours.size();
    int max_count=0; 
    string maxh;
    for(const auto& [hour,count] : hours)
    {
        if(count>max_count)
        {
            max_count = count ;
            maxh = hour;
        }
        if(count > average * 3)
        { 
        cout << "Traffic Spike: Hour " << hour << " had " << count << " requests (avg ~" << average << ")" << endl;
    }

    }
    cout << "Peak Active Hours: "<< maxh << " occurs " << max_count << " times " << endl;
}
     
    void threat_detection(const vector<logs>& storage)
    {     
        if (storage.empty()) return;
        set<string> uniqueIPs;
        for(const auto& log : storage) 
        {uniqueIPs.insert(log.get_s_IP());
        }
         if (uniqueIPs.empty())
          return;
         double average1 = static_cast<double>(storage.size()) / uniqueIPs.size();
         int threshold = 3 * average1 ;
         map<string, int> f_ip;
    for(const auto& logs: storage)
    {
        f_ip[logs.get_s_IP()]++ ;
    }
    int maxcount=0;
    string active_ip;
    for(const auto& [ip,count] : f_ip)
    {
        if(count > cfg_request_limit)
        {
         cout << "Custom Alert: IP " << ip << " made over " << cfg_request_limit << " requests!" << endl;
        }
    }
        map < string,int> failedLogins ;
    for(const auto& logs : storage)
    {
        if(logs.get_e_type()=="Login" && logs.get_s_code()>=400)
        {
            failedLogins[logs.get_s_IP()]++;
        }
    }
     for(const auto& [ip,count] : failedLogins) 
     {
        if(count >cfg_failed_login)
        { 
            cout << "Suspicious: IP " << ip << " had " << count  << " failed login attempts" << endl;
        }
 
   }
   set<string> blockedIPs = {"203.0.113.5", "198.51.100.25"};
    for(const auto& logs : storage)
    {
    if(blockedIPs.count(logs.get_s_IP())) 
    {
    cout << "Alert: Blocked IP attempted access -> " << logs.get_s_IP() << endl;
    }
    } 
    
    int serverErrors = 0;
    for(const auto& entry : storage)
    {
        if(entry.get_s_code() == 500)
         serverErrors++;
    }
    if(serverErrors > 10) 
    {
        cout << "Custom Alert: More than 10 server errors detected!" << endl;
    }

    for(const auto& [ip,count] : f_ip)
    {
        if(count > cfg_request_limit)
        {
            cout << "Custom Alert: IP " << ip << " made over "<< cfg_request_limit << "requests!" << endl;
        }
    }

    for(const auto& entry : storage) 
    {
        if(entry.get_e_type() == "System Shutdown") 
        {
            cout << "Custom Alert: Unexpected system shutdown event at " << entry.get_timestamp() << endl;
        }
    }
}

void fullanalysis(const vector<logs>& storage)
{
    if(storage.empty())
    {
        cout<< "No data available for analysis !! " << endl;

    }
  analyze(storage);
  threat_detection( storage);



}
vector<logs> search(const vector<logs>& storage, const string& value , const string& type)
{
   vector<logs> result;
 
   for(const auto& log : storage)
   {
    bool find = false;
    if(type == "IP")
    {
    if(value == log.get_s_IP() || value== log.get_d_IP())
    {
        find =true;
    }
    }
    else if(type== "Date")
    {
    if (log.get_timestamp().substr(0, 10) == value)
    {
       find = true;
    }
    }
    else if (type == "Event") 
    {
    if (log.get_e_type() == value) 
    {  
        find = true;
    }
    }
    if (find)
     {
            result.push_back(log);
    }
}
   return result;
   
}
void clearScreen()
 {
   system("cls");
 }
void exportReport(const vector<logs>& storage)
 {
    ofstream report("report.txt");
    if (report.is_open())
     {
        report << "========================================" << endl;
        report << "      Network Analysis Summary Report   " << endl;
        report << "========================================" << endl;
        report << "Total Requests Processed: " << storage.size() << endl;
        
        set<string> ips;
        for(const auto& log : storage) 
        {ips.insert(log.get_s_IP());}
        report << "Unique IP Addresses: " << ips.size() << endl;
        
        report << "\nDetailed logs exported at: " << time(0) << endl;
        report.close();
        cout << "\nReport successfully exported to 'report.txt'!" << endl;
    }
    else 
    {
        cout << "\nError: Could not create report file." << endl;
    }
}
void loadConfig() {
    ifstream file("config.txt");
    if (file.is_open()) {
        file >> cfg_failed_login >> cfg_spike_threshold >> cfg_request_limit;
        file.close();
        cout << "Configuration loaded successfully." << endl;
    } else {
        cout << "Config file not found, using default values." << endl;
    }
}
void monitorLogs()
 {
    ifstream file("log_file.csv");
    if (!file.is_open()) {
        cout << "Could not open log file for monitoring." << endl;
        return;
    }

    // Go to the end of the file initially so we only show NEW entries
    file.seekg(0, ios::end);
    streampos lastPos = file.tellg();

    cout << "Monitoring for new logs... (Press Ctrl+C to stop)" << endl;

    while (true) 
    {
    
        file.clear(); // Clear EOF flag
        file.seekg(lastPos);

        string line;
        while (getline(file, line)) 
        {
            if (!line.empty()) 
            {
                cout << "New Log Entry: " << line << endl;
            }
        }

                                 
        lastPos = file.tellg(); // Update last position
        this_thread::sleep_for(chrono::seconds(2));  // Wait 2 seconds before checking again
    }
}
void runAutomatedScan(const vector<logs>& storage)
 {
    static time_t lastScanTime = 0;  
    time_t currentTime = time(0);
    if (difftime(currentTime, lastScanTime) >= 60)
    {
        cout << "\n--- Scheduled Auto-Scan Initiated ---" << endl;
        fullanalysis(storage);
        lastScanTime = currentTime;
        cout << "--- Auto-Scan Finished ---" << endl;
    }
}
void printHistogram(const map<string, int>& data, string title)
{
    cout << "\n--- " << title << " ---" << endl;
    for (const auto& [key, count] : data)
     {
        cout << setw(15) << key << " | ";
        for (int i = 0; i < count; ++i)
        {
            cout << "#";
        }
        cout << " (" << count << ")" << endl;
    }
}

void generateHTMLReport(
    const vector<logs>& storage,
    const map<string,int>& f_ip,
    const map<string,int>& error_count)
{
    ofstream report("dashboard.html");

    if(!report.is_open())
        return;

    set<string> uniqueIPs;

    map<string,int> eventDistribution;

    int criticalErrors = 0;
    int warningErrors = 0;

    for(const auto& log : storage)
    {
        uniqueIPs.insert(log.get_s_IP());

        eventDistribution[log.get_e_type()]++;

        if(log.get_s_code() >= 500)
            criticalErrors++;

        else if(log.get_s_code() >= 400)
            warningErrors++;
    }

    int totalRequests = storage.size();

    int totalAlerts = criticalErrors + warningErrors;

    string riskLevel;

    if(totalAlerts > 30)
        riskLevel = "HIGH";

    else if(totalAlerts > 15)
        riskLevel = "MEDIUM";

    else
        riskLevel = "LOW";

    string topIP = "N/A";
    int topCount = 0;

    for(const auto& [ip,count] : f_ip)
    {
        if(count > topCount)
        {
            topCount = count;
            topIP = ip;
        }
    }

    report << "<html><head><title>Security Dashboard</title>";

    report << "<style>"
           << "body{font-family:Arial;background:#0f172a;color:white;padding:20px;}"
           << "h1{text-align:center;}"
           << ".summary{display:grid;grid-template-columns:repeat(4,1fr);gap:15px;margin-bottom:20px;}"
           << ".card{background:#1e293b;padding:15px;border-radius:12px;box-shadow:0 0 10px rgba(0,0,0,0.4);}"
           << ".section{background:#1e293b;padding:20px;border-radius:12px;margin-top:20px;}"
           << ".bar{height:15px;border-radius:8px;background:#38bdf8;margin-top:3px;}"
           << ".danger{color:#ef4444;font-weight:bold;}"
           << ".warning{color:#facc15;font-weight:bold;}"
           << ".safe{color:#22c55e;font-weight:bold;}"
           << "table{width:100%;border-collapse:collapse;margin-top:10px;}"
           << "th,td{border:1px solid #475569;padding:8px;text-align:left;}"
           << "</style>";

    report << "</head><body>";

    report << "<h1>Network Monitoring Dashboard</h1>";

    report << "<div class='summary'>";

    report << "<div class='card'><h3>Total Requests</h3><h2>"
           << totalRequests
           << "</h2></div>";

    report << "<div class='card'><h3>Unique IPs</h3><h2>"
           << uniqueIPs.size()
           << "</h2></div>";

    report << "<div class='card'><h3>Total Alerts</h3><h2>"
           << totalAlerts
           << "</h2></div>";

    report << "<div class='card'><h3>Risk Level</h3><h2>";

    if(riskLevel=="HIGH")
        report << "<span class='danger'>HIGH</span>";

    else if(riskLevel=="MEDIUM")
        report << "<span class='warning'>MEDIUM</span>";

    else
        report << "<span class='safe'>LOW</span>";

    report << "</h2></div>";

    report << "</div>";

    report << "<div class='section'>";
    report << "<h2>Top Active Source</h2>";
    report << "<p><b>" << topIP << "</b> (" << topCount << " requests)</p>";
    report << "</div>";

    report << "<div class='section'>";
    report << "<h2>Traffic by IP</h2>";

    for(const auto& [ip,count] : f_ip)
    {
        report << "<div>" << ip << " (" << count << ")</div>";
        report << "<div class='bar' style='width:"
               << min(count*5,100)
               << "%'></div>";
    }

    report << "</div>";

    report << "<div class='section'>";
    report << "<h2>Error Frequency</h2>";

    for(const auto& [ip,count] : error_count)
    {
        report << "<div>" << ip << " (" << count << ")</div>";
        report << "<div class='bar' style='width:"
               << min(count*5,100)
               << "%;background:#ef4444'></div>";
    }

    report << "</div>";

    report << "<div class='section'>";
    report << "<h2>Event Distribution</h2>";

    for(const auto& [event,count] : eventDistribution)
    {
        report << "<p>"
               << event
               << " : "
               << count
               << "</p>";
    }

    report << "</div>";

    report << "<div class='section'>";
    report << "<h2>Top Active IP Table</h2>";

    report << "<table>";
    report << "<tr><th>IP Address</th><th>Requests</th></tr>";

    for(const auto& [ip,count] : f_ip)
    {
        report << "<tr><td>"
               << ip
               << "</td><td>"
               << count
               << "</td></tr>";
    }

    report << "</table>";
    report << "</div>";

    report << "<div class='section'>";
    report << "<h2>Security Recommendations</h2>";

    if(criticalErrors > 10)
    {
        report << "<p>Investigate high number of server-side failures.</p>";
    }

    if(warningErrors > 20)
    {
        report << "<p>Review repeated client-side errors and failed requests.</p>";
    }

    if(topCount > cfg_request_limit)
    {
        report << "<p>Monitor potential excessive traffic from "
               << topIP
               << ".</p>";
    }

    if(totalAlerts < 10)
    {
        report << "<p>Network activity appears normal.</p>";
    }

    report << "</div>";

    report << "<div class='section'>";
    report << "<h2>Analysis Summary</h2>";
    report << "<p>Dashboard generated successfully.</p>";
    report << "<p>Total Logs Processed: "
           << totalRequests
           << "</p>";
    report << "</div>";

    report << "</body></html>";

    report.close();

    cout << "\nHTML Dashboard generated successfully (dashboard.html)\n";
}