#ifndef LOGS_H
#define LOGS_H


#include<iostream>
#include<vector>
#include<string>
#include <map>
using namespace std;


class logs {
private:
    string timestamp;
    string s_IP;
    string d_IP;
    string e_type;
    int s_code;
    string d_message;

    public:     //using getter and settters for better encapsulation
    void set_timestamp(const string& t)
    {
        timestamp = t ;
    }
    void set_s_IP(const string& ip) // can be used same variable
    {
        s_IP = ip;
    }
    void set_d_IP(const string& ip)
    {
        d_IP = ip;
    }
    void set_e_type(const string& event)
    {
        e_type = event ;
    }
    void set_s_code(int code)
    {
        s_code = code;
    }
    void set_d_message(const string& message)
    {
        d_message = message;
    }
    string get_timestamp()
    const {
        return timestamp ;
    }
    string get_s_IP()
    const { return s_IP ;}
    string get_d_IP()
    const {return d_IP;}
    string get_e_type()
    const {return e_type;}
    int get_s_code()
    const {return s_code;}
    string get_d_message()
    const {return d_message;}
    int get_severity() const {
    if (s_code >= 500) return 2; 
    if (s_code >= 400) return 1;
    return 0;                    
}
};

extern int cfg_failed_login;
extern int cfg_spike_threshold;
extern int cfg_request_limit;
void databaselogs(int size);
vector<logs> parsing();
void analyze(const vector<logs>& storage);
void fullanalysis(const vector<logs>& storage);
void loadConfig();
void clearScreen();
void monitorLogs();
vector <logs> search(const vector<logs>& storage, const string& value, const string& type);
void runAutomatedScan(const vector<logs>& storage);
void rotateLogs();
void exportReport(const vector<logs>& storage);
void printHistogram(const map<string, int>& data, string title);
void generateHTMLReport(const vector<logs>& storage, const map<string,int>& f_ip,const map<string,int>& error_count);

#endif