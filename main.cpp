#include "logs.h"
#include <vector>
#include <string>

using namespace std;

int main() 
{   loadConfig();
    vector<logs> storage;
    bool dataLoaded = false;
    int choice;
    bool autoScanEnabled = false;

    while (true) {
        clearScreen();
        cout << "\n========================================" << endl;
        cout << "   Network Monitoring & Log Analysis    " << endl;
        cout << "========================================" << endl;
        cout << "1. Load & Process Log File" << endl;
        cout << "2. View Full Statistics & Alerts" << endl;
        cout << "3. Search Activity Records" << endl;
        cout << "4. Export Analysis Report" << endl;
        cout << "5. Start Real-Time Monitor" << endl;
        cout << "6. Toggle Auto-Scan: " << (autoScanEnabled ? "ON" : "OFF") << endl; 
        cout << "7. Exit: " << endl;
        cout << "Selection: ";
        cin >> choice;
        if (autoScanEnabled && dataLoaded) 
        {
            runAutomatedScan(storage);
        }

        if (choice == 1) {
            databaselogs(30); 
            storage = parsing();
            dataLoaded = true;
            cout << "\nPress Enter to continue...";
            cin.ignore(); cin.get(); 
        } 
        else if (dataLoaded && (choice == 2 || choice == 3)) {
            bool back = false;
            while (!back) {
                clearScreen();
                if (choice == 2) {
                    fullanalysis(storage);
                    cout << "\nPress Enter to return to Main Menu...";
                    cin.ignore(); cin.get();
                    back = true;
                } 
                else if (choice == 3) {
                    cout << "\n--- Search Menu ---" << endl;
                    cout << "1. Search by IP" << endl;
                    cout << "2. Search by Date" << endl;
                    cout << "3. Search by Event" << endl;
                    cout << "4. Back" << endl;
                    cout << "Selection: ";
                    int subChoice;
                    cin >> subChoice;

                    if (subChoice == 4) {
                        back = true;
                    } 
                    else if (subChoice >= 1 && subChoice <= 3) {
                        string type = (subChoice == 1) ? "IP" : (subChoice == 2) ? "Date" : "Event";
                        string value;
                        cout << "Enter " << type << ": "; cin >> value;
                        
                        vector<logs> results = search(storage, value, type);
                        cout << "\nResults (" << results.size() << " found):" << endl;
                        for (const auto& log : results) {
                            cout << log.get_timestamp() << " | " << log.get_s_IP() << " | " << log.get_e_type() << endl;
                        }
                        cout << "\nPress Enter to continue...";
                        cin.ignore(); cin.get(); 
                    }
                }
            }
        }
        else if (choice == 4) {
            if (!dataLoaded) 
                cout << "Please load data first!" << endl;
            else 
                exportReport(storage);
            cout << "\nPress Enter to continue...";
            cin.ignore(); cin.get();
        }
        else if (choice == 5) 
        {
            monitorLogs(); // Call the function defined in logs.cpp
            cout << "\nMonitoring stopped. Returning to menu..." << endl;
        }
        else if (choice == 6) 
        {
         autoScanEnabled = !autoScanEnabled;
         cout << "\n----------------------------------------" << endl;
         cout << "Auto-Scan feature has been toggled: " << (autoScanEnabled ? "ON" : "OFF") << endl;
         cout << "----------------------------------------" << endl;
         cout << "Press Enter to continue...";
         cin.ignore(); cin.get(); // Pauses so the user can actually read the message
}
    


        else if (choice == 7)
        {
            break;
        }
    }
    return 0;
}
