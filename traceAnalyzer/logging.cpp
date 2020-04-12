#include <iostream>

#include "logging.hpp"

using namespace std;

void log(const char* tag, const string &msg) {
    string tagged_msg = string("[") + tag + "] " + msg;

    cout << tagged_msg << endl;
}

void LOG_DEBUG(const string &msg){
    if(getenv("INTRIGUER_DEBUG"))
        log("DEBUG", msg);
}