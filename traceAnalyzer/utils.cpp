#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <assert.h>

#include "utils.hpp"

using namespace std;

const uint64_t kUsToS = 1000000;

unsigned long long strToUll(string value, int size){
    string stringValue = value.substr(0, size*2);

    unsigned long long intValue = stoull(stringValue , NULL, 16);
    //reverse((char*)&intValue, ((char*)&intValue)+size);
    return intValue;
}

unsigned long long strToUllRev(string value, int size){
    string stringValue = value.substr(0, size*2);

    unsigned long long intValue = stoull(stringValue , NULL, 16);
    reverse((char*)&intValue, ((char*)&intValue)+size);
    return intValue;
}

string ullToStr(unsigned long long value, int size){
    string result;
/*
    ss << hex << value;
    ss >> result;

    for(int i=0; result.size() < size*2; i++){
        result = "0" + result;
    }
*/

    for(int i=0; i < size; i++){
        stringstream ss;

        ss << setfill ('0') << setw(2) << hex << (int)((unsigned char*)&value)[i];
        result.append(ss.str());
        
    }

    //reverse(result.begin(), result.end());

    return result.substr(0, size*2);
}

string reversePairs(std::string const & src)
{
    assert(src.size() % 2 == 0);
    string result;
    result.reserve(src.size());

    for (std::size_t i = src.size(); i != 0; i -= 2)
    {
        result.append(src, i - 2, 2);
    }

    return result;
}

void fromHex(const std::string &in, void *const data){
    size_t length = in.length();
    unsigned char *byteData = reinterpret_cast<unsigned char*>(data);

    std::stringstream hexStringStream; hexStringStream >> std::hex;
    for(size_t strIndex = 0, dataIndex = 0; strIndex < length; ++dataIndex)
    {
        // Read out and convert the string two characters at a time
        const char tmpStr[3] = { in[strIndex++], in[strIndex++], 0 };

        // Reset and fill the string stream
        hexStringStream.clear();
        hexStringStream.str(tmpStr);

        // Do the conversion
        int tmpValue = 0;
        hexStringStream >> tmpValue;
        byteData[dataIndex] = static_cast<unsigned char>(tmpValue);
    }
}

uint64_t getTimeStamp() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec * kUsToS + tv.tv_usec;
}