#ifndef _INTRIGUER_UTILS_HPP_
#define _INTRIGUER_UTILS_HPP_

#include <vector>
#include <string>
#include <sys/time.h>

using namespace std;

unsigned long long strToUll(string value, int size);

unsigned long long strToUllRev(string value, int size);

string ullToStr(unsigned long long value, int size);

string reversePairs(string const & src);

void fromHex(const std::string &in, void *const data);

uint64_t getTimeStamp();

template <typename T>
void delete_pointed_to(T* const ptr)
{
    delete ptr;
}

#endif