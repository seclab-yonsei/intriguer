#ifndef INTRIGUER_REDUCTION_HPP_
#define INTRIGUER_REDUCTION_HPP_

#include <string>
#include <vector>

#include "trace.hpp"

using namespace std;

class CheckWideRange{
private:
    string insDis;
    int insAddr;
    vector<Trace*> traces;
    vector<string> offsetsOp1, offsetsOp2;

    const uint32_t  recoverSize = 8;
    uint32_t reductionThreshold = 16;

public:
    CheckWideRange(string insDis, int insAddr);
    ~CheckWideRange();

    string getInsDis() const {return this->insDis;}
    int getInsAddr() const {return this->insAddr;}

    vector<Trace*> getTraces() const {return this->traces;}

    void addOffsetsOp1(string offsets){this->offsetsOp1.push_back(offsets);}
    void addOffsetsOp2(string offsets){this->offsetsOp2.push_back(offsets);}
    void addTrace(Trace* trace){this->traces.push_back(trace);}

    bool doReduction();

    bool isWideRange(vector<string> offsets);
    bool isWideRangeOp1();
    bool isWideRangeOp2();

    void clearTraces();
};

extern vector<Trace*> gTraces;

#endif