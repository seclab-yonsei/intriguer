#include <string>
#include <vector>

#include "reduction.hpp"
#include "logging.hpp"

using namespace std;

CheckWideRange::CheckWideRange(string insDis, int insAddr){
    this->insDis = insDis;
    this->insAddr = insAddr;

    if(getenv("INTRIGUER_REDUCTION_THRESHOLD")){
        reductionThreshold = stoi(getenv("INTRIGUER_REDUCTION_THRESHOLD"));
    }
}

CheckWideRange::~CheckWideRange(){
    this->offsetsOp1.clear();
    this->offsetsOp2.clear();

    vector<Trace*>::iterator itTraces;

    for(itTraces = this->traces.begin(); itTraces != this->traces.end(); itTraces++){
        delete *itTraces;
    }

    this->traces.clear();
}

bool CheckWideRange::doReduction(){
    vector<Trace*> checkTraces = this->getTraces();

    if((!this->isWideRangeOp1() && !this->isWideRangeOp2()) || getenv("INTRIGUER_NOREDUCTION")){
        gTraces.insert(gTraces.end(), checkTraces.begin(), checkTraces.end());
        
        return false;
    } else {
        stringstream debug;
        debug << hex << "[Trace Reduce] \tinsAddr: 0x" << this->getInsAddr() << " insDis: " << this->getInsDis();
        debug << dec << ", " << checkTraces.size()  << " traces are removed.";
        
        LOG_DEBUG(debug.str());

        if (checkTraces.size() < recoverSize) gTraces.insert(gTraces.end(), checkTraces.begin(), checkTraces.end());
        else gTraces.insert(gTraces.end(), checkTraces.begin(), checkTraces.begin()+recoverSize);

        return true;
    }
}

bool CheckWideRange::isWideRange(vector<string> offsets){
    if(offsets.size() == 0) return false;

    int start = 0;
    vector<int> tempOffsets;
    vector<string>::iterator it;

    for(it = offsets.begin()+1; it != offsets.end(); it++){
        start = Field(*it).getStart();

        if(find(tempOffsets.begin(), tempOffsets.end(), start) == tempOffsets.end()) 
            tempOffsets.push_back(start);

        if(tempOffsets.size() > reductionThreshold)
            return true;
    }

    return false;
}

bool CheckWideRange::isWideRangeOp1(){
    return this->isWideRange(offsetsOp1);
}

bool CheckWideRange::isWideRangeOp2(){
    return this->isWideRange(offsetsOp2);
}