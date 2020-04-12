#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <cmath>

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include "traceAnalyzer.hpp"
#include "utils.hpp"
#include "trace.hpp"
#include "operand.hpp"
#include "field.hpp"
#include "fieldValue.hpp"
#include "reduction.hpp"
#include "logging.hpp"

using namespace std;

#define MAX_TRACE_LINE 1000000

vector<Field*> gFields;
vector<Trace*> gTraces;
vector<string> gInsDisList;
vector<CheckWideRange*> gCheckList;

ofstream output;

int insCount = 0;
int constraintQueryCount = 0;
int boundaryQueryCount = 0;
int constraintSolvingTime = 0;
int boundarySolvingTime = 0;
int constraint_time = 0; 
int boundary_time = 0;

int total_cmp = 0;
int simple_cmp = 0;
int simple_add = 0;
int simple_mul = 0;
int simple_sub = 0;
int un_add = 0;
int un_sub = 0;
int un_mul = 0;
int total_add = 0;
int total_sub = 0;
int total_mul = 0;

int skipCount = 0;
int unsupportedCount = 0;

bool SKIP_CONSTRAINT = false;
bool SKIP_BOUNDARY = false;
bool DISABLE_SIMPLE = false;

int initReduction(Trace* trace){
    int newTraceCount = 0;

    string insDis = trace->getInsDis();
    int insAddr = strToUll(trace->getInsAddress().substr(2, sizeof(int)*2), sizeof(int));

    vector<string>::iterator it;

    it = find(gInsDisList.begin(), gInsDisList.end(), insDis);

    if(it == gInsDisList.end()){
        gInsDisList.push_back(insDis);
    }

    // grouping by instruction address
    vector<CheckWideRange*>::iterator itCheck;

    // find checkList by insAddress
    for(itCheck = gCheckList.begin(); itCheck != gCheckList.end(); itCheck++){
        if((*itCheck)->getInsAddr() == insAddr)
            break;
    }

    CheckWideRange* check;

    // new CheckWideRange
    if(itCheck == gCheckList.end()){
        check = new CheckWideRange(insDis, insAddr);
        gCheckList.push_back(check);
    }
    else{
        check = (*itCheck);  
    }

    vector<string> offsets = trace->getOffsets();

    // TODO: >2 operands
    if(offsets[0].find("0x") != string::npos){
        check->addOffsetsOp1(offsets[0]);
        check->addTrace(trace);
        newTraceCount = 1;
    }

    if (offsets.size() >= 2){
        if(offsets[1].find("0x") != string::npos){
            check->addOffsetsOp2(offsets[1]);
            
            if(newTraceCount == 0){
                check->addTrace(trace);
                newTraceCount = 1;
            }
        }
    }

    return newTraceCount;
}

int parseTrace(ifstream& traceList){
    int newTraceCount = 0;
    int traceId = 0;
    int traceCount = 0;

    string strTrace;

    while(getline(traceList, strTrace)){
        if(traceCount > MAX_TRACE_LINE) break;
        
        traceCount++;
        
        Trace* trace = new Trace(traceId, strTrace);
        vector<string>::iterator it;

        traceId++;

        vector<string> offsets = trace->getOffsets();
        
        bool isContinuous = false;

        // ignore trace with non continuous offset
        for(it = offsets.begin(); it != offsets.end(); it++){
            Field field(*it);

            if(field.getSize() > 0){
                isContinuous = true;
            }
        }

        if(isContinuous == true){
            newTraceCount += initReduction(trace);
        }
        else{
            delete trace;
        }
    }

    cout << dec << "[TraceAnalyzer] total trace count: " << traceCount << endl; 

    return newTraceCount;
}

void doReduction(){
    vector<CheckWideRange*>::iterator itCheck;

    for(itCheck = gCheckList.begin(); itCheck != gCheckList.end(); ){
        if((*itCheck)->doReduction()){
            itCheck = gCheckList.erase(itCheck);
        }
        else{
            itCheck++;
        }
    }
}

void parseField(){
    vector<Trace*>::iterator itIns;

    for(itIns = gTraces.begin(); itIns != gTraces.end(); ){
        // skip mov instruction
        if((*itIns)->getIns().find("mov") == string::npos){
            (*itIns)->makeField();

            itIns++;
        }
        else{
            delete *itIns;
            itIns = gTraces.erase(itIns);
        }
    }
}

void initFields(vector<unsigned char> inputData){
    vector<Field*>::iterator itField;

    for(itField = gFields.begin(); itField != gFields.end(); itField++){
        (*itField)->initOriginValue(inputData);
    }
}

void printFieldTree(){
    vector<Field*>::iterator itField;

    for(itField = gFields.begin(); itField != gFields.end(); itField++){
        Field* field = *itField;

        vector<FieldValue*> fVal = field->getFieldValues();
        vector<FieldValue*>::iterator itFVal;

        if(field->getSize() > MIN_FIELD_SIZE){
            stringstream ss;

            ss << "field start: " << field->getStart();
            LOG_DEBUG(ss.str());

            ss << " size: " << field->getSize()  << " fVal size: " << fVal.size() << endl;
            LOG_DEBUG(ss.str());

            for(itFVal = fVal.begin(); itFVal != fVal.end(); itFVal++){
                (*itFVal)->print();
            }
        }
    }
}

void makeFieldTree(){
    vector<Field*>::iterator itField;

    for(itField = gFields.begin(); itField != gFields.end(); itField++){
        Field* field = *itField;
        
        field->makeFieldTree();
    }

    cout << "[FieldTree] Field Transition Tree Generation Finished." << endl;
    cout << "[FieldTree] " << skipCount << " instructions are skipped" << endl;
    cout << "[FieldTree] " << unsupportedCount << " instructions are unsupported" << endl;
}

void getInterestingValue(){
    vector<Field*>::iterator itField;

    for(itField = gFields.begin(); itField != gFields.end(); itField++){
        (*itField)->getInterestingValue();
    }
}

int main(int argc, char** argv){
    if(argc < 4){
        cout << "usage: ./field [trace file] [input data] [output file]" << endl;
        exit(1);
    }

    if(getenv("INTRIGUER_SKIP_CONSTRAINT")) SKIP_CONSTRAINT = true;
    if(getenv("INTRIGUER_SKIP_BOUNDARY")) SKIP_BOUNDARY = true;
    if(getenv("INTRIGUER_DISABLE_SIMPLE")) DISABLE_SIMPLE = true;

    output.open(argv[3]);

    std::ifstream input(argv[2], std::ios::binary);

    // copies all data into buffer
    vector<unsigned char> inputData((istreambuf_iterator<char>(input)), (istreambuf_iterator<char>()));

    ifstream traceList;

    // read trace file
    traceList.open(argv[1], ios::in);

    int newTraceCount;

    newTraceCount = parseTrace(traceList);

    cout << dec << "[Trace Reduce] before instruction count: " << gCheckList.size() << endl;
    cout << dec << "[Trace Reduce] before trace count: " << newTraceCount << endl;  

    // find instuction using wide-range input
    doReduction();

    cout << "[Trace Reduce] Finished." << endl;
    cout << dec << "[Trace Reduce] after instruction count: " << gCheckList.size() << endl;
    cout << dec << "[Trace Reduce] after trace count: " << gTraces.size() << endl;

    gCheckList.clear();

    cout << "[Parse Field] before ins count: " << gTraces.size() << endl;

    parseField();

    cout << "[Parse Field] after ins count: " << gTraces.size() << endl;
    cout << "[Parse Field] Finished." << endl;

    sort(gFields.begin(), gFields.end(), compare);

    cout << "[Make Field] Finished." << endl;

    initFields(inputData);

    makeFieldTree();

    // print field transition tree
    // printFieldTree();

    // get interesting value
    getInterestingValue();

    cout << dec << "[Constraint Generation] query count: " << constraintQueryCount;
    cout << " time: " << constraint_time << " solving time: " << constraintSolvingTime << endl;

    cout << dec << "[Boundary Generation] query count: " << boundaryQueryCount;
    cout << " time: " << boundary_time << " solving time: " << boundarySolvingTime << endl;

    cout << dec << "[RESULT] total cmp: " << total_cmp << " simple cmp: " << simple_cmp << endl;
    cout << dec << "[RESULT] total add: " << total_add << " simple add: " << simple_add;
    cout << dec << " unsat add: " << un_add << endl;
    cout << dec << "[RESULT] total sub: " << total_sub << " simple sub: " << simple_sub;
    cout << dec << " unsat sub: " << un_sub << endl;
    cout << dec << "[RESULT] total mul: " << total_mul << " simple mul: " << simple_mul;
    cout << dec << " unsat mul: " << un_mul << endl;

    output.close();

    for_each(gFields.begin(), gFields.end(), delete_pointed_to<Field>);
    gFields.clear();

    for_each(gTraces.begin(), gTraces.end(), delete_pointed_to<Trace>);
    gTraces.clear();

    return 0;
}