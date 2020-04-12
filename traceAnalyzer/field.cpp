#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <cmath>

#include "traceAnalyzer.hpp"
#include "utils.hpp"
#include "field.hpp"
#include "logging.hpp"

using namespace std;

bool compare(const Field* field1, const Field* field2){
    if(field1->getSize() != field2->getSize()){
        return (field1->getSize() < field2->getSize());
    } else {
        return (field1->getStart() < field2->getStart());
    }
}

bool compareFieldTrace(const FieldTrace* ft1, const FieldTrace* ft2){
    Trace* t1 = ft1->getTrace();
    Trace* t2 = ft2->getTrace();

    return t1->getId() < t2->getId();
}

vector<Field*>::iterator findField(const Field field){
    vector<Field*>::iterator it;

    for(it = gFields.begin(); it != gFields.end(); it++){
        if(((*it)->getStart() == field.getStart()) &&
            (*it)->getSize() == field.getSize())
            break;
    }

    return it;
}

vector<Field*>::iterator findField(const Field* const field){
    vector<Field*>::iterator it;

    for(it = gFields.begin(); it != gFields.end(); it++){
        if(((*it)->getStart() == field->getStart()) &&
            (*it)->getSize() == field->getSize())
            break;
    }

    return it;
}

Field::Field(){

}

Field::Field(string strOffsets){
    strOffsets = strOffsets.substr(1, strOffsets.size() - 2);

    string strOffset; 
    string::size_type sz = 0;

    istringstream ss(strOffsets); 

    this->start = -1;
    this->size = 0;
    this->endian = BIG;
    this->end = 0;

    this->constraintCount = 0;
    this->boundaryCount = 0;

    int direction = 0;

    while(getline(ss, strOffset, ',')) {
        if(!strOffset.empty()){
            unsigned long long offset = stoull(strOffset, &sz, 0);

            // first offset
            if(this->start == -1){
                this->start = offset;
                this->end = offset;
                this->size = 1;
            }
            // increse offset
            else if(this->end + 1 == (int)offset && direction != -1)
            {
                direction = 1;

                this->end = offset;
                this->size++;
            }
            //decrese offset
            else if(this->end - 1 == (int)offset && direction != 1)
            {
                direction = -1;

                this->end = offset;
                this->size++;
                this->endian = LITTLE;
            }
            else
            {
                if(size >= MIN_FIELD_SIZE && size <= MAX_FIELD_SIZE){
                    break;
                }

                this->size = -1; // not a field
                return ;
            }
        }
    }

    if(this->endian == LITTLE){
        this->start = this->end;
        this->end = this->start + this->size;
    }
}

Field::Field(OperandField* operandField){
    this->start = operandField->getStart();
    this->end = operandField->getEnd();
    this->size = operandField->getSize();
    this->endian = operandField->getEndian();

    this->constraintCount = 0;
    this->boundaryCount = 0;
}

Field::~Field(){
    vector<FieldTrace*>::iterator it;

    for(it = traces.begin(); it != traces.end(); it++){
        delete *it;
    }

    traces.clear();

    vector<FieldValue*>::iterator itFv;

    for(itFv = fieldValues.begin(); itFv != fieldValues.end(); itFv++){
        delete *itFv;
    }

    fieldValues.clear();
}

void Field::initOriginValue(vector<unsigned char> inputData){
    int start = this->getStart();
    int size = this->getSize();

    vector<FieldTrace*> ft = this->getTraces();

    //set original value
    string value;

    for(int i=0; i < size; i++){
        stringstream ss;

        ss << setfill('0') << setw(2) << hex << (int)inputData[start+i];
        value.append(ss.str());
    }

    this->setOriginalValue(value);
    
    sort(ft.begin(), ft.end(), compareFieldTrace);
}

void Field::addTrace(Trace* trace, int index){
    if(!this->isTraceExist(trace)){
        this->traces.push_back(new FieldTrace(trace, index));
    }
}

// [TODO] check side-effect
bool Field::isTraceExist(Trace* trace){
    vector<FieldTrace*>::iterator it;

    for(it = this->traces.begin(); it != this->traces.end(); it++){
        if((*(*it)->getTrace()) == *trace){
            return true;
        }
    }

    return false;
}

bool Field::isInterestValueExist(string value){
    if(this->isMarkerExist(value) || 
        this->isConstraintExist(value) ||
        this->isConditionBoundaryExist(value) ||
        this->isArithmeticBoundaryExist(value)){
        return true;
    }
    
    return false;
}

bool Field::isMarkerExist(string value){
    vector<string>::iterator i;

    for(i = markers.begin(); i != markers.end(); i++){
        if((*i) == value)
            return true;
    }

    return false;
}

bool Field::isConstraintExist(string value){
    vector<string>::iterator i;

    for(i = constraints.begin(); i != constraints.end(); i++){
        if((*i) == value)
            return true;
    }

    return false;
}

bool Field::isConditionBoundaryExist(string value){
    vector<string>::iterator i;

    for(i = conditionBoundaries.begin(); i != conditionBoundaries.end(); i++){
        if((*i) == value)
            return true;
    }

    return false;
}

bool Field::isArithmeticBoundaryExist(string value){
    vector<string>::iterator i;

    for(i = arithmeticBoundaries.begin(); i != arithmeticBoundaries.end(); i++){
        if((*i) == value)
            return true;
    }

    return false;
}

FieldValue* Field::getFieldValue(string value) {
    vector<FieldValue*>::iterator it;
    FieldValue* fv = NULL;

    for(it = this->fieldValues.begin(); it != this->fieldValues.end(); it++){
        if(!(*it)->getValue().compare(value)){
            fv = *it;
        }
    }

    // return last field value
    return fv;
}

FieldValue* Field::getNearFieldValue(string value, int addr) {
    vector<FieldValue*>::iterator it;
    FieldValue* fv = NULL;
    unsigned int distance = 0xffffffff;

    for(it = this->fieldValues.begin(); it != this->fieldValues.end(); it++){
        if(!(*it)->getValue().compare(value) && !(*it)->getIsOpt()){
            if(abs((*it)->getTrace()->getAddress() - addr) < distance){
                distance = abs((*it)->getTrace()->getAddress() - addr);
                // [TODO] heuristic distance
                if(distance < 0x10000){
                    fv = *it;
                }
            }
        }
    }

    // return last field value
    return fv;
}

void Field::addFieldValue(FieldValue* fv){
    if(!this->isFieldValueExist(fv)){
        this->fieldValues.push_back(fv);
    }
    else{
        delete fv;
    }
}

bool Field::isFieldValueExist(FieldValue* fv){
    vector<FieldValue*>::iterator it;

    for(it = this->fieldValues.begin(); it != this->fieldValues.end(); it++){
        FieldValue* curFv = *it;

        if(*curFv == *fv){
            return true;
        }
    }

    return false;
}

void Field::printOutput(vector<string> values){
    vector<string>::iterator itStr;

    for(itStr = values.begin(); itStr != values.end(); itStr++){
        if((*itStr).at(0) == ':')
            output << (*itStr);
        else
            output << (*itStr).substr(0, this->size * 2);

        if(itStr+1 == values.end()) break;

        output << ",";
    }
}

void Field::printOutput(){
    if(this->markers.size() == 0 && this->constraints.size() == 0  
        && this->conditionBoundaries.size() == 0 && this->arithmeticBoundaries.size() == 0)
        return;
    if(this->start < 0) 
        return;

    output << this->start << "\t" << this->size << "\t";

    vector<string>::iterator itStr;

    output << "M";

    this->printOutput(this->markers);

    output << "\tC";

    this->printOutput(this->constraints);

    output << "\tB";

    this->printOutput(this->conditionBoundaries);

    output << "\tI";

    this->printOutput(this->arithmeticBoundaries);

    output << endl;
}

void Field::printCout(vector<unsigned char> inputData){
    cout << "start: " << this->getStart() << "\tsize: " << this->getSize() << "\t" << endl;
    cout << "orig value: ";

    for(int j=0; j < this->getSize(); j++){
        printf("%02x", (unsigned int)inputData[this->getStart() + j]);
        cout << hex << (unsigned int)inputData[this->getStart() + j];
    }

    cout << endl;

    vector<FieldTrace*> fieldTraces = this->getTraces();
    vector<FieldTrace*>::iterator itFT;

    sort(fieldTraces.begin(), fieldTraces.end(), compareFieldTrace);

    for(itFT = fieldTraces.begin(); itFT != fieldTraces.end(); itFT++){
        Trace* trace = (*itFT)->getTrace();
        int index = (*itFT)->getIndex();

        cout << "\t\t"  << trace->getId() << " " << trace->getInsDis() << " \t";
        cout << "endian: " << trace->getEndianStr() << "\t";

        trace->printOperands();
        
        cout << " tainted op: " << index;
        cout << endl;
    }
}

void Field::makeFieldValue(FieldTrace* ft, FieldValue* fieldValue, bool isOpt){
    Trace* trace = ft->getTrace();
    int index = ft->getIndex();

    string ins = trace->getIns();
    vector<Operand*> operands = trace->getOperands();

    vector<int> vecOpSize;
    vector<unsigned long long> vecOpInt;

    for(uint32_t i = 0; i < operands.size(); i++){
        vecOpSize.push_back(operands[i]->getSize());
        vecOpInt.push_back(operands[i]->getValueInt(vecOpSize.at(i)));
    }

    uint64_t result = 0;

    int resultSize = vecOpSize[0];

    if(operands.size() == 2) 
        resultSize = (vecOpSize[0] > vecOpSize[1]) ? vecOpSize[0] : vecOpSize[1];

    if(operands.size() == 3)
        resultSize = (resultSize > vecOpSize[2]) ? resultSize : vecOpSize[2];

    if(!ins.compare("add")){
        if ((index == 0 && vecOpInt[1] == 0) || 
            (index == 1 && vecOpInt[0] == 0)){

        } else {
            result = vecOpInt[0] + vecOpInt[1];
            
            string strResult = ullToStr(result, resultSize);

            this->addFieldValue(new FieldValue(trace, index, strResult, fieldValue, isOpt));
        }
    }
    else if(!ins.compare("imul"))
    {
        if(operands.size() == 3){
            if(index == 1 || index == 2){
                result = (signed)vecOpInt[1] * (signed)vecOpInt[2];

                string strResult = ullToStr(result, resultSize);

                this->addFieldValue(new FieldValue(trace, index, strResult, fieldValue, isOpt));
            }
        }
        else if(operands.size() == 2){
                result = (signed)vecOpInt[0] * (signed)vecOpInt[1];

                string strResult = ullToStr(result, resultSize);

                this->addFieldValue(new FieldValue(trace, index, strResult, fieldValue, isOpt));
        }
    }
    else if(!ins.compare("cmp") || ins.find("cmps") != string::npos || 
            !ins.compare("test") || ins.find("pcmp") != string::npos)
    {
        int tOperandSize = operands[index]->getSize();

        string strResult = operands[index]->getValue(tOperandSize);

        FieldValue* fv = new FieldValue(trace, index, strResult, fieldValue, isOpt);

        this->addFieldValue(fv);
    } 
    else {
        if(!ins.compare("not"))
            result = ~vecOpInt[0];
        else if(!ins.compare("inc"))
            result = vecOpInt[0] + 1;
        else if(!ins.compare("dec"))
            result = vecOpInt[0] - 1;
        else if(!ins.compare("add") || !ins.compare("adc"))
            result = vecOpInt[0] + vecOpInt[1];
        else if(!ins.compare("sub") || !ins.compare("sbb"))
            result = vecOpInt[0] - vecOpInt[1];
        else if(!ins.compare("shl"))
            result = vecOpInt[0] << vecOpInt[1];
        else if(!ins.compare("shr"))
            result = vecOpInt[0] >> vecOpInt[1];
        else if(!ins.compare("sar"))
            result = (signed)vecOpInt[0] >> (signed)vecOpInt[1];
        else if(!ins.compare("sal"))
            result = (signed)vecOpInt[0] << (signed)vecOpInt[1];
        else if(!ins.compare("and"))
            result = vecOpInt[0] & vecOpInt[1];
        else if(!ins.compare("or"))
            result = vecOpInt[0] | vecOpInt[1];
        else if(!ins.compare("xor"))
            result = vecOpInt[0] ^ vecOpInt[1];
        else if(!ins.compare("mul"))
            result = (unsigned)vecOpInt[0] * (unsigned)vecOpInt[1];
        else if(!ins.compare("ror"))
            result = (vecOpInt[0] >> vecOpInt[1]) | (vecOpInt[0] << (vecOpSize[0] * 8 - vecOpInt[1]));
        else if(!ins.compare("rol"))
            result = (vecOpInt[0] << (vecOpSize[0] * 8 - vecOpInt[1])) | (vecOpInt[0] >> vecOpInt[1]);
        else if(!ins.compare("div"))
            result = (unsigned)vecOpInt[0] / (unsigned)vecOpInt[1];
        else if(!ins.compare("idiv"))
            result = (signed)vecOpInt[0] / (signed)vecOpInt[1];
        else{
            LOG_DEBUG("[MakeFieldTree] unsupported instruction: " + ins);
            unsupportedCount++;
            return;
        }

        string strResult = ullToStr(result, resultSize);
        
        this->addFieldValue(new FieldValue(trace, index, strResult, fieldValue, isOpt));
    }
}

void Field::makeFieldTree(){
    vector<FieldTrace*> vecFieldTrace = this->getTraces();
    vector<FieldTrace*>::iterator itFT;

    sort(vecFieldTrace.begin(), vecFieldTrace.end(), compareFieldTrace);

    vector<FieldTrace*> doneTrace;

    for(itFT = vecFieldTrace.begin(); itFT != vecFieldTrace.end(); itFT++){
        if(find(doneTrace.begin(), doneTrace.end(), *itFT) != doneTrace.end()) {
            skipCount++;
            continue;
        }

        FieldTrace* fieldTrace = *itFT;

        doneTrace.push_back(fieldTrace);

        Trace* trace = fieldTrace->getTrace();
        int index = fieldTrace->getIndex();

        vector<Operand*> operands = trace->getOperands();

        string orig = this->getOrignalValue();

        if(trace->getEndian() == LITTLE){
            orig = reversePairs(orig);
        }

        FieldValue* fieldValue = NULL;
        string taintValue = operands[index]->getValue(operands[index]->getSize());
        int offset = operands[index]->getFieldOffset(this->start, this->size);

        bool isNewFv = false;

        if((fieldValue = this->getNearFieldValue(taintValue, trace->getAddress())) != NULL){
            isNewFv = true;

            this->makeFieldValue(fieldTrace, fieldValue, false);
        }

        if(!taintValue.substr(offset*2, this->size*2).compare(orig)){
            if(isNewFv == true){
                this->makeFieldValue(fieldTrace, NULL, true);
            }
            else{
                isNewFv = true;
                this->makeFieldValue(fieldTrace, NULL, false);
            }
        }

        if (isNewFv == false) skipCount++;
    }
}

void Field::getInterestingValueComparison(FieldValue* fv){
    Trace* trace = fv->getTrace();
    int index = fv->getIndex();
    vector<Operand*> operands = trace->getOperands();

    // [TODO] checking xor is used for initialize variable
    if(trace->isXor() && operands[(index+1)%2]->isTaintOp()) return;

    total_cmp++;

    vector<string> queryResult;
    vector<string>::iterator itquery;

    if((fv->getPrev() != NULL || DISABLE_SIMPLE) && 
        operands[index]->getFieldValue(start, size) != this->getOrignalValue() && 
        size >= MIN_FIELD_SIZE){
        vector<string> tempResult;

        tempResult = fv->queryInterest(this->getSize());
        queryResult.insert(queryResult.end(), tempResult.begin(), tempResult.end());

        for(itquery = queryResult.begin(); itquery != queryResult.end(); itquery++){
            string interestValue = *itquery;
            if(!this->isInterestValueExist(interestValue)){
                this->addConstraint(interestValue);
            }
        }
    }
    else{
        Operand* operand = NULL;

        if(index == 0){
            operand = operands[1];
        }
        else if(index == 1){
            operand = operands[0];
        }

        Operand* taintOp = operands[index];
        int endian = taintOp->getOperandField(start, size)->getEndian();

        if (endian == LITTLE)
            queryResult.push_back(reversePairs(operand->getValue(size)));
        else
            queryResult.push_back(operand->getValue(size));

        for(itquery = queryResult.begin(); itquery != queryResult.end(); itquery++){
            string interestValue = *itquery;
            if(!this->isInterestValueExist(interestValue)){
                this->addMarker(interestValue);
            }
        }

        queryResult.clear();

        if (endian == LITTLE) {
            // queryResult.push_back(reversePairs(ullToStr(strToUllRev(operand->getValue(size), size)+1, size)));
            // queryResult.push_back(reversePairs(ullToStr(strToUllRev(operand->getValue(size), size)-1, size)));
        }
        else {
            // queryResult.push_back(ullToStr(strToUllRev(operand->getValue(size), size)+1, size));
            // queryResult.push_back(ullToStr(strToUllRev(operand->getValue(size), size)-1, size));

            llvm::APInt tempInt;
            tempInt = llvm::APInt(size*8, operand->getValue(size), 16);
            queryResult.push_back((tempInt+1).toString(16, false));
            queryResult.push_back((tempInt-1).toString(16, false));
        }

        for(itquery = queryResult.begin(); itquery != queryResult.end(); itquery++){
            string interestValue = *itquery;
            if(!this->isInterestValueExist(interestValue)){
                this->addConditionBoundary(interestValue);
            }
        }

        simple_cmp++;
    }
}

void Field::getInterestingValueBoundary(FieldValue* fv){
    Trace* trace = fv->getTrace();
    int index = fv->getIndex();

    vector<string> queryResult;
    vector<string> temp;

    vector<Operand*> operands = trace->getOperands();

    Operand* taintOp = operands[index];
    Operand* operand = NULL;

    if(index == 0){
        operand = operands[1];
    }
    else if(index == 1){
        operand = operands[0];
    }

    if(trace->isOverflowIns()){
        if(trace->isAdd()) total_add++;
        else total_mul++;

        if(trace->isImul() && operands.size() == 3){
            operand = operands[2];
        }

        // unsolvable
        if(operand->getValueInt(operand->getSize()) == 0 && !operand->isTaintOp()){
            if(trace->isAdd()){
                un_add++;
            } else {
                un_mul++;
            }
            return;
        } 
        // uncomplicated
        else if(fv->getPrev() == NULL && !operand->isTaintOp()){
            if(trace->isAdd()){
                simple_add++;

                // signed overflow
                queryResult.push_back(ullToStr((uint64_t) 0x80000000 - operand->getValueInt(operand->getSize()), size));

                //unsigned overflow
                queryResult.push_back(ullToStr((uint64_t) 0x100000000 - operand->getValueInt(operand->getSize()), size));
            } 
            else if (operand->getValueInt(operand->getSize()) != 0){
                simple_mul++;

                // signed overflow
                queryResult.push_back(ullToStr((uint64_t) 0x80000000 / operand->getValueInt(operand->getSize()) + 1, size));

                //unsigned overflow
                queryResult.push_back(ullToStr((uint64_t) 0x100000000 / operand->getValueInt(operand->getSize()) + 1, size));
            }
        }
        else if(this->getBoundaryCount() < MAX_BOUNDARY_COUNT){
            temp = fv->queryInterest(this->getSize());
            queryResult.insert(queryResult.end(), temp.begin(), temp.end());

            this->incBoundaryCount();
            this->incBoundaryCount();
        }
    }
    else if(trace->isUnderflowIns()){
        total_sub++;
        
        if(operand->getValueInt(operand->getSize()) == 0 && !operand->isTaintOp() && index == 0){
            un_sub++;

            return;
        }
        // uncomplicated
        else if(fv->getPrev() == NULL && !operand->isTaintOp()){
            simple_sub++;

            // underflow
            if(index == 0){
                queryResult.push_back(ullToStr(operand->getValueInt(operand->getSize())-1, size));
            }
            else if(index == 1){
                queryResult.push_back(ullToStr(operand->getValueInt(operand->getSize())+1, size));
            }            

            // equal zero
            queryResult.push_back(ullToStr((uint64_t) operand->getValueInt(operand->getSize()), size));            
        }
        else if(this->getBoundaryCount() < MAX_BOUNDARY_COUNT){
            temp = fv->queryInterest(this->getSize());
            queryResult.insert(queryResult.end(), temp.begin(), temp.end());

            this->incBoundaryCount();
            this->incBoundaryCount();
        } 
    }

    vector<string>::iterator itquery;

    for(itquery = queryResult.begin(); itquery != queryResult.end(); itquery++){
        string interestValue = *itquery;
        if(!this->isInterestValueExist(interestValue)){
            this->addArithmeticBoundary(interestValue);
        }
    }
}

void Field::getInterestingValue(){
    string orig = this->getOrignalValue();

    vector<FieldValue*> fVal = this->getFieldValues();
    vector<FieldValue*>::iterator itFVal;

    LOG_DEBUG("[getInterestingValue] field start: " + to_string(this->start) + " size: " + to_string(this->size));

    LOG_DEBUG(" value count: " + to_string(fVal.size()));
    LOG_DEBUG(" orig value: " + orig);

    for(itFVal = fVal.begin(); itFVal != fVal.end(); itFVal++){
        FieldValue* fv = *itFVal;
        Trace* trace = fv->getTrace();

        if((trace->isComparisonIns() || trace->isXor()) && !SKIP_CONSTRAINT){

            int start_time = getTimeStamp();

            this->getInterestingValueComparison(fv);

            int cur_time = getTimeStamp();
            int elapsed = cur_time - start_time;

            constraint_time += elapsed;
        }
        else if(trace->isArithmeticBoundaryIns() && this->size >= MIN_FIELD_SIZE && !SKIP_BOUNDARY){
            int start_time = getTimeStamp();   

            this->getInterestingValueBoundary(fv);
            
            int cur_time = getTimeStamp();
            int elapsed = cur_time - start_time;

            boundary_time += elapsed;
        }
    }

    this->printOutput();
}