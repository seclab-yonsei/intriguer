#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <cmath>

#include "trace.hpp"
#include "traceAnalyzer.hpp"
#include "logging.hpp"

bool compareIns(const Trace* t1, const Trace* t2) {
    return t1->getId() < t2->getId();
}

Trace::Trace(int id, string line){
    string strOffsets, insAddress, insDis, ins, type, operand;

    this->id = id;

    istringstream ss(line); 

    getline(ss, insAddress, '.');
    
    this->insAddress = insAddress;
    this->address = strToUll(insAddress.substr(2, sizeof(int)*2), sizeof(int));

    getline(ss, insDis, '.');

    this->insDis = insDis;
    
    istringstream ssInsDis(insDis);

    getline(ssInsDis, ins, ' ');

    if(!ins.compare("rep"))
        getline(ssInsDis, ins, ' ');

    this->ins = ins;

    // parse operand offsets
    getline(ss, strOffsets, '.');

    this->strOffsets = strOffsets;

    strOffsets = this->strOffsets;

    string offset1 = strOffsets.substr(0, strOffsets.find("}")+1);
    
    // parse first offset
    if(offset1.size() >= 2){
        this->offsets.push_back(offset1);
    }
        
    // parse second offset
    if(strOffsets.size() > offset1.size()){
        string offset2 = strOffsets.substr(offset1.size());

        if(offset2.size() >= 2){
            this->offsets.push_back(offset2);
        }
    }

    // parse operand values
    for(uint32_t i = 0; i < 10; i++){
        getline(ss, operand, '.');

        if(operand.empty()){
            break;
        }

        if(offsets.size() > i){
            this->operands.push_back(new Operand(i, operand, offsets.at(i)));
        } 
        // IMM
        else{
            this->operands.push_back(new Operand(i, operand));
        }
    }
}

Trace::~Trace(){
    vector<Operand*>::iterator itOperand;

    for(itOperand = this->operands.begin(); itOperand != this->operands.end(); itOperand++){
        delete (*itOperand);
    }

    operands.clear();
}

void Trace::makeField(string offset, int operandIndex){
    Field* field = new Field(offset);
    vector<Field*>::iterator it;

    if(field->getSize() > 0){        
        it = findField(field);

        
        if(it == gFields.end())
        {
            // new field
            field->addTrace(this, operandIndex);
            gFields.push_back(field);
        }
        else
        {
            (*it)->addTrace(this, operandIndex);
        }

        this->endian = field->getEndian();
    }
    else
    {
        delete field;
    }
}

void Trace::makeField(){
    vector<Operand*>::iterator itOperand;
    int operandIndex = 0;

    for (itOperand = this->operands.begin(); itOperand != this->operands.end(); itOperand++){
        Operand* op = *itOperand;
        vector<OperandField*> operandFields = op->getFields();
        vector<OperandField*>::iterator itOperandField;

        operandIndex = op->getIndex();

        for(itOperandField = operandFields.begin(); itOperandField != operandFields.end(); itOperandField++){
            OperandField* operandField = *itOperandField;

            if(operandField->getSize() > 0){
                vector<Field*>::iterator itField;
                
                Field localField = Field(operandField);

                itField = findField(localField);

                // new field
                if(itField == gFields.end()){
                    Field* field = new Field(operandField);

                    field->addTrace(this, operandIndex);
                    gFields.push_back(field);
                }
                // exist field
                else{
                    (*itField)->addTrace(this, operandIndex);
                }

                this->endian = localField.getEndian();
            }
        }
    }
}

void Trace::printDebug(){
    stringstream debug;

    debug << "id: " << this->id << " insDis: " << this->insDis << endl;
    
    LOG_DEBUG(debug.str());

    this->printOperands();
    this->printOffsets();
}

void Trace::printOperands(){
    vector<Operand*>::iterator it;
    int i=0;

    stringstream debug;

    for(it = operands.begin(); it != operands.end(); it++){
        debug << " operand" << i << ": " << (*it)->getValue();
        i++;
    }

    LOG_DEBUG(debug.str());
}

void Trace::printOffsets(){
    vector<string>::iterator it;
    int i=0;

    stringstream debug;

    for(it = offsets.begin(); it != offsets.end(); it++){
        debug << "\toffset" << i << ": " << (*it);
        i++;
    }

    LOG_DEBUG(debug.str());
}

bool Trace::isComparisonIns(){
    if(!ins.compare("test") || !ins.compare("cmp") || ins.find("cmps") != string::npos || ins.find("pcmp") != string::npos)
        return true;
    return false;
}

bool Trace::isArithmeticBoundaryIns(){
    if(!ins.compare("add") || !ins.compare("mul") || !ins.compare("imul") || !ins.compare("shl") || !ins.compare("sub"))
        return true;
    return false;
}

bool Trace::isOverflowIns(){
    if(!ins.compare("add") || !ins.compare("mul") || !ins.compare("imul") || !ins.compare("shl"))
        return true;
    return false;
}

bool Trace::isUnderflowIns(){
    if(!ins.compare("sub"))
        return true;
    return false;
}

bool Trace::isAdd(){
    if(!ins.compare("add"))
        return true;
    return false;
}

bool Trace::isImul(){
    if(!ins.compare("imul"))
        return true;
    return false;
}

bool Trace::isXor(){
    if(!ins.compare("xor"))
        return true;
    return false;
}

// TODO: String Comparison
bool Trace::isStringCompare(int size){
    istringstream ssInsDis(this->insDis);
    string ins;
    string op1 = this->operands[0]->getValue();
    string op2 = this->operands[1]->getValue();
    unsigned long long imm;

    getline(ssInsDis, ins, ' ');

    // cmp reg/mem, imm string
    if(!ins.compare("cmp")){
        if(ins.find(",") != string::npos){
            stringstream ss(op2);

            if(op2.find("0x") == string::npos || (ss >> hex >> imm).fail()){
            } else {
                int i;
                // if length of ascii equals with field size
                for(i = 0; i < size; i++){
                    unsigned long long byte = ((imm >> (i*8)) & 0xff);

                    if( (unsigned)byte > 0x7f || (unsigned)byte < 0x20 ){
                        return false;
                    }
                }

                if( i >= 2){
                    string val((char*)&imm);
                    if(this->endian == LITTLE){
                        reverse(val.begin(), val.end());
                    }

                    this->operands[1]->setValue(val);

                    return true;
                }
            }
        }
    }

    //else if(!ins.compare("rep")){
    //  getline(ssInsDis, ins, ' ');

        if(!ins.compare("cmpsb")){
            stringstream ss(op2);

            if(op2.find("0x") == string::npos || (ss >> hex >> imm).fail()){
            } else {
                int i;
                // if length of ascii equals with field size
                for(i = 0; i < size; i++){
                    unsigned long long byte = ((imm >> (i*8)) & 0xff);

                    if((unsigned)byte > 0x7f || (unsigned)byte < 0x20 ){
                        return false;
                    }
                }

                if( i >= 2){
                    string val((char*)&imm);
                    if(this->endian == LITTLE)
                        reverse(val.begin(), val.end());

                    this->operands[1]->setValue(val);
                    return true;
                }
            }

            return true;
        } 
    //}

    return false;
}

// [TODO] compare all information
bool Trace::operator==(const Trace& trace) const {
    vector<Operand*> operands = trace.getOperands(); 

    if(this->operands.size() != operands.size()) return false;
    if(this->insAddress != trace.getInsAddress()) return false;

    for(uint32_t i=0; i<this->operands.size(); i++){
        if(this->operands[i]->getValue().compare(operands[i]->getValue()))
            return false;
    }

    return (this->insDis == trace.getInsDis());
}