#ifndef INTRIGUER_OPERAND_HPP_
#define INTRIGUER_OPERAND_HPP_

#include <vector>
#include <algorithm>
#include <iostream>
#include "utils.hpp"

using namespace std;

class OperandField{
private:
    int start, end, size, offset, endian;

public:
    OperandField();
    OperandField(int start, int end, int size, int offset, int endian);

    ~OperandField();

    int getStart() const {return this->start;}
    int getEnd() const {return this->end;}
    int getSize() const {return this->size;}
    int getOffset() const {return this->offset;}
    int getEndian() const {return this->endian;}
};

class Operand{
private:
    int index, size;
    vector<OperandField*> operandFields;
    bool isTaint;
    string value;

public:
    Operand();
    Operand(int index, string operand);
    Operand(int index, string operand, string strOffset);

    ~Operand();

    void setIndex(int index) {this->index = index;}
    void setValue(string value) {this->value = value;}
    void setSize(int size) {this->size = size;}

    bool isTaintOp() const {return this->isTaint;}

    int getIndex() const {return this->index;}
    int getSize() const {return this->size;}

    string getValue() const {return this->value;}
    string getValue(int size) const {return this->value.substr(0, size * 2);}

    // TODO: >16 byte operands
    unsigned long long getValueInt(int size) const {
        if(size > 8) size = 8;

        string stringValue = this->value.substr(0, size * 2);

        unsigned long long intValue = stoull(stringValue , NULL, 16);
        reverse((char*)&intValue, ((char*)&intValue)+size);

        return intValue;
    }

    vector<OperandField*> getFields() const {return this->operandFields;}
    OperandField* getOperandField(int start, int size);

    int getFieldOffset(int start, int size);
    string getFieldValue(int start, int size);
};

#endif
