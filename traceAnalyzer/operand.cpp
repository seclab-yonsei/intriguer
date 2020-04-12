#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <cmath>

#include "operand.hpp"
#include "field.hpp"
#include "traceAnalyzer.hpp"
#include "logging.hpp"
#include "type.hpp"

using namespace std;

Operand::Operand(){

}

Operand::Operand(int id, string operand){
    this->index = id;
    this->value = operand;
    this->size = operand.length()/2;
    this->isTaint = false;
}

Operand::Operand(int id, string operand, string strOffsets){
    string strOffset;
    strOffsets = strOffsets.substr(1, strOffsets.size()-2);

    this->index = id;
    this->value = operand;
    this->size = operand.length()/2;
    this->isTaint = false;
    
    string::size_type sz = 0;

    istringstream ss(strOffsets); 

    int start = -1;
    int size = 0;
    int endian = BIG;
    int end = 0;

    int direction = 0;
    int operandOffset = 0;

    while(getline(ss, strOffset, ',')){    
        if(!strOffset.empty()){
            unsigned long long offset = stoull(strOffset, &sz, 0);

            // first offset
            if(start == -1){
                start = offset;
                end = offset;
                size = 1;
            }
            // increse offset
            else if(end + 1 == (int)offset && direction != -1)
            {
                direction = 1;

                end = offset;
                size++;
            }
            //decrese offset
            else if(end - 1 == (int)offset && direction != 1)
            {
                direction = -1;

                end = offset;
                size++;
                endian = LITTLE;
            }
            else
            {
                if(size >= MIN_FIELD_SIZE && size <= MAX_FIELD_SIZE){
                    if(endian == LITTLE){
                        start = end;    
                        end = start + size;
                    }

                    if(size == 1){
                        start = offset;
                        end = offset;
                    }

                    // TODO
                    if (start >= 0){
                        this->operandFields.push_back(new OperandField(start, end, size, operandOffset-size, endian));
                        this->isTaint = true;
                    }
                }

                start = offset;
                size = 1;
                endian = BIG;
                end = offset;
                direction = 0;
            }
        } else {
            if(start != -1 && size >= MIN_FIELD_SIZE && size <= MAX_FIELD_SIZE){
                if(endian == LITTLE){
                    start = end;    
                    end = start + size;
                }

                // TODO
                if (start >= 0){
                    this->operandFields.push_back(new OperandField(start, end, size, operandOffset-size, endian));
                    this->isTaint = true;
                }
            }

            start = -1;
            size = 1;
            endian = BIG;
            end = 0;
            direction = 0;
        }

        operandOffset++;
    }

    if(endian == LITTLE){
        start = end;    
        end = start + size;
    }

    if(size >= MIN_FIELD_SIZE && size <= MAX_FIELD_SIZE){       
        // TODO
        if (start >= 0){
            this->operandFields.push_back(new OperandField(start, end, size, operandOffset-size, endian));
            this->isTaint = true;
        }
    }
}

Operand::~Operand(){
    vector<OperandField*>::iterator it;

    for(it = this->operandFields.begin(); it != this->operandFields.end(); it++){
        delete (*it);
    }

    this->operandFields.clear();
}

int Operand::getFieldOffset(int start, int size) {
    vector<OperandField*>::iterator it;

    for(it = this->operandFields.begin(); it != this->operandFields.end(); it++){
        if((*it)->getSize() == size && (*it)->getStart() == start){
            return (*it)->getOffset();
        }
    }

    return -1;
}

OperandField* Operand::getOperandField(int start, int size) {
    vector<OperandField*>::iterator it;

    for(it = this->operandFields.begin(); it != this->operandFields.end(); it++){
        if((*it)->getSize() == size && (*it)->getStart() == start){
            return (*it);
        }
    }

    return NULL;
}

string Operand::getFieldValue(int start, int size) {
    vector<OperandField*>::iterator it;

    OperandField* operandField = this->getOperandField(start, size);

    string result;
    int offset = operandField->getOffset();

    if (offset != -1) {
        result = this->value.substr(offset*2, size*2);
    }
    else {
        return NULL;
    }

    if (operandField->getEndian() == LITTLE) 
        result = reversePairs(result);

    return result;
}

OperandField::OperandField(){

}

OperandField::OperandField(int start, int end, int size, int offset, int endian){
    this->start = start;
    this->end = end;
    this->size = size;
    this->offset = offset;
    this->endian = endian;
}

OperandField::~OperandField(){

}
