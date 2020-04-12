#ifndef INTRIGUER_FIELD_HPP_
#define INTRIGUER_FIELD_HPP_

#include <string>
#include <vector>

#include "trace.hpp"
#include "fieldValue.hpp"

using namespace std;

#define MAX_FIELD_SIZE 16
#define MIN_FIELD_SIZE 2 

#define MAX_BOUNDARY_COUNT 100 

class Trace;
class FieldValue;

class FieldTrace{
private:
    Trace* trace;
    int index;

public:
    FieldTrace(Trace* trace, int index){
        this->trace = trace;
        this->index = index;
    }

    ~FieldTrace(){
        
    }

    Trace* getTrace() const {return this->trace;}
    int getIndex() const {return this->index;}

    void setTrace(Trace* trace){this->trace = trace;}
    void setIndex(int index){this->index = index;}
};

class Field{
private:
    int start, end, size, endian; // little endian = 1
    vector<FieldTrace*> traces;
    vector<string> markers;
    vector<string> constraints;
    vector<string> conditionBoundaries;
    vector<string> arithmeticBoundaries;
    vector<FieldValue*> fieldValues;

    string orignalValue;

    int constraintCount;
    int boundaryCount;

public:
    Field();
    Field(int start, int end, int size);
    Field(string strOffset);
    Field(OperandField* operandField);
    ~Field();

    int getStart() const {return this->start;}
    int getSize() const {return this->size;}
    int getEndian() const {return this->endian;}
    int getConstraintCount() const {return this->constraintCount;}
    int getBoundaryCount() const {return this->boundaryCount;}

    string getOrignalValue() const {return this->orignalValue;}
    
    vector<FieldTrace*> getTraces() const {return this->traces;}


    FieldValue* getFieldValue(string value);
    FieldValue* getNearFieldValue(string value, int addr);
    vector<FieldValue*> getFieldValues() const {return this->fieldValues;}

    void setStart(int start) {this->start = start;}
    void setSize(int size) {this->size = size;}
    void setOriginalValue(string value){this->orignalValue = value;}

    void addTrace(Trace* ins, int index);
    void addMarker(string marker){this->markers.push_back(marker);}
    void addConstraint(string constraint){this->constraints.push_back(constraint);}
    void addConditionBoundary(string condition){this->conditionBoundaries.push_back(condition);}
    void addArithmeticBoundary(string arithmetic){this->arithmeticBoundaries.push_back(arithmetic);}
    void addFieldValue(FieldValue* value);

    bool isTraceExist(Trace* ins);
    bool isFieldValueExist(FieldValue* fv);

    bool isMarkerExist(string value);
    bool isConstraintExist(string value);
    bool isConditionBoundaryExist(string value);
    bool isArithmeticBoundaryExist(string value);
    bool isInterestValueExist(string value);

    bool operator==(const Field& field) const { 
        //cout << "compare: " << this->start << " " << field.getStart() << endl;
        return (this->start == field.getStart()) && (this->size && field.getSize());
    }

    void initOriginValue(vector<unsigned char> inputData);
    void printCout(vector<unsigned char> inputData);

    void makeFieldTree();
    void makeFieldValue(FieldTrace* ft, FieldValue* fieldValue, bool isOpt);

    void getInterestingValue();
    void getInterestingValueComparison(FieldValue* fv);
    void getInterestingValueBoundary(FieldValue* fv);

    void printOutput();
    void printOutput(vector<string> values);

    void incConstraintCount() {this->constraintCount++;}
    void incBoundaryCount() {this->boundaryCount++;}
};

bool compare(const Field* field1, const Field* field2);
bool compareFieldTrace(const FieldTrace* ft1, const FieldTrace* ft2);

vector<Field*>::iterator findField(const Field field);
vector<Field*>::iterator findField(const Field* const field);

extern ofstream output;

extern int total_cmp;
extern int simple_cmp;
extern int simple_add;
extern int simple_mul;
extern int simple_sub;
extern int un_add;
extern int un_sub;
extern int un_mul;
extern int total_add;
extern int total_sub;
extern int total_mul;

extern int unsupportedCount;
extern int skipCount;
extern int constraint_time;
extern int boundary_time;

extern bool SKIP_CONSTRAINT;
extern bool SKIP_BOUNDARY;
extern bool DISABLE_SIMPLE;

#endif