#ifndef INTRIGUER_FIELD_VALUE_HPP_
#define INTRIGUER_FIELD_VALUE_HPP_

#include <vector>

#include "z3++.h"

#include "type.hpp"
#include "trace.hpp"
#include "solver.hpp"

using namespace std;

class Trace;

class FieldValue{
private:
    string value;
    FieldValue* prev;
    Trace* trace;
    int index;
    bool isOpt;

    Solver *solver;

public:
    FieldValue(Trace* trace, int index, string value, FieldValue* prev, bool isOpt);
    ~FieldValue();

    string getValue() const {return this->value;}
    FieldValue* getPrev() const {return this->prev;}
    Trace* getTrace() const {return this->trace;}
    int getIndex() const {return this->index;}
    int getDepth();
    bool getIsOpt() const {return this->isOpt;}

    Solver* getSolver() const {return this->solver;}
    z3::solver getZ3Solver() const {return this->solver->getSolver_();}

    vector<z3::expr*> makeEquation(z3::expr* z3Var);
    void appendEquation(FieldValue* fv, z3::expr* z3Equation, z3::expr* z3Var);
    void appendTaintEquation(FieldValue* fv, z3::expr* z3Equation, Solver* solver);

    vector<string> queryInterest(int fieldSize);
    vector<string> queryConstraint(Solver* solver, z3::expr* const z3Equation, int fieldSize);
    vector<string> queryBoundary(Solver* solver, z3::expr* const z3Equation, int fieldSize);

    bool needBoundaryTrigger(int type, Trace* trace, uint64_t op, uint64_t opTaint);

    bool operator==(const FieldValue& fv) const;

    void print();
};

vector<FieldValue*> getFieldValuesByOperandField(OperandField* of);

extern int constraintQueryCount;
extern int boundaryQueryCount;
extern int constraintSolvingTime;
extern int boundarySolvingTime;

extern z3::context z3Context;

#endif
