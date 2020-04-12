#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <cstring>

#include "z3++.h"
#include "fieldValue.hpp"
#include "logging.hpp"
#include "solver.hpp"

using namespace std;

//todo - prev?
bool FieldValue::operator==(const FieldValue& fv) const {
    if(this->value == fv.getValue() &&
        this->trace == fv.getTrace() &&
        this->index == fv.getIndex() &&
        this->prev == fv.getPrev()){

        return true;
    }

    return false;
}

int FieldValue::getDepth(){
    int depth = 0;
    FieldValue* prev = this->prev;

    while(prev != NULL){
        depth++;
        prev = prev->prev;
    }

    return depth;
}

vector<FieldValue*> getFieldValuesByOperandField(OperandField* of){
    vector<Field*>::iterator itField;

    for(itField = gFields.begin(); itField != gFields.end(); itField++){
        Field* field = *itField;
        if(of->getStart() == field->getStart() && of->getSize() == field->getSize()){
            return (*itField)->getFieldValues();
        }
    }

    return {};
}

bool FieldValue::needBoundaryTrigger(int type, Trace* trace, uint64_t op1, uint64_t op2){
    bool result = true;
    uint64_t maxInt = UINT32_MAX;
    string ins = trace->getIns();

    if (type == UIO) maxInt = UINT32_MAX;
    else if (type == SIO) maxInt = INT32_MAX;

    if(!ins.compare("add")){
        if (op1 + op2 > maxInt) result = false;
    }
    else if(!ins.compare("mul") || !ins.compare("imul")){
        if (op1 * op2 > maxInt) result = false;
    }
    else if(!ins.compare("shl")){
        if (op1 << op2 > maxInt) result = false;
    }
    else if(!ins.compare("sub")){
        if (type == UIU){
            if (op1 < op2) result = false;
        }
        else if (type == ZERO){
            if (op1 - op2 == 0) result = false;
        }
    }

    return result;
}

vector<z3::expr*> FieldValue::makeEquation(z3::expr* z3Var){
    FieldValue* prev = this->prev;

    vector<FieldValue*> list;

    while(prev != NULL){
        list.push_back(prev);

        prev = prev->prev;
    }

    reverse(list.begin(), list.end());

    vector<FieldValue*>::iterator it;

    z3::expr* z3Equation = new z3::expr(*z3Var);
    
    vector<z3::expr*> z3Equations;

    for(it = list.begin(); it != list.end(); it++){
        FieldValue* fv = *it;

        fv->appendEquation(fv, z3Equation, NULL);

        if(fv->getTrace()->isComparisonIns()){
            z3Equations.push_back(z3Equation);

            z3Equation  = new z3::expr(*z3Var);
        }
    }

    delete z3Equation;

    return z3Equations;
}

void FieldValue::appendTaintEquation(FieldValue* fv, z3::expr* z3Equation, Solver* solver){
    int fvIndex = fv->getIndex();

    string ins = fv->getTrace()->getIns();

    vector<OperandField*> thisOpFields = fv->getTrace()->getOperands()[(fvIndex)]->getFields();
    vector<OperandField*> opFields = fv->getTrace()->getOperands()[(fvIndex+1)%2]->getFields();

    vector<OperandField*>::iterator itOpField;

    string constName;

    if(thisOpFields[0]->getStart() == opFields[0]->getStart() && thisOpFields[0]->getSize() == opFields[0]->getSize()){
        constName = string("x");
    }
    else{
        constName = to_string(opFields[0]->getStart()) + "_" + to_string(opFields[0]->getSize());
    }

    // todo suboperands
    vector<FieldValue*> opFieldValues = getFieldValuesByOperandField(opFields[0]);
    vector<FieldValue*>::iterator itOp;

    FieldValue* tmpFV = NULL;

    for(itOp = opFieldValues.begin(); itOp != opFieldValues.end();itOp++){
        if((*itOp)->getTrace() == fv->getTrace()){
            if(tmpFV != NULL && tmpFV->getDepth() > (*itOp)->getDepth()) continue;

            tmpFV = (*itOp);
        }
    }

    vector<z3::expr*> z3Equations;
    z3::expr* tmpZ3Var = new z3::expr(z3Context.bv_const(constName.c_str(), 64));

    if(tmpFV != NULL){
        solver->add(z3::ule(*tmpZ3Var, z3Context.bv_val(UINT32_MAX, 64)));
        z3Equations = tmpFV->makeEquation(tmpZ3Var);

        vector<z3::expr*>::iterator itEq;
        
        for(itEq = z3Equations.begin(); itEq != z3Equations.end(); itEq++){
            solver->add(*(*itEq));
            delete (*itEq);
        }
    }

    fv->appendEquation(fv, z3Equation, tmpZ3Var);

    delete tmpZ3Var;
}

void FieldValue::appendEquation(FieldValue* fv, z3::expr* z3Equation, z3::expr* z3Var){
    int fvIndex = fv->getIndex();
    uint64_t opTaint = fv->getTrace()->getOperands()[fvIndex]->getValueInt(this->value.length()/2);
    int opCount = fv->getTrace()->getOperands().size();
    string ins = fv->getTrace()->getIns();

    if(opCount == 1){
        if(!ins.compare("inc")){
            *z3Equation = (*z3Equation + static_cast<int>(1));
        }
        else if(!ins.compare("dec")){
            *z3Equation = (*z3Equation - static_cast<int>(1));
        }
        else if(!ins.compare("not")){
            *z3Equation = ~(*z3Equation);
        }
    }
    else{
        uint64_t op = fv->getTrace()->getOperands()[(fvIndex+1)%2]->getValueInt(this->value.length()/2);

        z3::expr lExpr = z3Context.bv_val((unsigned)op, 64);

        if(z3Var != NULL){
            lExpr = *z3Var;    
        }

        if (!ins.compare("add") || !ins.compare("adc")){
            *z3Equation = (*z3Equation + lExpr);
        }
        else if(!ins.compare("sub") || !ins.compare("sbb")){
            *z3Equation = (*z3Equation - lExpr);
        } 
        else if(!ins.compare("imul") || !ins.compare("mul")){
            if(opCount == 3){
                op = fv->getTrace()->getOperands()[2]->getValueInt(this->value.length()/2);
                lExpr = z3Context.bv_val((unsigned)op, 64);
            }

            *z3Equation = (*z3Equation * lExpr);
        } 
        else if(!ins.compare("div") || !ins.compare("idiv")){   
            *z3Equation = (*z3Equation / lExpr);
        }
        else if(!ins.compare("shl") || !ins.compare("sal")){
            *z3Equation = (*z3Equation * static_cast<int>(pow(2, op)));
        }
        else if(!ins.compare("shr") || !ins.compare("sar")){
            *z3Equation = (*z3Equation / static_cast<int>(pow(2, op)));
        } 
        else if(!ins.compare("ror")){
            z3::expr exprShifted = lshr(*z3Equation, static_cast<int>(op));
            z3::expr exprRotBits = shl(*z3Equation, static_cast<int>((this->value.length()/2) * 8 - op));
            exprRotBits = exprRotBits & z3Context.bv_val(UINT32_MAX, 64);
            *z3Equation = (exprShifted | exprRotBits);
        } 
        else if(!ins.compare("rol")){
            z3::expr exprShifted = shl(*z3Equation, static_cast<int>(op));
            z3::expr exprRotBits = lshr(*z3Equation, static_cast<int>((this->value.length()/2) * 8 - op));
            exprShifted = exprShifted & z3Context.bv_val(UINT32_MAX, 64);
            *z3Equation = (exprRotBits | exprShifted);
        } 
        else if(!ins.compare("or")){
            *z3Equation = (*z3Equation | lExpr);
        } 
        else if(!ins.compare("and")){
            *z3Equation = (*z3Equation & lExpr);
        } 
        else if(!ins.compare("xor")){
            *z3Equation = (*z3Equation ^ lExpr);
        }
        else if(!ins.compare("test")){
            if(op & opTaint)
                *z3Equation = (*z3Equation != 0);
            else
                *z3Equation = (*z3Equation == 0);
        }
        else if(!ins.compare("cmp") || ins.find("cmps") != string::npos || ins.find("pcmp") != string::npos){
            if(op > opTaint)
                *z3Equation = ult(*z3Equation, lExpr);
            else if(op < opTaint)
                *z3Equation = ugt(*z3Equation, lExpr);
            else
                *z3Equation = (*z3Equation == lExpr);
        }
    }
}

vector<string> FieldValue::queryInterest(int fieldSize){
    z3::expr *z3Var = new z3::expr(z3Context.bv_const("x", 64));
    z3::expr *z3Equation = new z3::expr(*z3Var);
    Solver* lSolver = NULL;

    FieldValue* prev = this->prev;
    uint64_t opTaint = 0;

    vector<FieldValue*> list;

    opTaint = this->getTrace()->getOperands()[0]->getValueInt(this->value.length()/2);

    LOG_DEBUG("[queryInterest] current fvalue: " + this->getValue() + " ins: " + this->getTrace()->getInsDis() 
        + " addr: " + this->getTrace()->getInsAddress() + " taint value: " + ullToStr(opTaint, 4));

    while(prev != NULL){
        if (prev->getSolver() != NULL){
            lSolver = new Solver(prev->getZ3Solver());

            break;
        }

        list.push_back(prev);
        prev = prev->prev;
    }

    reverse(list.begin(), list.end());

    vector<FieldValue*>::iterator it;

    LOG_DEBUG("[queryInterest] fvalue list");

    for(it = list.begin(); it != list.end(); it++){
        FieldValue* fv = *it;

        opTaint = fv->getTrace()->getOperands()[0]->getValueInt(this->value.length()/2);

        LOG_DEBUG("\tfvalue: " + fv->getValue() + " ins: " + fv->getTrace()->getInsDis() + " taint value: " + ullToStr(opTaint, 4));
    }

    if(lSolver == NULL){
        lSolver = new Solver();

        uint64_t maxValue = 0;
        if(fieldSize >= 16) {
             maxValue = UINT64_MAX;
        }
        else {
             maxValue = (0x1 << (fieldSize*8)) - 1;
        }

        lSolver->add(z3::ule(*z3Var, z3Context.bv_val(maxValue, 64)));
    }

    for(it = list.begin(); it != list.end(); it++){
        FieldValue* fv = *it;
        
        int fvIndex = fv->getIndex();
        vector<Operand*> fvOperands = fv->getTrace()->getOperands();

        if (fvOperands.size() > 1 && fvOperands[(fvIndex+1)%2]->isTaintOp() && it+1 == list.end()){
            this->appendTaintEquation(fv, z3Equation, lSolver);
        }
        else{
            this->appendEquation(fv, z3Equation, NULL);
        }

        LOG_DEBUG("[queryInterest] make list ins: " + fv->getTrace()->getIns());

        if(fv->getTrace()->isComparisonIns()){
            lSolver->add(*z3Equation);

            *z3Equation  = z3::expr(*z3Var);
        }
    }

    vector<string> results;

    if(this->getTrace()->isComparisonIns()){
        results = this->queryConstraint(lSolver, z3Equation, fieldSize);

        this->appendEquation(this, z3Equation, NULL);

        lSolver->add(*z3Equation);

        this->solver = lSolver;
    } 
    else if(this->getTrace()->isArithmeticBoundaryIns()){
        int fvIndex = this->getIndex();
        vector<Operand*> fvOperands = this->getTrace()->getOperands();

        if (fvOperands.size() > 1 && fvOperands[(fvIndex+1)%2]->isTaintOp() && it+1 == list.end()){
            this->appendTaintEquation(this, z3Equation, lSolver);
        }
        else{
            this->appendEquation(this, z3Equation, NULL);
        }

        results = this->queryBoundary(lSolver, z3Equation, fieldSize);

        delete lSolver;
    }
 
    delete z3Equation;
    delete z3Var;

    return results;
}

vector<string> FieldValue::queryConstraint(Solver* solver, z3::expr* const z3Equation, int fieldSize){
    vector<string> results;

    uint64_t opTaint = this->getTrace()->getOperands()[(this->index)]->getValueInt(this->value.length()/2);
    uint64_t op = this->getTrace()->getOperands()[(this->index+1)%2]->getValueInt(this->value.length()/2);

    vector<string> temp;
    vector<z3::expr> z3Equations;

    for(uint32_t i = 0; i < 3; i++){
        z3::expr tempEquation = z3Context.bv_val((unsigned)op, 64);
        
        switch(i){
            case 0: 
                if(opTaint == op) continue;

                tempEquation = (*z3Equation == tempEquation); 
                break;

            case 1: 
                if(opTaint > op) continue;

                tempEquation = ugt(*z3Equation, tempEquation); 
                break;

            case 2: 
                if(opTaint < op) continue;

                tempEquation = ult(*z3Equation, tempEquation); 
                break;

            default: 
                break;
        }

        solver->push();
        solver->add(tempEquation);
        
        int start_time = getTimeStamp();

        temp = solver->solve(fieldSize);

        int cur_time = getTimeStamp();

        constraintSolvingTime += cur_time - start_time;
        constraintQueryCount++;

        if (temp.empty()){
            // z3Equations.push_back(tempEquation); // optimistic solving
        } else {
            results.insert(results.end(), temp.begin(), temp.end());
            temp.clear();
        }

        solver->pop();
    }

    return results;
}

vector<string> FieldValue::queryBoundary(Solver* solver, z3::expr* const z3Equation, int fieldSize){
    vector<string> results;

    Trace* trace = this->getTrace();

    uint64_t op1 = trace->getOperands()[0]->getValueInt(this->value.length()/2);
    uint64_t op2 = trace->getOperands()[1]->getValueInt(this->value.length()/2);

    for (int i = 0 ; i < ARITHTYPES; i++){
        z3::expr tempEquation = *z3Equation;

        if(trace->isOverflowIns()){
            switch(i){
            case SIO:
                if (!this->needBoundaryTrigger(SIO, trace, op1, op2)) continue;

                tempEquation = (*z3Equation > static_cast<int>(INT32_MAX));

                break;

            case UIO:
                if(!this->needBoundaryTrigger(UIO, trace, op1, op2)) continue;

                tempEquation = (*z3Equation / static_cast<int>(2));
                tempEquation = (tempEquation > static_cast<int>(INT32_MAX));

                break;

            default:
                continue;
            }
        }
        else if(trace->isUnderflowIns()){
            switch(i){
            case UIU:
                if(!this->needBoundaryTrigger(UIU, trace, op1, op2)) continue;

                tempEquation = (*z3Equation < 0);

                break;

            case ZERO:
                if(!this->needBoundaryTrigger(ZERO, trace, op1, op2)) continue;

                tempEquation = (*z3Equation == 0);

                break;

            default:
                continue;
            }
        }

        solver->push();
        solver->add(tempEquation);

        int start_time = getTimeStamp();

        vector<string> temp = solver->solve(fieldSize);

        int cur_time = getTimeStamp();

        boundarySolvingTime += cur_time - start_time;
        boundaryQueryCount++;

        results.insert(results.end(), temp.begin(), temp.end());

        solver->pop();
    }

    return results;
}

void FieldValue::print(){
     LOG_DEBUG("[FieldValue] instruction: " + this->trace->getInsDis() + " value: " + this->value);
}

FieldValue::FieldValue(Trace* trace, int index, string value, FieldValue* prev, bool isOpt){
    this->trace = trace;
    this->index = index;
    this->value = value;
    this->prev = prev;
    this->isOpt = isOpt;

    this->solver = NULL;
}

FieldValue::~FieldValue(){
    delete solver;
}