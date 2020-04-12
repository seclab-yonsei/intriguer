#include <string>

#include "z3++.h"

#include "solver.hpp"
#include "utils.hpp"
#include "logging.hpp"

using namespace std;

z3::context z3Context;

const unsigned solverTimeout = 1000 *10; // 10 seconds

Solver::Solver()
    : context_(z3Context)
    , solver_(z3::solver(z3Context))
{
    // Set timeout for solver
    z3::params p(context_);
    p.set(":timeout", solverTimeout);
    solver_.set(p);
}

Solver::Solver(z3::solver s)
    : context_(z3Context)
    , solver_(z3::solver(s))
{
    // Set timeout for solver
    z3::params p(context_);
    p.set(":timeout", solverTimeout);
    solver_.set(p);
}

Solver::~Solver(){

}

void Solver::push(){
    solver_.push();
}

void Solver::pop(){
    solver_.pop();
}

void Solver::reset(){
    solver_.reset();
}

void Solver::add(z3::expr expr) {
    if (!expr.is_const()){
        if (getenv("INTRIGUER_DEBUG"))
            solver_.add(expr);
        else
            solver_.add(expr.simplify());
    }   
}

vector<string> Solver::solve(int fieldSize){
    vector<string> results;
    string tempResult;
    z3::model* z3Model;

    uint64_t before = getTimeStamp();

    LOG_DEBUG("solver: " + string(Z3_solver_to_string(context_, solver_)));

    try{
    switch(solver_.check()){
        case z3::unsat: LOG_DEBUG("unsat"); 
            break;

        case z3::sat:
            z3Model = new z3::model(solver_.get_model());

            LOG_DEBUG("model: " + string(Z3_model_to_string(context_, *z3Model)));

            uint64_t goodValue;

            if(z3Model->size() == 1){
                    Z3_get_numeral_uint64(context_, z3Model->get_const_interp((*z3Model)[0]), &goodValue); 
                    results.push_back(ullToStr(goodValue, fieldSize));
            } else {
                for (uint32_t i=0; i < z3Model->size(); i++){
                    z3::func_decl v = (*z3Model)[i];
                    Z3_get_numeral_uint64(context_, z3Model->get_const_interp(v), &goodValue); 
                    
                    stringstream ss;
                    ss <<  hex << "\tvalue " << v.name() << ": " << goodValue << " fieldSize: " <<  to_string(fieldSize) << endl;

                    LOG_DEBUG(ss.str());

                    if(v.name().str() == "x"){
                        tempResult += ":x_x_" + ullToStr(goodValue, fieldSize);
                    } else{
                        tempResult += ":" + v.name().str() + "_" + ullToStr(goodValue, fieldSize);
                    }
                }

                results.push_back(tempResult);
            }

            delete z3Model;
            break;

        case z3::unknown:
            break;
        }

    }
    catch (z3::exception e) {
    }

    uint64_t cur = getTimeStamp();
    uint64_t elapsed = cur - before;

    LOG_DEBUG("[FieldValue Solve] elapsed time = " + to_string(elapsed/1000));

    return results;
}
