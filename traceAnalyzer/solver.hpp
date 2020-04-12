#ifndef INTRIGUER_SOLVER_HPP_
#define INTRIGUER_SOLVER_HPP_

#include <vector>

#include "z3++.h"

using namespace std;

class Solver{
private:
    z3::context& context_;
    z3::solver solver_;

public:
    Solver();
	Solver(z3::solver s);

    ~Solver();
    
    void push();
    void pop();
    void reset();
    void add(z3::expr expr);

    vector<string> solve(int fieldSize);
    z3::solver getSolver_() const {return this->solver_;}
};

#endif