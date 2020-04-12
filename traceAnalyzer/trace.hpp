#ifndef INTRIGUER_INSTRUCTION_HPP_
#define INTRIGUER_INSTRUCTION_HPP_

#include <string>
#include <vector>

#include "operand.hpp"
#include "field.hpp"
#include "type.hpp"

using namespace std;

class Field;

class Trace{
private:
	string insDis, ins, type, strOffsets, insAddress;
	int endian, id, address;
	vector<Operand*> operands;
	vector<string> offsets;

public:
	Trace();
	Trace(string line);
	Trace(int id, string line);

	~Trace();

	string getInsDis() const {return this->insDis;}
	string getIns() const {return this->ins;}
	string getInsAddress() const {return this->insAddress;}

	int getEndian() const {return this->endian;}
	int getId() const {return this->id;}
	int getAddress() const {return this->address;}

	string getEndianStr() const {
		switch (this->endian){
		case BIG:
			return string("Big Endian");
		case LITTLE: 
			return string("Little Endian");
		default:
			return string("");
			break;
		}
	}

	vector<string> getOffsets() const {return this->offsets;}
	vector<Operand*> getOperands() const {return this->operands;}

	bool isStringCompare(int size);
	bool isComparisonIns();
	bool isArithmeticBoundaryIns();
	bool isOverflowIns();
	bool isUnderflowIns();
	bool isAdd();
	bool isImul();
	bool isXor();

	void addOperand(Operand* operand){this->operands.push_back(operand);}

	void proccessOffset();
	void makeField(string offset, int ind);
	void makeField();

	void printDebug();
	void printOperands();
	void printOffsets();

	bool operator==(const Trace& ins) const;
};

bool compareIns(const Trace* ins1, const Trace* ins2);

extern vector<Field*> gFields;

#endif