CXX  = g++
CXXFLAGS = -std=c++11 -O3 -D__STDC_LIMIT_MACROS -D__STDC_CONSTANT_MACROS -I/usr/lib/llvm-5.0/include 
TARGET = traceAnalyzer
OBJECTS = traceAnalyzer.o utils.o fieldValue.o operand.o trace.o field.o reduction.o logging.o solver.o
LIB_PATH = /usr/lib/llvm-5.0/lib/
LIBS = -lz3 -lLLVM-5.0

all : $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) -L$(LIB_PATH) $(CXXFLAGS) -o $@ $^ $(LIBS)
	rm *.o
	
traceAnalyzer.o : traceAnalyzer.cpp
	$(CXX) $(CXXFLAGS) -c -o traceAnalyzer.o traceAnalyzer.cpp

fieldValue.o : fieldValue.cpp
	$(CXX) $(CXXFLAGS) -c -o fieldValue.o fieldValue.cpp

operand.o : operand.cpp
	$(CXX) $(CXXFLAGS) -c -o operand.o operand.cpp

trace.o : trace.cpp
	$(CXX) $(CXXFLAGS) -c -o trace.o trace.cpp

field.o : field.cpp
	$(CXX) $(CXXFLAGS) -c -o field.o field.cpp

reduction.o : reduction.cpp
	$(CXX) $(CXXFLAGS) -c -o reduction.o reduction.cpp

logging.o : logging.cpp
	$(CXX) $(CXXFLAGS) -c -o logging.o logging.cpp

solver.o : solver.cpp
	$(CXX) $(CXXFLAGS) -c -o solver.o solver.cpp

utils.o : utils.cpp
	$(CXX) $(CXXFLAGS) -c -o utils.o utils.cpp

clean :
	rm *.o traceAnalyzer
