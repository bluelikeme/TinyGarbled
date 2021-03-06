# ***********************************************
#                    TinyGarble
# ***********************************************
# ***********************************************
#                    JustGarble
# ***********************************************

OBJDIR   = obj
RELDIR   = bin
DEBDIR   = debug
RELOBJDIR = $(RELDIR)/$(OBJDIR)
DEBOBJDIR = $(DEBDIR)/$(OBJDIR)

IDIR      = include

CC=g++ 
CFLAGS= -std=c++11 -lm -lrt -lpthread -maes -msse4 -Wno-unused-result -march=native -I$(IDIR)
DBGCFLAGS = -g -O0 -DDEBUG
RELCFLAGS = -O3 -DNDEBUG

SOURCES := $(wildcard *.cpp)
RELOBJECT := $(SOURCES:$/%.cpp=$(RELOBJDIR)/%.o)
DEBOBJECT := $(SOURCES:$/%.cpp=$(DEBOBJDIR)/%.o) 


READNETLIST = readNetlist
rm = rm --f

.PHONY: all release debug check_msgpack prep clean

all: release debug

release: prep  $(RELDIR)/$(READNETLIST).out 
debug:   prep $(DEBDIR)/$(READNETLIST).out 

##release
$(RELDIR)/$(READNETLIST).out: $(RELOBJECT)
	$(CC) $(RELOBJECT) -o $(RELDIR)/$(READNETLIST).out $(LIBS) $(CFLAGS) $(RELCFLAGS)

$(RELOBJECT): $(RELOBJDIR)/%.o : %.cpp
	$(CC) -c $< -o $@ $(LIBS) $(CFLAGS) $(RELCFLAGS)

##debug
$(DEBDIR)/$(READNETLIST).out: $(DEBOBJECT)
	$(CC) $(DEBOBJECT) -o $(DEBDIR)/$(READNETLIST).out $(LIBS) $(CFLAGS) $(DBGCFLAGS)

$(DEBOBJECT): $(DEBOBJDIR)/%.o : %.cpp
	$(CC) -c $< -o $@ $(LIBS) $(CFLAGS) $(DBGCFLAGS)

prep:
	@mkdir -p $(RELDIR) $(DEBDIR) 
	@mkdir -p $(RELDIR)/$(OBJDIR) 
	@mkdir -p $(DEBDIR)/$(OBJDIR) 

clean:
	@$(rm) $(RELOBJECT)
	@$(rm) $(RELDIR)/$(READNETLIST).out
	@$(rm) $(DEBOBJECT)
	@$(rm) $(DEBDIR)/$(READNETLIST).out
