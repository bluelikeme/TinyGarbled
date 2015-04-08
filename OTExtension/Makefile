CC=g++
AR=ar rvs
OT=ot
LIBRARIES=-std=c++11 -lpthread util/Miracl/miracl.a -lssl -lcrypto -maes -msse4  -march=native
MIRACL_PATH= -I./util/Miracl
SOURCES_OTMAIN=mains/*.cpp
OBJECTS_OTMAIN=mains/*.o
SOURCES_UTIL=util/*.cpp
OBJECTS_UTIL=util/*.o
SOURCES_CRYPTO=util/crypto/*.cpp
OBJECTS_CRYPTO=util/crypto/*.o
SOURCES_OT=ot/*.cpp
OBJECTS_OT=ot/*.o
OBJECTS_MIRACL= util/Miracl/*.o
CFLAGS=-O3
INCLUDE=-I..

all: ${OT}

${OT}: ${OBJECTS_UTIL} ${OBJECTS_CRYPTO} ${OBJECTS_MIRACL} ${OBJECTS_OT} ${OBJECTS_OTMAIN}
	${AR} ${OT}.a  ${OBJECTS_OTMAIN} ${OBJECTS_UTIL} ${OBJECTS_CRYPTO} ${OBJECTS_OT} ${OBJECTS_MIRACL} 

${OBJECTS_OTMAIN}: ${SOURCES_OTMAIN}$
	@cd mains; ${CC} -c ${INCLUDE} ${CFLAGS} *.cpp 
	

${OBJECTS_UTIL}: ${SOURCES_UTIL}$  
	@cd util; ${CC} -c ${INCLUDE} ${CFLAGS} *.cpp

${OBJECTS_OT}: ${SOURCES_OT}$
	@cd ot; ${CC} -c ${INCLUDE} ${CFLAGS} *.cpp 

${OBJECTS_CRYPTO}: ${SOURCES_CRYPTO}$
	@cd util/crypto; ${CC} -c ${INCLUDE} ${CFLAGS} *.cpp 

clean:
	rm -rf ${OT}.a ${OBJECTS_UTIL} ${OBJECTS_OTMAIN} ${OBJECTS_OT} ${OBJECTS_CRYPTO}

