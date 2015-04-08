#ifndef _MPC_H_
#define _MPC_H_

#include "../util/typedefs.h"
#include "../util/crypto/crypto.h"
#include "../util/socket.h"
#include "../ot/naor-pinkas.h"
//#include "../ot/asharov-lindell.h"
#include "../ot/ot-extension.h"
#include "../util/cbitvector.h"
#include "../ot/xormasking.h"


#include <vector>
#include <sys/time.h>

#include <limits.h>
#include <iomanip>
#include <string>

using namespace std;

BOOL Init(crypto* crypt);
BOOL Cleanup();
BOOL Connect();
BOOL Listen();

void InitOTSender(int sock, crypto* crypt);
void InitOTReceiver(int sock, crypto* crypt);

BOOL PrecomputeNaorPinkasSender(crypto* crypt);
BOOL PrecomputeNaorPinkasReceiver(crypto* crypt);
BOOL ObliviouslyReceive(CBitVector& choices, CBitVector& ret, int numOTs, int bitlength, BYTE version, crypto* crypt);
BOOL ObliviouslySend(CBitVector& X1, CBitVector& X2, int numOTs, int bitlength, BYTE version, crypto* crypt);


extern USHORT		m_nPort;
extern const char* m_nAddr ;// = "localhost";

// Network Communication
extern CSocket* m_vSockets;
extern int m_nPID; // thread id
extern int m_nSecParam; 
extern int m_nBitLength;
extern int m_nMod;
extern MaskingFunction* m_fMaskFct;

// Naor-Pinkas OT
extern BaseOT* bot;
extern OTExtensionSender *sender;
extern OTExtensionReceiver *receiver;
extern CBitVector U; 
extern BYTE *vKeySeeds;
extern BYTE *vKeySeedMtx;

extern int m_nNumOTThreads;

extern double rndgentime;



#endif //_MPC_H_
