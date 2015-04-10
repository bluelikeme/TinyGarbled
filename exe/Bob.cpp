/*
 This file is part of JustGarble.

 JustGarble is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 JustGarble is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with JustGarble.  If not, see <http://www.gnu.org/licenses/>.

 */
/*
 This file is part of TinyGarble. It is modified version of JustGarble
 under GNU license.

 TinyGarble is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 TinyGarble is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with TinyGarble.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <assert.h>
#include "../include/justGarble.h"
#include "../include/tcpip.h"
#include "../OTExtension/mains/otmain.h"

int main(int argc, char* argv[]) {

	//Parameters
	int numOTs = 1;
	int bitlength = 128;
	m_nSecParam = 128;
	//-------------------------

#ifndef DEBUG
	srand(time(NULL));
	srand_sse(time(NULL));
#else
	srand(7);
	srand_sse(7777);
#endif

	if (argc < 4) {
		printf("Usage: %s <scd file name> <ip of server> <port> \n", argv[0]);
		return -1;
	}

	int port = atoi(argv[3]);
	int sockfd = client_init(argv[2], port);
	if (sockfd == -1) {
		printf("Something's wrong with the socket!\n");
		return -1;
	}

	m_nNumOTThreads = 1;
	BYTE version;
	crypto *crypt = new crypto(m_nSecParam, (uint8_t*) m_vSeed);
	InitOTReceiver(sockfd, crypt);
	CBitVector choices, response;
	m_fMaskFct = new XORMasking(bitlength);
	choices.Create(numOTs, 1);
	response.Create(numOTs, bitlength);

	choices.Set(0,0x1);


	cout << "Receiver performing " << numOTs << " C_OT extensions on "
			<< bitlength << " bit elements" << endl;
	BYTE* b = new BYTE[16];
	printf("b:    ");
	for (int i = 0; i < 16; i++) {
		b[i] = i;
		printf("%02x", b[i]);
	}
	printf("\n");
	BYTE* b2 = new BYTE[16];
	printf("b2:   ");
	for (int i = 0; i < 16; i++) {
		b2[i] = 3 - i;
		printf("%02x", b2[i]);
	}
	printf("\n");

	CBitVector X1, X2;
	X1.Create(1, 128);
	X2.Create(1, 128);

	for (int i = 0; i < numOTs; i++) {
		//access and set the i-th element in the bitvectors
		X1.SetBytes(b, 0, 16);
		X2.SetBytes(b2, 0, 16);
	}


	version = C_OT;
	ObliviouslyReceive(choices, response, numOTs, bitlength, version, crypt);




	if (response.IsEqual(X1))
		printf("CORRECT\n");
	else
		printf("WRONG ***\n");
	delete crypt;



	printf("Printing response:\t");

	for (int i = 0; i < 16; i++) {
		b[i] = response.GetByte(i);
		printf("%02x", b[i]);
	}
	printf("\n");

	printf("Printing X1:\t");
	for (int i = 0; i < 16; i++) {
		b[i] = X1.GetByte(i);
		printf("%02x", b[i]);
	}
	printf("\n");

	printf("Printing X2:\t");
	for (int i = 0; i < 16; i++) {
		b[i] = X2.GetByte(i);
		printf("%02x", b[i]);
	}
	printf("\n");

//#define GARBLING

#ifndef GARBLING
	client_close(sockfd);
	return 0;

#else
	//--------------------------------------- Garbling
	GarbledCircuit garbledCircuit;
	long i, j, cid;

	readCircuitFromFile(&garbledCircuit, argv[1]);

	printf("garbledCircuit.I[0] = %d\n", garbledCircuit.I[0]);

	int n = garbledCircuit.n;
	int g = garbledCircuit.g;
	int p = garbledCircuit.p;
	int m = garbledCircuit.m;
	int c = garbledCircuit.c;
	int e = n - g;

	int *evaluator_inputs = (int *) malloc(sizeof(int) * (e) * c);

	block *inputLabels = (block *) malloc(sizeof(block) * n * c);
	block *initialDFFLable = (block *) malloc(sizeof(block) * p);
	block *outputLabels = (block *) malloc(sizeof(block) * m * c);

	printf("\n\ninputs:\n");
	for (cid = 0; cid < c; cid++) {   //For each Clock Cycle
		for (j = 0; j < e; j++) {      //For each input bit

			evaluator_inputs[cid * e + j] = rand() % 2;//generate one random bit as evaluator's input bit

			printf("%d ", evaluator_inputs[cid * e + j]);
		}
	}

	printf("\n\n");

	for (cid = 0; cid < c; cid++) {
		for (j = 0; j < g; j++) {
			recv_block(sockfd, &inputLabels[n * cid + j]);
			printf("i(%ld,%ld,?)\n", cid, j);
			print__m128i(inputLabels[n * cid + j]);
		}

		//for each clock cycle
		//-------------------------------------------------------------------------------------- CHANGE 1
		for (j = 0; j < e; j++) {

			write(sockfd, &evaluator_inputs[cid * e + j], sizeof(int));
			recv_block(sockfd, &inputLabels[cid * n + g + j]);

			printf("i(%ld,%ld,%d)\n", cid, j + g,
					evaluator_inputs[cid * e + j]);
			print__m128i(inputLabels[cid * n + g + j]);
		}
		//--------------------------------------------------------------------------------------

	}
	printf("\n\n");

	for (j = 0; j < p; j++) {
		printf("garbledCircuit.I[j] = %d\n", garbledCircuit.I[j]);

		if (garbledCircuit.I[j] < g) // initial value is constant or belongs to Alice (garbler)
		{
			recv_block(sockfd, &initialDFFLable[j]);
			if (garbledCircuit.I[j] == CONST_ZERO)
			printf("dffi(%ld,%ld,0)\n", cid, j);
			else if (garbledCircuit.I[j] == CONST_ONE)
			printf("dffi(%ld,%ld,1)\n", cid, j);
			else
			printf("dffi(%ld,%ld,?)\n", cid, j);
			print__m128i(initialDFFLable[j]);
		} else {
			assert(
					(garbledCircuit.I[j] - g > 0)
					&& (garbledCircuit.I[j] - g < e));

			//------------------------------------------------------------------------ CHANGE 2
			write(sockfd, &evaluator_inputs[garbledCircuit.I[j] - g],
					sizeof(int));
			recv_block(sockfd, &initialDFFLable[j]);

			//------------------------------------------------------------------------

			printf("dffi(%ld,%ld,%d)\n", cid, j + g,
					evaluator_inputs[garbledCircuit.I[j] - g]);
			print__m128i(initialDFFLable[j]);
			printf("\n");
		}
	}
	printf("\n\n");

	recv_block(sockfd, &(garbledCircuit.globalKey)); //receive key

	evaluate(&garbledCircuit, inputLabels, initialDFFLable, outputLabels,
			sockfd);

	printf("\n\noutput:\n");
	for (cid = 0; cid < c; cid++) {
		for (i = 0; i < m; i++) {
			short myOutputType = getLSB(outputLabels[m * cid + i]);
			short outputType;
			recv_type(sockfd, &outputType);

			printf("%d ", outputType ^ myOutputType);
		}
	}
	printf("\n\n");

	client_close(sockfd);
	removeGarbledCircuit(&garbledCircuit);

	return 0;
#endif

}

