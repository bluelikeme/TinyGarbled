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
#include "../include/justGarble.h"
#include "../include/tcpip.h"
#include "../OTExtension/mains/otmain.h"

int main(int argc, char* argv[])
{
#ifndef DEBUG
	srand( time(NULL));
	srand_sse( time(NULL));
#else
	srand(1);
	srand_sse(1111);
#endif


	if(argc < 3)
	{
			printf( "Usage: %s <scd file name> <port> \n", argv[0]);
			return -1;
	}

	int port = atoi(argv[2]);
	int connfd = server_init(port);
	if (connfd == -1)
	{
		printf( "Something's wrong with the socket!\n");
		return -1;
	}


	//----------------------------------------------------------------------------------------------------------------------------------------- OT Extension

	//the number of OTs that are performed. Has to be initialized to a certain minimum size due to
	int numOTs = 5;

	//bitlength of the values that are transferred - NOTE that when bitlength is not 1 or a multiple of 8, the endianness has to be observed
	int bitlength = 128;

	//The symmetric security parameter (80, 112, 128)
	m_nSecParam = 128;

	//Number of threads that will be used in OT extension
	m_nNumOTThreads = 1;

	//Specifies whether G_OT, C_OT, or R_OT should be used
	BYTE version;

	crypto *crypt = new crypto(m_nSecParam, (uint8_t*) m_vSeed);

	InitOTSender(connfd, crypt);

	CBitVector delta, X1, X2;

	//The masking function with which the values that are sent in the last communication step are processed
	m_fMaskFct = new XORMasking(bitlength, delta);

	//creates delta as an array with "numOTs" entries of "bitlength" bit-values and fills delta with random values
	delta.Create(1, bitlength, crypt);

	//Create X1 and X2 as two arrays with "numOTs" entries of "bitlength" bit-values and resets them to 0
	X1.Create(numOTs, bitlength);
	X1.Reset();
	X2.Create(numOTs, bitlength);
	X2.Reset();

	for(int i = 0; i < numOTs; i++)
	{
		//access and set the i-th element in the bitvectors
		X1.Set(0x5555, i);
		X2.Set(0xAAAA, i);
	}

	version = C_OT;
	ObliviouslySend(X1, X2, numOTs, bitlength, version, crypt);

	//-----------------------------------------------------------------------------------------------------------------------------------------*** end










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


	int *garbler_inputs = (int *)malloc(sizeof(int)*(g)*c);
	block *inputLabels = (block *)malloc(sizeof(block)*2*n*c);
	block *initialDFFLable = (block *)malloc(sizeof(block)*2*p);
	block *outputLabels = (block *)malloc(sizeof(block)*2*m*c);

	printf("\n\ninputs:\n");
	for(cid=0;cid<c;cid++)
	{
		for (j = 0; j < g; j++)
		{
			garbler_inputs[cid*g + j] = rand() % 2;
			printf("%d ", garbler_inputs[cid*g + j]);
		}
	}
	printf("\n\n");






#ifndef DEBUG
	block R = randomBlock();
	*((short *) (&R)) = 1;
#else
	block R = makeBlock((long)(-1),(long)(-1));
#endif

	createInputLabels(inputLabels, R, n*c);
	createInputLabels(initialDFFLable, R, p);


	for (cid = 0; cid < c; cid++)
	{
		for (j = 0; j < g; j++)
		{
			if (garbler_inputs[cid*g + j]==0)
				send_block(connfd, inputLabels[2*(cid*n+j)]);
			else
				send_block(connfd, inputLabels[2*(cid*n+j)+1]);

			printf("i(%ld, %ld, %d)\n", cid, j, garbler_inputs[cid*g + j]);
			print__m128i(inputLabels[2*(cid*n+j)]);
			print__m128i(inputLabels[2*(cid*n+j)+1]);
		}


		//------------------------------------------------------------------------------------------ CHANGE 1
		for(j = 0 ; j < e; j++)
		{
			int ev_input;
			read(connfd, &ev_input, sizeof(int));
			if (!ev_input)
				send_block(connfd, inputLabels[2*(cid*n+g+j)]);
			else
				send_block(connfd, inputLabels[2*(cid*n+g+j) + 1]);

			printf("i(%ld, %ld, %d)\n", cid, j, ev_input);
			print__m128i(inputLabels[2*(cid*n+g+j)]);
			print__m128i(inputLabels[2*(cid*n+g+j) + 1]);
		}
		//----------------------------------------------------------------------end




	}
	printf("\n\n");

	for (j = 0; j < p; j++) //p:#DFF
	{
		printf("garbledCircuit.I[j] = %d\n", garbledCircuit.I[j]);
		if(garbledCircuit.I[j] == CONST_ZERO) // constant zero
		{
			send_block(connfd, initialDFFLable[2*j]);
			printf("dffi(%ld, %ld, %d)\n", cid, j, 0);
			print__m128i(initialDFFLable[2*j]);
			print__m128i(initialDFFLable[2*j+1]);

		}
		else if(garbledCircuit.I[j] == CONST_ONE) // constant zero
		{
			send_block(connfd, initialDFFLable[2*j+1]);
			printf("dffi(%ld, %ld, %d)\n", cid, j, 0);
			print__m128i(inputLabels[2*j]);
			print__m128i(inputLabels[2*j+1]);

		}
		else if(garbledCircuit.I[j] < g) //belongs to Alice (garbler)
		{
			int index = garbledCircuit.I[j];

			if (garbler_inputs[index]==0)
				send_block(connfd, initialDFFLable[2*j]);
			else
				send_block(connfd, initialDFFLable[2*j+1]);

			printf("dffi(%ld, %ld, %d)\n", cid, j, garbler_inputs[index]);
			print__m128i(initialDFFLable[2*j]);
			print__m128i(initialDFFLable[2*j+1]);

		}
		//------------------------------------------------------------------------------------------ CHANGE 2
		else          //**** belongs to Bob
		{
			int ev_input;
			read(connfd, &ev_input, sizeof(int));
			if (!ev_input)
				send_block(connfd, initialDFFLable[2*j]);
			else
				send_block(connfd, initialDFFLable[2*j+1]);

			printf("dffi(%ld, %ld, %d)\n", cid, j, ev_input);
			print__m128i(initialDFFLable[2*j]);
			print__m128i(initialDFFLable[2*j+1]);
			printf("\n");
		}
		//----------------------------------------------------------------------end
	}
	printf("\n\n");

	garbledCircuit.globalKey = randomBlock();
	send_block(connfd, garbledCircuit.globalKey); // send DKC key


	garble(&garbledCircuit, inputLabels, initialDFFLable, outputLabels, &R, connfd);

	for(cid=0;cid<c;cid++)
	{
		for(i=0;i<m;i++)
		{
			short outputType =  getLSB(outputLabels[2*(m*cid + i)+ 0]);
			send_type(connfd, outputType);
		}
	}




	server_close(connfd);
	removeGarbledCircuit(&garbledCircuit);


	return 0;
}

