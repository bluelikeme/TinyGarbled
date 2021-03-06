`timescale 1ns / 1ps
// synopsys template
module matrixMult_N_M_0
#(
	parameter N=3,
	parameter M=32
)
(
	clk,
	rst,
	x,
	y,
	o
);
	input clk,rst;
	input[M*N*N-1:0] x;
	input[M*N*N-1:0] y;
	output[M*N*N-1:0] o;

	wire [M-1:0] xij[N-1:0][N-1:0];
	wire [M-1:0] yij[N-1:0][N-1:0];
	wire  [M-1:0] oij[N-1:0][N-1:0];
	wire  [M-1:0] oijk[N-1:0][N-1:0][N-1:0];


	wire  [M-1:0] xyijk[N-1:0][N-1:0][N-1:0];

	genvar i;
	genvar j;
	genvar k;
	
	generate
	for (i=0;i<N;i=i+1)
	begin:ASS_ROW
		for (j=0;j<N;j=j+1)
		begin:ASS_COL
			assign xij[i][j] = x[M*(N*i+j+1)-1:M*(N*i+j)];
			assign yij[i][j] = y[M*(N*i+j+1)-1:M*(N*i+j)];
			assign o[M*(N*i+j+1)-1:M*(N*i+j)] = oij[i][j];
			assign oijk[i][j][0] = xyijk[i][j][0];
			assign oij[i][j] = oijk[i][j][N-1];
		end
	end
	endgenerate



	generate
	for (i=0;i<N;i=i+1)
	begin:MUL_ROW_MULT
		for (j=0;j<N;j=j+1)
		begin:MUL_COL_MULT
			for (k=0;k<N;k=k+1)
			begin:MULT_O
				//assign xyijk[i][j][k] = xij[i][k]*yij[k][j];
				MULT 
				#(
					.N(M)
				)
				MULT_
				(
					.A(xij[i][k]),
					.B(yij[k][j]),
					.O(xyijk[i][j][k])
				);
			end
		end
	end
	endgenerate
	
	generate
	for (i=0;i<N;i=i+1)
	begin:MUL_ROW_ADD
		for (j=0;j<N;j=j+1)
		begin:MUL_COL_ADD
			for (k=1;k<N;k=k+1)
			begin:ADD_O
				ADD 
				#(
					.N(M)
				)
				ADD_
				(
					.A(xyijk[i][j][k]),
					.B(oijk[i][j][k-1]),
					.CI(1'b0),
					.S(oijk[i][j][k]),
					.CO()
				);	
			end
		end
	end
	endgenerate
	
	
endmodule

