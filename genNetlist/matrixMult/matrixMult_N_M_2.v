`timescale 1ns / 1ps
// synopsys template
module matrixMult_N_M_2
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
	input[N*M-1:0] x;
	input[N*M-1:0] y;
	output reg[M-1:0] o;

	wire [M-1:0] xi[N-1:0];
	wire [M-1:0] yi[N-1:0];

	wire [M-1:0] xyi[N-1:0];
	wire [M-1:0] oi[N:0];

	genvar i;

	generate
	for (i=0;i<N;i=i+1)
	begin:ASS_ROW
		assign xi[i] = x[M*(i+1)-1:M*(i)];
		assign yi[i] = y[M*(i+1)-1:M*(i)];
	end
	endgenerate



	generate
	for (i=0;i<N;i=i+1)
	begin:MMULT_ROW
		//assign xyi[i] = xi[i]*yi[i];
		MULT 
		#(
			.N(M)
		)
		MULT_
		(
			.A(xi[i]),
			.B(yi[i]),
			.O(xyi[i])
		);
	end
	endgenerate

	
	assign oi[0] = o;


	generate
	for (i=0;i<N;i=i+1)
	begin:ADD_ROW
		ADD 
		#(
			.N(M)
		)
		ADD_
		(
			.A(xyi[i]),
			.B(oi[i]),
			.CI(1'b0),
			.S(oi[i+1]),
			.CO()
		);
	end
	endgenerate
	
	
	always@(posedge clk or posedge rst)
	begin
		if(rst)
		begin
			o <= 'b0;
		end
		else
		begin
			o <= oi[N];
		end
	end
endmodule
