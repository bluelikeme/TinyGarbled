module modexp_2N_NN
#(
	parameter N 	= 8, //number of bits
	parameter CC	= 2*N*N  //2*N to 2*N*N
)
(
	clk,
	rst,
	m,
	e,
	n,
	c 	// c = m^e mode n 
);

	input			clk;
	input			rst;
	input 	[N-1:0]	m;
	input 	[N-1:0]	e;
	input 	[N-1:0]	n;

	output [N-1:0]	c;


	reg 	first_one;
	reg		mul_pow;
	
	reg		[CC/(2*N)-1:0] start_reg;	
	reg 	[N-1:0]	ereg; 
	reg	 	[N-1:0]	creg; 
	
	wire	[CC/(2*N)-1:0] start_in;
	wire	[CC/(2*N)-1:0] start_in_shift;
	wire 	[N-1:0]	ein; 
	
	wire 	[N-1:0] y;	
	wire 	[N-1:0] x;
	wire 	[N-1:0] o;
	
	
	wire 	[N-1:0]	ereg_next, creg_next; 

	
	
	//assign start_in = (init)?start_reg:1'b1;
	//assign ein = (init)?ereg:e;
	//assign c = (ein[N-1])?o:creg;


	assign c = creg_next;
	
	assign start_in = start_reg;
	assign ein = ereg;

	/*MUX 
	#(
		.N(N)
	)
	MUX_1
	(
		.A(ereg),
		.B(e),
		.S(init),
		.O(ein)
	);*/	

	/*MUX 
	#(
		.N(N)
	)
	MUX_2
	(
		.A(o),
		.B(creg),
		.S(ein[N-1]),
		.O(c)
	);*/



	generate
	if(CC/(2*N) > 1)
	begin
		assign start_in_shift = {start_in[CC/(2*N)-2:0] , start_in[CC/(2*N)-1]};
	end
	else
	begin
		assign start_in_shift = {start_in[CC/(2*N)-1]};
	end	
	endgenerate


	//assign creg_next = (~init)?m:((first_one & ein[N-1] & mul_pow)|(first_one & ~mul_pow))?o:creg;

	wire [N-1:0] w1, w2, w3;


	assign creg_next = w1;

	/*MUX 
	#(
		.N(N)
	)
	MUX_3
	(
		.A(m),
		.B(w1),
		.S(~init),
		.O(creg_next)
	);*/	

	MUX 
	#(
		.N(N)
	)
	MUX_4
	(
		.A(o),
		.B(creg),
		.S(((first_one & ein[N-1] & mul_pow)|(first_one & ~mul_pow))),
		.O(w1)
	);	

	//assign ereg_next = (~init)?e:(mul_pow)?{ein[N-2:0], 1'b0}:ereg;
	
	
	assign ereg_next = w2;
	
	/*MUX 
	#(
		.N(N)
	)
	MUX_5
	(
		.A(e),
		.B(w2),
		.S(~init),
		.O(ereg_next)
	);*/	

	MUX 
	#(
		.N(N)
	)
	MUX_6
	(
		.A({ein[N-2:0], 1'b0}),
		.B(ereg),
		.S(mul_pow),
		.O(w2)
	);	





	always@(posedge clk or posedge rst)
	begin
		if(rst)
		begin
			creg <= m;
			ereg  <= e;
			first_one <= 0;
			mul_pow <= 0;
			start_reg <= 1'b1;
		end
		else
		begin
		
			start_reg <= start_in_shift;
		
		
			if(start_in[CC/(2*N)-1])
				mul_pow <= ~mul_pow;
		
		
			
			ereg <= ereg_next;
			creg <= creg_next;
		
			/*if(~init)
			begin
				//ereg <= e;
				//creg <= m;
			end
			else */
			if(start_in[CC/(2*N)-1])
			begin
				if(ein[N-1] & mul_pow)
				begin
					first_one <= 1;
				end
		
				/*
				if(first_one & ein[N-1] & mul_pow)
				begin
					creg <= o;
				end
				else if(first_one & ~mul_pow)
				begin
					creg <= o;
				end
				
				if(mul_pow)
					ereg <= {ein[N-2:0], 1'b0};
				*/
			end
		end
	end




	//assign x = (init)?creg:m;
	//assign y = (mul_pow)?m:(init)?creg:m;

	assign x = creg;
	//assign y = (mul_pow)?m:creg;

	/*MUX 
	#(
		.N(N)
	)
	MUX_7
	(
		.A(creg),
		.B(m),
		.S(init),
		.O(x)
	);	
	
	
	
	MUX 
	#(
		.N(N)
	)
	MUX_8
	(
		.A(creg),
		.B(m),
		.S(init),
		.O(w3)
	);	*/
	
	assign w3 = creg;
	
	MUX 
	#(
		.N(N)
	)
	MUX_9
	(
		.A(m),
		.B(w3),
		.S(mul_pow),
		.O(y)
	);	



    modmult
	#(
		.N(N),
		.CC(CC/(2*N))
	)
	modmult_1
	(
		.clk(clk),
		.rst(rst),
		.start(start_in[0]),
		.x(x),
		.y(y),
		.n(n),
		.o(o)
	);

endmodule
