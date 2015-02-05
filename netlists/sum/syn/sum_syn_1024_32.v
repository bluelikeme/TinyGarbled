
module sum_N1024_CC32 ( clk, rst, a, b, c );
  input [31:0] a;
  input [31:0] b;
  output [31:0] c;
  input clk, rst;
  wire   carry_on, carry_on_d, n1, n2, n3, n4, n5, n6, n7, n8, n9, n10, n11,
         n12, n13, n14, n15, n16, n17, n18, n19, n20, n21, n22, n23, n24, n25,
         n26, n27, n28, n29, n30, n31, n32, n33, n34, n35, n36, n37, n38, n39,
         n40, n41, n42, n43, n44, n45, n46, n47, n48, n49, n50, n51, n52, n53,
         n54, n55, n56, n57, n58, n59, n60, n61, n62, n63, n64, n65, n66, n67,
         n68, n69, n70, n71, n72, n73, n74, n75, n76, n77, n78, n79, n80, n81,
         n82, n83, n84, n85, n86, n87, n88, n89, n90, n91, n92, n93, n94, n95,
         n96, n97, n98, n99, n100, n101, n102, n103, n104, n105, n106, n107,
         n108, n109, n110, n111, n112, n113, n114, n115, n116, n117, n118,
         n119, n120, n121, n122, n123, n124, n125, n126, n127;

  DFF carry_on_reg ( .D(carry_on_d), .CLK(clk), .RST(rst), .Q(carry_on) );
  XOR U3 ( .A(a[1]), .B(n123), .Z(n61) );
  XOR U4 ( .A(a[4]), .B(n114), .Z(n10) );
  XOR U5 ( .A(a[7]), .B(n105), .Z(n7) );
  XOR U6 ( .A(a[10]), .B(n95), .Z(n97) );
  XOR U7 ( .A(a[13]), .B(n83), .Z(n85) );
  XOR U8 ( .A(a[16]), .B(n71), .Z(n73) );
  XOR U9 ( .A(a[19]), .B(n58), .Z(n60) );
  XOR U10 ( .A(a[22]), .B(n46), .Z(n48) );
  XOR U11 ( .A(a[25]), .B(n34), .Z(n36) );
  XOR U12 ( .A(a[28]), .B(n22), .Z(n24) );
  XOR U13 ( .A(a[2]), .B(n120), .Z(n20) );
  XOR U14 ( .A(a[5]), .B(n111), .Z(n9) );
  XOR U15 ( .A(a[8]), .B(n102), .Z(n6) );
  XOR U16 ( .A(a[11]), .B(n91), .Z(n93) );
  XOR U17 ( .A(a[14]), .B(n79), .Z(n81) );
  XOR U18 ( .A(a[17]), .B(n67), .Z(n69) );
  XOR U19 ( .A(a[20]), .B(n54), .Z(n56) );
  XOR U20 ( .A(a[23]), .B(n42), .Z(n44) );
  XOR U21 ( .A(a[26]), .B(n30), .Z(n32) );
  XOR U22 ( .A(a[29]), .B(n17), .Z(n19) );
  XOR U23 ( .A(a[3]), .B(n117), .Z(n11) );
  XOR U24 ( .A(a[6]), .B(n108), .Z(n8) );
  XOR U25 ( .A(a[9]), .B(n99), .Z(n5) );
  XOR U26 ( .A(a[12]), .B(n87), .Z(n89) );
  XOR U27 ( .A(a[15]), .B(n75), .Z(n77) );
  XOR U28 ( .A(a[18]), .B(n63), .Z(n65) );
  XOR U29 ( .A(a[21]), .B(n50), .Z(n52) );
  XOR U30 ( .A(a[24]), .B(n38), .Z(n40) );
  XOR U31 ( .A(a[27]), .B(n26), .Z(n28) );
  XOR U32 ( .A(a[30]), .B(n13), .Z(n15) );
  XOR U33 ( .A(n1), .B(n2), .Z(carry_on_d) );
  ANDN U34 ( .B(n3), .A(n4), .Z(n1) );
  XOR U35 ( .A(b[31]), .B(n2), .Z(n3) );
  XNOR U36 ( .A(b[9]), .B(n5), .Z(c[9]) );
  XNOR U37 ( .A(b[8]), .B(n6), .Z(c[8]) );
  XNOR U38 ( .A(b[7]), .B(n7), .Z(c[7]) );
  XNOR U39 ( .A(b[6]), .B(n8), .Z(c[6]) );
  XNOR U40 ( .A(b[5]), .B(n9), .Z(c[5]) );
  XNOR U41 ( .A(b[4]), .B(n10), .Z(c[4]) );
  XNOR U42 ( .A(b[3]), .B(n11), .Z(c[3]) );
  XNOR U43 ( .A(b[31]), .B(n4), .Z(c[31]) );
  XNOR U44 ( .A(a[31]), .B(n2), .Z(n4) );
  XNOR U45 ( .A(n12), .B(n13), .Z(n2) );
  ANDN U46 ( .B(n14), .A(n15), .Z(n12) );
  XNOR U47 ( .A(b[30]), .B(n13), .Z(n14) );
  XNOR U48 ( .A(b[30]), .B(n15), .Z(c[30]) );
  XOR U49 ( .A(n16), .B(n17), .Z(n13) );
  ANDN U50 ( .B(n18), .A(n19), .Z(n16) );
  XNOR U51 ( .A(b[29]), .B(n17), .Z(n18) );
  XNOR U52 ( .A(b[2]), .B(n20), .Z(c[2]) );
  XNOR U53 ( .A(b[29]), .B(n19), .Z(c[29]) );
  XOR U54 ( .A(n21), .B(n22), .Z(n17) );
  ANDN U55 ( .B(n23), .A(n24), .Z(n21) );
  XNOR U56 ( .A(b[28]), .B(n22), .Z(n23) );
  XNOR U57 ( .A(b[28]), .B(n24), .Z(c[28]) );
  XOR U58 ( .A(n25), .B(n26), .Z(n22) );
  ANDN U59 ( .B(n27), .A(n28), .Z(n25) );
  XNOR U60 ( .A(b[27]), .B(n26), .Z(n27) );
  XNOR U61 ( .A(b[27]), .B(n28), .Z(c[27]) );
  XOR U62 ( .A(n29), .B(n30), .Z(n26) );
  ANDN U63 ( .B(n31), .A(n32), .Z(n29) );
  XNOR U64 ( .A(b[26]), .B(n30), .Z(n31) );
  XNOR U65 ( .A(b[26]), .B(n32), .Z(c[26]) );
  XOR U66 ( .A(n33), .B(n34), .Z(n30) );
  ANDN U67 ( .B(n35), .A(n36), .Z(n33) );
  XNOR U68 ( .A(b[25]), .B(n34), .Z(n35) );
  XNOR U69 ( .A(b[25]), .B(n36), .Z(c[25]) );
  XOR U70 ( .A(n37), .B(n38), .Z(n34) );
  ANDN U71 ( .B(n39), .A(n40), .Z(n37) );
  XNOR U72 ( .A(b[24]), .B(n38), .Z(n39) );
  XNOR U73 ( .A(b[24]), .B(n40), .Z(c[24]) );
  XOR U74 ( .A(n41), .B(n42), .Z(n38) );
  ANDN U75 ( .B(n43), .A(n44), .Z(n41) );
  XNOR U76 ( .A(b[23]), .B(n42), .Z(n43) );
  XNOR U77 ( .A(b[23]), .B(n44), .Z(c[23]) );
  XOR U78 ( .A(n45), .B(n46), .Z(n42) );
  ANDN U79 ( .B(n47), .A(n48), .Z(n45) );
  XNOR U80 ( .A(b[22]), .B(n46), .Z(n47) );
  XNOR U81 ( .A(b[22]), .B(n48), .Z(c[22]) );
  XOR U82 ( .A(n49), .B(n50), .Z(n46) );
  ANDN U83 ( .B(n51), .A(n52), .Z(n49) );
  XNOR U84 ( .A(b[21]), .B(n50), .Z(n51) );
  XNOR U85 ( .A(b[21]), .B(n52), .Z(c[21]) );
  XOR U86 ( .A(n53), .B(n54), .Z(n50) );
  ANDN U87 ( .B(n55), .A(n56), .Z(n53) );
  XNOR U88 ( .A(b[20]), .B(n54), .Z(n55) );
  XNOR U89 ( .A(b[20]), .B(n56), .Z(c[20]) );
  XOR U90 ( .A(n57), .B(n58), .Z(n54) );
  ANDN U91 ( .B(n59), .A(n60), .Z(n57) );
  XNOR U92 ( .A(b[19]), .B(n58), .Z(n59) );
  XNOR U93 ( .A(b[1]), .B(n61), .Z(c[1]) );
  XNOR U94 ( .A(b[19]), .B(n60), .Z(c[19]) );
  XOR U95 ( .A(n62), .B(n63), .Z(n58) );
  ANDN U96 ( .B(n64), .A(n65), .Z(n62) );
  XNOR U97 ( .A(b[18]), .B(n63), .Z(n64) );
  XNOR U98 ( .A(b[18]), .B(n65), .Z(c[18]) );
  XOR U99 ( .A(n66), .B(n67), .Z(n63) );
  ANDN U100 ( .B(n68), .A(n69), .Z(n66) );
  XNOR U101 ( .A(b[17]), .B(n67), .Z(n68) );
  XNOR U102 ( .A(b[17]), .B(n69), .Z(c[17]) );
  XOR U103 ( .A(n70), .B(n71), .Z(n67) );
  ANDN U104 ( .B(n72), .A(n73), .Z(n70) );
  XNOR U105 ( .A(b[16]), .B(n71), .Z(n72) );
  XNOR U106 ( .A(b[16]), .B(n73), .Z(c[16]) );
  XOR U107 ( .A(n74), .B(n75), .Z(n71) );
  ANDN U108 ( .B(n76), .A(n77), .Z(n74) );
  XNOR U109 ( .A(b[15]), .B(n75), .Z(n76) );
  XNOR U110 ( .A(b[15]), .B(n77), .Z(c[15]) );
  XOR U111 ( .A(n78), .B(n79), .Z(n75) );
  ANDN U112 ( .B(n80), .A(n81), .Z(n78) );
  XNOR U113 ( .A(b[14]), .B(n79), .Z(n80) );
  XNOR U114 ( .A(b[14]), .B(n81), .Z(c[14]) );
  XOR U115 ( .A(n82), .B(n83), .Z(n79) );
  ANDN U116 ( .B(n84), .A(n85), .Z(n82) );
  XNOR U117 ( .A(b[13]), .B(n83), .Z(n84) );
  XNOR U118 ( .A(b[13]), .B(n85), .Z(c[13]) );
  XOR U119 ( .A(n86), .B(n87), .Z(n83) );
  ANDN U120 ( .B(n88), .A(n89), .Z(n86) );
  XNOR U121 ( .A(b[12]), .B(n87), .Z(n88) );
  XNOR U122 ( .A(b[12]), .B(n89), .Z(c[12]) );
  XOR U123 ( .A(n90), .B(n91), .Z(n87) );
  ANDN U124 ( .B(n92), .A(n93), .Z(n90) );
  XNOR U125 ( .A(b[11]), .B(n91), .Z(n92) );
  XNOR U126 ( .A(b[11]), .B(n93), .Z(c[11]) );
  XOR U127 ( .A(n94), .B(n95), .Z(n91) );
  ANDN U128 ( .B(n96), .A(n97), .Z(n94) );
  XNOR U129 ( .A(b[10]), .B(n95), .Z(n96) );
  XNOR U130 ( .A(b[10]), .B(n97), .Z(c[10]) );
  XOR U131 ( .A(n98), .B(n99), .Z(n95) );
  ANDN U132 ( .B(n100), .A(n5), .Z(n98) );
  XNOR U133 ( .A(b[9]), .B(n99), .Z(n100) );
  XOR U134 ( .A(n101), .B(n102), .Z(n99) );
  ANDN U135 ( .B(n103), .A(n6), .Z(n101) );
  XNOR U136 ( .A(b[8]), .B(n102), .Z(n103) );
  XOR U137 ( .A(n104), .B(n105), .Z(n102) );
  ANDN U138 ( .B(n106), .A(n7), .Z(n104) );
  XNOR U139 ( .A(b[7]), .B(n105), .Z(n106) );
  XOR U140 ( .A(n107), .B(n108), .Z(n105) );
  ANDN U141 ( .B(n109), .A(n8), .Z(n107) );
  XNOR U142 ( .A(b[6]), .B(n108), .Z(n109) );
  XOR U143 ( .A(n110), .B(n111), .Z(n108) );
  ANDN U144 ( .B(n112), .A(n9), .Z(n110) );
  XNOR U145 ( .A(b[5]), .B(n111), .Z(n112) );
  XOR U146 ( .A(n113), .B(n114), .Z(n111) );
  ANDN U147 ( .B(n115), .A(n10), .Z(n113) );
  XNOR U148 ( .A(b[4]), .B(n114), .Z(n115) );
  XOR U149 ( .A(n116), .B(n117), .Z(n114) );
  ANDN U150 ( .B(n118), .A(n11), .Z(n116) );
  XNOR U151 ( .A(b[3]), .B(n117), .Z(n118) );
  XOR U152 ( .A(n119), .B(n120), .Z(n117) );
  ANDN U153 ( .B(n121), .A(n20), .Z(n119) );
  XNOR U154 ( .A(b[2]), .B(n120), .Z(n121) );
  XOR U155 ( .A(n122), .B(n123), .Z(n120) );
  ANDN U156 ( .B(n124), .A(n61), .Z(n122) );
  XNOR U157 ( .A(b[1]), .B(n123), .Z(n124) );
  XOR U158 ( .A(carry_on), .B(n125), .Z(n123) );
  NANDN U159 ( .A(n126), .B(n127), .Z(n125) );
  XOR U160 ( .A(carry_on), .B(b[0]), .Z(n127) );
  XNOR U161 ( .A(b[0]), .B(n126), .Z(c[0]) );
  XNOR U162 ( .A(a[0]), .B(carry_on), .Z(n126) );
endmodule
