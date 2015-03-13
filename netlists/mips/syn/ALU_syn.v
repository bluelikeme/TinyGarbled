
module ALU ( a_in, b_in, alu_function, c_alu );
  input [31:0] a_in;
  input [31:0] b_in;
  input [3:0] alu_function;
  output [31:0] c_alu;
  wire   n383, n384, n385, n386, n387, n388, n389, n390, n391, n392, n393,
         n394, n395, n396, n397, n398, n399, n400, n401, n402, n403, n404,
         n405, n406, n407, n408, n409, n410, n411, n412, n413, n414, n415,
         n416, n417, n418, n419, n420, n421, n422, n423, n424, n425, n426,
         n427, n428, n429, n430, n431, n432, n433, n434, n435, n436, n437,
         n438, n439, n440, n441, n442, n443, n444, n445, n446, n447, n448,
         n449, n450, n451, n452, n453, n454, n455, n456, n457, n458, n459,
         n460, n461, n462, n463, n464, n465, n466, n467, n468, n469, n470,
         n471, n472, n473, n474, n475, n476, n477, n478, n479, n480, n481,
         n482, n483, n484, n485, n486, n487, n488, n489, n490, n491, n492,
         n493, n494, n495, n496, n497, n498, n499, n500, n501, n502, n503,
         n504, n505, n506, n507, n508, n509, n510, n511, n512, n513, n514,
         n515, n516, n517, n518, n519, n520, n521, n522, n523, n524, n525,
         n526, n527, n528, n529, n530, n531, n532, n533, n534, n535, n536,
         n537, n538, n539, n540, n541, n542, n543, n544, n545, n546, n547,
         n548, n549, n550, n551, n552, n553, n554, n555, n556, n557, n558,
         n559, n560, n561, n562, n563, n564, n565, n566, n567, n568, n569,
         n570, n571, n572, n573, n574, n575, n576, n577, n578, n579, n580,
         n581, n582, n583, n584, n585, n586, n587, n588, n589, n590, n591,
         n592, n593, n594, n595, n596, n597, n598, n599, n600, n601, n602,
         n603, n604, n605, n606, n607, n608, n609, n610, n611, n612, n613,
         n614, n615, n616, n617, n618, n619, n620, n621, n622, n623, n624,
         n625, n626, n627, n628, n629, n630, n631, n632, n633, n634, n635,
         n636, n637, n638, n639, n640, n641, n642, n643, n644, n645, n646,
         n647, n648, n649, n650, n651, n652, n653, n654, n655, n656, n657,
         n658, n659, n660, n661, n662, n663, n664, n665, n666, n667, n668,
         n669, n670, n671, n672, n673, n674, n675, n676, n677, n678, n679,
         n680, n681, n682, n683, n684, n685, n686, n687, n688, n689, n690,
         n691, n692, n693, n694, n695, n696, n697, n698, n699, n700, n701,
         n702, n703, n704, n705, n706, n707, n708, n709, n710, n711, n712,
         n713, n714, n715, n716, n717, n718, n719, n720, n721, n722, n723,
         n724, n725, n726, n727, n728, n729, n730, n731, n732, n733, n734,
         n735, n736, n737, n738, n739, n740, n741, n742, n743, n744, n745,
         n746, n747, n748, n749, n750, n751, n752, n753, n754, n755, n756,
         n757, n758, n759, n760, n761, n762, n763, n764, n765, n766, n767,
         n768, n769, n770, n771, n772, n773, n774, n775, n776, n777, n778,
         n779, n780, n781, n782, n783, n784, n785, n786, n787, n788, n789,
         n790, n791, n792, n793, n794, n795, n796, n797, n798, n799, n800,
         n801, n802, n803, n804, n805, n806, n807, n808, n809, n810, n811,
         n812, n813, n814, n815, n816, n817, n818, n819, n820, n821, n822,
         n823, n824, n825, n826, n827, n828, n829, n830, n831, n832, n833,
         n834, n835, n836, n837, n838, n839, n840, n841, n842, n843, n844,
         n845, n846, n847, n848, n849, n850, n851, n852, n853, n854, n855,
         n856, n857, n858, n859, n860, n861, n862, n863, n864, n865, n866,
         n867, n868, n869, n870, n871, n872, n873, n874, n875, n876, n877,
         n878, n879, n880, n881, n882, n883, n884, n885, n886, n887, n888,
         n889, n890, n891, n892, n893, n894, n895, n896, n897, n898, n899,
         n900, n901, n902, n903, n904, n905, n906, n907, n908, n909, n910,
         n911, n912, n913, n914, n915, n916, n917, n918, n919, n920, n921,
         n922, n923, n924, n925, n926, n927, n928, n929, n930, n931, n932,
         n933, n934, n935, n936, n937;

  NAND U449 ( .A(n383), .B(n384), .Z(c_alu[9]) );
  AND U450 ( .A(n385), .B(n386), .Z(n384) );
  NAND U451 ( .A(n387), .B(n388), .Z(n386) );
  XOR U452 ( .A(n389), .B(n390), .Z(n387) );
  NAND U453 ( .A(n391), .B(n392), .Z(n385) );
  XOR U454 ( .A(b_in[9]), .B(a_in[9]), .Z(n391) );
  AND U455 ( .A(n393), .B(n394), .Z(n383) );
  NAND U456 ( .A(n395), .B(n396), .Z(n394) );
  AND U457 ( .A(a_in[9]), .B(b_in[9]), .Z(n395) );
  MUX U458 ( .IN0(n397), .IN1(n398), .SEL(n399), .F(n393) );
  NOR U459 ( .A(b_in[9]), .B(a_in[9]), .Z(n399) );
  NAND U460 ( .A(n400), .B(n401), .Z(c_alu[8]) );
  AND U461 ( .A(n402), .B(n403), .Z(n401) );
  NAND U462 ( .A(n404), .B(n388), .Z(n403) );
  XOR U463 ( .A(n405), .B(n406), .Z(n404) );
  NAND U464 ( .A(n407), .B(n392), .Z(n402) );
  XOR U465 ( .A(b_in[8]), .B(a_in[8]), .Z(n407) );
  AND U466 ( .A(n408), .B(n409), .Z(n400) );
  NAND U467 ( .A(n410), .B(n396), .Z(n409) );
  AND U468 ( .A(a_in[8]), .B(b_in[8]), .Z(n410) );
  MUX U469 ( .IN0(n397), .IN1(n398), .SEL(n411), .F(n408) );
  NOR U470 ( .A(b_in[8]), .B(a_in[8]), .Z(n411) );
  NAND U471 ( .A(n412), .B(n413), .Z(c_alu[7]) );
  AND U472 ( .A(n414), .B(n415), .Z(n413) );
  NAND U473 ( .A(n416), .B(n388), .Z(n415) );
  XOR U474 ( .A(n417), .B(n418), .Z(n416) );
  NAND U475 ( .A(n419), .B(n392), .Z(n414) );
  XOR U476 ( .A(b_in[7]), .B(a_in[7]), .Z(n419) );
  AND U477 ( .A(n420), .B(n421), .Z(n412) );
  NAND U478 ( .A(n422), .B(n396), .Z(n421) );
  AND U479 ( .A(a_in[7]), .B(b_in[7]), .Z(n422) );
  MUX U480 ( .IN0(n397), .IN1(n398), .SEL(n423), .F(n420) );
  NOR U481 ( .A(b_in[7]), .B(a_in[7]), .Z(n423) );
  NAND U482 ( .A(n424), .B(n425), .Z(c_alu[6]) );
  AND U483 ( .A(n426), .B(n427), .Z(n425) );
  NAND U484 ( .A(n428), .B(n388), .Z(n427) );
  XOR U485 ( .A(n429), .B(n430), .Z(n428) );
  NAND U486 ( .A(n431), .B(n392), .Z(n426) );
  XOR U487 ( .A(b_in[6]), .B(a_in[6]), .Z(n431) );
  AND U488 ( .A(n432), .B(n433), .Z(n424) );
  NAND U489 ( .A(n434), .B(n396), .Z(n433) );
  AND U490 ( .A(a_in[6]), .B(b_in[6]), .Z(n434) );
  MUX U491 ( .IN0(n397), .IN1(n398), .SEL(n435), .F(n432) );
  NOR U492 ( .A(b_in[6]), .B(a_in[6]), .Z(n435) );
  NAND U493 ( .A(n436), .B(n437), .Z(c_alu[5]) );
  AND U494 ( .A(n438), .B(n439), .Z(n437) );
  NAND U495 ( .A(n440), .B(n388), .Z(n439) );
  XOR U496 ( .A(n441), .B(n442), .Z(n440) );
  NAND U497 ( .A(n443), .B(n392), .Z(n438) );
  XOR U498 ( .A(b_in[5]), .B(a_in[5]), .Z(n443) );
  AND U499 ( .A(n444), .B(n445), .Z(n436) );
  NAND U500 ( .A(n446), .B(n396), .Z(n445) );
  AND U501 ( .A(a_in[5]), .B(b_in[5]), .Z(n446) );
  MUX U502 ( .IN0(n397), .IN1(n398), .SEL(n447), .F(n444) );
  NOR U503 ( .A(b_in[5]), .B(a_in[5]), .Z(n447) );
  NAND U504 ( .A(n448), .B(n449), .Z(c_alu[4]) );
  AND U505 ( .A(n450), .B(n451), .Z(n449) );
  NAND U506 ( .A(n452), .B(n388), .Z(n451) );
  XOR U507 ( .A(n453), .B(n454), .Z(n452) );
  NAND U508 ( .A(n455), .B(n392), .Z(n450) );
  XOR U509 ( .A(b_in[4]), .B(a_in[4]), .Z(n455) );
  AND U510 ( .A(n456), .B(n457), .Z(n448) );
  NAND U511 ( .A(n458), .B(n396), .Z(n457) );
  AND U512 ( .A(a_in[4]), .B(b_in[4]), .Z(n458) );
  MUX U513 ( .IN0(n397), .IN1(n398), .SEL(n459), .F(n456) );
  NOR U514 ( .A(b_in[4]), .B(a_in[4]), .Z(n459) );
  NAND U515 ( .A(n460), .B(n461), .Z(c_alu[3]) );
  AND U516 ( .A(n462), .B(n463), .Z(n461) );
  NAND U517 ( .A(n464), .B(n388), .Z(n463) );
  XOR U518 ( .A(n465), .B(n466), .Z(n464) );
  NAND U519 ( .A(n467), .B(n392), .Z(n462) );
  XOR U520 ( .A(b_in[3]), .B(a_in[3]), .Z(n467) );
  AND U521 ( .A(n468), .B(n469), .Z(n460) );
  NAND U522 ( .A(n470), .B(n396), .Z(n469) );
  AND U523 ( .A(a_in[3]), .B(b_in[3]), .Z(n470) );
  MUX U524 ( .IN0(n397), .IN1(n398), .SEL(n471), .F(n468) );
  NOR U525 ( .A(b_in[3]), .B(a_in[3]), .Z(n471) );
  NAND U526 ( .A(n472), .B(n473), .Z(c_alu[31]) );
  AND U527 ( .A(n474), .B(n475), .Z(n473) );
  NAND U528 ( .A(n388), .B(n476), .Z(n475) );
  NAND U529 ( .A(n477), .B(n392), .Z(n474) );
  XOR U530 ( .A(b_in[31]), .B(a_in[31]), .Z(n477) );
  AND U531 ( .A(n478), .B(n479), .Z(n472) );
  NAND U532 ( .A(b_in[31]), .B(n480), .Z(n479) );
  AND U533 ( .A(n396), .B(a_in[31]), .Z(n480) );
  MUX U534 ( .IN0(n397), .IN1(n398), .SEL(n481), .F(n478) );
  AND U535 ( .A(n482), .B(n483), .Z(n481) );
  NAND U536 ( .A(n484), .B(n485), .Z(c_alu[30]) );
  AND U537 ( .A(n486), .B(n487), .Z(n485) );
  NAND U538 ( .A(n488), .B(n388), .Z(n487) );
  XOR U539 ( .A(n489), .B(n490), .Z(n488) );
  NAND U540 ( .A(n491), .B(n392), .Z(n486) );
  XNOR U541 ( .A(n492), .B(a_in[30]), .Z(n491) );
  AND U542 ( .A(n493), .B(n494), .Z(n484) );
  NAND U543 ( .A(b_in[30]), .B(n495), .Z(n494) );
  AND U544 ( .A(n396), .B(a_in[30]), .Z(n495) );
  MUX U545 ( .IN0(n397), .IN1(n398), .SEL(n496), .F(n493) );
  AND U546 ( .A(n492), .B(n497), .Z(n496) );
  IV U547 ( .A(a_in[30]), .Z(n497) );
  IV U548 ( .A(b_in[30]), .Z(n492) );
  NAND U549 ( .A(n498), .B(n499), .Z(c_alu[2]) );
  AND U550 ( .A(n500), .B(n501), .Z(n499) );
  NAND U551 ( .A(n502), .B(n388), .Z(n501) );
  XOR U552 ( .A(n503), .B(n504), .Z(n502) );
  NAND U553 ( .A(n505), .B(n392), .Z(n500) );
  XOR U554 ( .A(b_in[2]), .B(a_in[2]), .Z(n505) );
  AND U555 ( .A(n506), .B(n507), .Z(n498) );
  NAND U556 ( .A(n508), .B(n396), .Z(n507) );
  AND U557 ( .A(a_in[2]), .B(b_in[2]), .Z(n508) );
  MUX U558 ( .IN0(n397), .IN1(n398), .SEL(n509), .F(n506) );
  NOR U559 ( .A(b_in[2]), .B(a_in[2]), .Z(n509) );
  NAND U560 ( .A(n510), .B(n511), .Z(c_alu[29]) );
  AND U561 ( .A(n512), .B(n513), .Z(n511) );
  NAND U562 ( .A(n514), .B(n388), .Z(n513) );
  XOR U563 ( .A(n515), .B(n516), .Z(n514) );
  NAND U564 ( .A(n517), .B(n392), .Z(n512) );
  XNOR U565 ( .A(n518), .B(a_in[29]), .Z(n517) );
  AND U566 ( .A(n519), .B(n520), .Z(n510) );
  NAND U567 ( .A(b_in[29]), .B(n521), .Z(n520) );
  AND U568 ( .A(n396), .B(a_in[29]), .Z(n521) );
  MUX U569 ( .IN0(n397), .IN1(n398), .SEL(n522), .F(n519) );
  AND U570 ( .A(n518), .B(n523), .Z(n522) );
  IV U571 ( .A(a_in[29]), .Z(n523) );
  IV U572 ( .A(b_in[29]), .Z(n518) );
  NAND U573 ( .A(n524), .B(n525), .Z(c_alu[28]) );
  AND U574 ( .A(n526), .B(n527), .Z(n525) );
  NAND U575 ( .A(n528), .B(n388), .Z(n527) );
  XOR U576 ( .A(n529), .B(n530), .Z(n528) );
  NAND U577 ( .A(n531), .B(n392), .Z(n526) );
  XNOR U578 ( .A(n532), .B(a_in[28]), .Z(n531) );
  AND U579 ( .A(n533), .B(n534), .Z(n524) );
  NAND U580 ( .A(b_in[28]), .B(n535), .Z(n534) );
  AND U581 ( .A(n396), .B(a_in[28]), .Z(n535) );
  MUX U582 ( .IN0(n397), .IN1(n398), .SEL(n536), .F(n533) );
  AND U583 ( .A(n532), .B(n537), .Z(n536) );
  IV U584 ( .A(a_in[28]), .Z(n537) );
  IV U585 ( .A(b_in[28]), .Z(n532) );
  NAND U586 ( .A(n538), .B(n539), .Z(c_alu[27]) );
  AND U587 ( .A(n540), .B(n541), .Z(n539) );
  NAND U588 ( .A(n542), .B(n388), .Z(n541) );
  XOR U589 ( .A(n543), .B(n544), .Z(n542) );
  NAND U590 ( .A(n545), .B(n392), .Z(n540) );
  XNOR U591 ( .A(n546), .B(a_in[27]), .Z(n545) );
  AND U592 ( .A(n547), .B(n548), .Z(n538) );
  NAND U593 ( .A(b_in[27]), .B(n549), .Z(n548) );
  AND U594 ( .A(n396), .B(a_in[27]), .Z(n549) );
  MUX U595 ( .IN0(n397), .IN1(n398), .SEL(n550), .F(n547) );
  AND U596 ( .A(n546), .B(n551), .Z(n550) );
  IV U597 ( .A(a_in[27]), .Z(n551) );
  IV U598 ( .A(b_in[27]), .Z(n546) );
  NAND U599 ( .A(n552), .B(n553), .Z(c_alu[26]) );
  AND U600 ( .A(n554), .B(n555), .Z(n553) );
  NAND U601 ( .A(n556), .B(n388), .Z(n555) );
  XOR U602 ( .A(n557), .B(n558), .Z(n556) );
  NAND U603 ( .A(n559), .B(n392), .Z(n554) );
  XNOR U604 ( .A(n560), .B(a_in[26]), .Z(n559) );
  AND U605 ( .A(n561), .B(n562), .Z(n552) );
  NAND U606 ( .A(b_in[26]), .B(n563), .Z(n562) );
  AND U607 ( .A(n396), .B(a_in[26]), .Z(n563) );
  MUX U608 ( .IN0(n397), .IN1(n398), .SEL(n564), .F(n561) );
  AND U609 ( .A(n560), .B(n565), .Z(n564) );
  IV U610 ( .A(a_in[26]), .Z(n565) );
  IV U611 ( .A(b_in[26]), .Z(n560) );
  NAND U612 ( .A(n566), .B(n567), .Z(c_alu[25]) );
  AND U613 ( .A(n568), .B(n569), .Z(n567) );
  NAND U614 ( .A(n570), .B(n388), .Z(n569) );
  XOR U615 ( .A(n571), .B(n572), .Z(n570) );
  NAND U616 ( .A(n573), .B(n392), .Z(n568) );
  XNOR U617 ( .A(n574), .B(a_in[25]), .Z(n573) );
  AND U618 ( .A(n575), .B(n576), .Z(n566) );
  NAND U619 ( .A(b_in[25]), .B(n577), .Z(n576) );
  AND U620 ( .A(n396), .B(a_in[25]), .Z(n577) );
  MUX U621 ( .IN0(n397), .IN1(n398), .SEL(n578), .F(n575) );
  AND U622 ( .A(n574), .B(n579), .Z(n578) );
  IV U623 ( .A(a_in[25]), .Z(n579) );
  IV U624 ( .A(b_in[25]), .Z(n574) );
  NAND U625 ( .A(n580), .B(n581), .Z(c_alu[24]) );
  AND U626 ( .A(n582), .B(n583), .Z(n581) );
  NAND U627 ( .A(n584), .B(n388), .Z(n583) );
  XOR U628 ( .A(n585), .B(n586), .Z(n584) );
  NAND U629 ( .A(n587), .B(n392), .Z(n582) );
  XNOR U630 ( .A(n588), .B(a_in[24]), .Z(n587) );
  AND U631 ( .A(n589), .B(n590), .Z(n580) );
  NAND U632 ( .A(b_in[24]), .B(n591), .Z(n590) );
  AND U633 ( .A(n396), .B(a_in[24]), .Z(n591) );
  MUX U634 ( .IN0(n397), .IN1(n398), .SEL(n592), .F(n589) );
  AND U635 ( .A(n588), .B(n593), .Z(n592) );
  IV U636 ( .A(a_in[24]), .Z(n593) );
  IV U637 ( .A(b_in[24]), .Z(n588) );
  NAND U638 ( .A(n594), .B(n595), .Z(c_alu[23]) );
  AND U639 ( .A(n596), .B(n597), .Z(n595) );
  NAND U640 ( .A(n598), .B(n388), .Z(n597) );
  XOR U641 ( .A(n599), .B(n600), .Z(n598) );
  NAND U642 ( .A(n601), .B(n392), .Z(n596) );
  XNOR U643 ( .A(n602), .B(a_in[23]), .Z(n601) );
  AND U644 ( .A(n603), .B(n604), .Z(n594) );
  NAND U645 ( .A(b_in[23]), .B(n605), .Z(n604) );
  AND U646 ( .A(n396), .B(a_in[23]), .Z(n605) );
  MUX U647 ( .IN0(n397), .IN1(n398), .SEL(n606), .F(n603) );
  AND U648 ( .A(n602), .B(n607), .Z(n606) );
  IV U649 ( .A(a_in[23]), .Z(n607) );
  IV U650 ( .A(b_in[23]), .Z(n602) );
  NAND U651 ( .A(n608), .B(n609), .Z(c_alu[22]) );
  AND U652 ( .A(n610), .B(n611), .Z(n609) );
  NAND U653 ( .A(n612), .B(n388), .Z(n611) );
  XOR U654 ( .A(n613), .B(n614), .Z(n612) );
  NAND U655 ( .A(n615), .B(n392), .Z(n610) );
  XNOR U656 ( .A(n616), .B(a_in[22]), .Z(n615) );
  AND U657 ( .A(n617), .B(n618), .Z(n608) );
  NAND U658 ( .A(b_in[22]), .B(n619), .Z(n618) );
  AND U659 ( .A(n396), .B(a_in[22]), .Z(n619) );
  MUX U660 ( .IN0(n397), .IN1(n398), .SEL(n620), .F(n617) );
  AND U661 ( .A(n616), .B(n621), .Z(n620) );
  IV U662 ( .A(a_in[22]), .Z(n621) );
  IV U663 ( .A(b_in[22]), .Z(n616) );
  NAND U664 ( .A(n622), .B(n623), .Z(c_alu[21]) );
  AND U665 ( .A(n624), .B(n625), .Z(n623) );
  NAND U666 ( .A(n626), .B(n388), .Z(n625) );
  XOR U667 ( .A(n627), .B(n628), .Z(n626) );
  NAND U668 ( .A(n629), .B(n392), .Z(n624) );
  XNOR U669 ( .A(n630), .B(a_in[21]), .Z(n629) );
  AND U670 ( .A(n631), .B(n632), .Z(n622) );
  NAND U671 ( .A(b_in[21]), .B(n633), .Z(n632) );
  AND U672 ( .A(n396), .B(a_in[21]), .Z(n633) );
  MUX U673 ( .IN0(n397), .IN1(n398), .SEL(n634), .F(n631) );
  AND U674 ( .A(n630), .B(n635), .Z(n634) );
  IV U675 ( .A(a_in[21]), .Z(n635) );
  IV U676 ( .A(b_in[21]), .Z(n630) );
  NAND U677 ( .A(n636), .B(n637), .Z(c_alu[20]) );
  AND U678 ( .A(n638), .B(n639), .Z(n637) );
  NAND U679 ( .A(n640), .B(n388), .Z(n639) );
  XOR U680 ( .A(n641), .B(n642), .Z(n640) );
  NAND U681 ( .A(n643), .B(n392), .Z(n638) );
  XNOR U682 ( .A(n644), .B(a_in[20]), .Z(n643) );
  AND U683 ( .A(n645), .B(n646), .Z(n636) );
  NAND U684 ( .A(b_in[20]), .B(n647), .Z(n646) );
  AND U685 ( .A(n396), .B(a_in[20]), .Z(n647) );
  MUX U686 ( .IN0(n397), .IN1(n398), .SEL(n648), .F(n645) );
  AND U687 ( .A(n644), .B(n649), .Z(n648) );
  IV U688 ( .A(a_in[20]), .Z(n649) );
  IV U689 ( .A(b_in[20]), .Z(n644) );
  NAND U690 ( .A(n650), .B(n651), .Z(c_alu[1]) );
  AND U691 ( .A(n652), .B(n653), .Z(n651) );
  NAND U692 ( .A(n654), .B(n388), .Z(n653) );
  XOR U693 ( .A(n655), .B(n656), .Z(n654) );
  NAND U694 ( .A(n657), .B(n392), .Z(n652) );
  XOR U695 ( .A(b_in[1]), .B(a_in[1]), .Z(n657) );
  AND U696 ( .A(n658), .B(n659), .Z(n650) );
  NAND U697 ( .A(n660), .B(n396), .Z(n659) );
  AND U698 ( .A(a_in[1]), .B(b_in[1]), .Z(n660) );
  MUX U699 ( .IN0(n397), .IN1(n398), .SEL(n661), .F(n658) );
  NOR U700 ( .A(b_in[1]), .B(a_in[1]), .Z(n661) );
  NAND U701 ( .A(n662), .B(n663), .Z(c_alu[19]) );
  AND U702 ( .A(n664), .B(n665), .Z(n663) );
  NAND U703 ( .A(n666), .B(n388), .Z(n665) );
  XOR U704 ( .A(n667), .B(n668), .Z(n666) );
  NAND U705 ( .A(n669), .B(n392), .Z(n664) );
  XNOR U706 ( .A(n670), .B(a_in[19]), .Z(n669) );
  AND U707 ( .A(n671), .B(n672), .Z(n662) );
  NAND U708 ( .A(b_in[19]), .B(n673), .Z(n672) );
  AND U709 ( .A(n396), .B(a_in[19]), .Z(n673) );
  MUX U710 ( .IN0(n397), .IN1(n398), .SEL(n674), .F(n671) );
  AND U711 ( .A(n670), .B(n675), .Z(n674) );
  IV U712 ( .A(a_in[19]), .Z(n675) );
  IV U713 ( .A(b_in[19]), .Z(n670) );
  NAND U714 ( .A(n676), .B(n677), .Z(c_alu[18]) );
  AND U715 ( .A(n678), .B(n679), .Z(n677) );
  NAND U716 ( .A(n680), .B(n388), .Z(n679) );
  XOR U717 ( .A(n681), .B(n682), .Z(n680) );
  NAND U718 ( .A(n683), .B(n392), .Z(n678) );
  XNOR U719 ( .A(n684), .B(a_in[18]), .Z(n683) );
  AND U720 ( .A(n685), .B(n686), .Z(n676) );
  NAND U721 ( .A(b_in[18]), .B(n687), .Z(n686) );
  AND U722 ( .A(n396), .B(a_in[18]), .Z(n687) );
  MUX U723 ( .IN0(n397), .IN1(n398), .SEL(n688), .F(n685) );
  AND U724 ( .A(n684), .B(n689), .Z(n688) );
  IV U725 ( .A(a_in[18]), .Z(n689) );
  IV U726 ( .A(b_in[18]), .Z(n684) );
  NAND U727 ( .A(n690), .B(n691), .Z(c_alu[17]) );
  AND U728 ( .A(n692), .B(n693), .Z(n691) );
  NAND U729 ( .A(n694), .B(n388), .Z(n693) );
  XOR U730 ( .A(n695), .B(n696), .Z(n694) );
  NAND U731 ( .A(n697), .B(n392), .Z(n692) );
  XNOR U732 ( .A(n698), .B(a_in[17]), .Z(n697) );
  AND U733 ( .A(n699), .B(n700), .Z(n690) );
  NAND U734 ( .A(b_in[17]), .B(n701), .Z(n700) );
  AND U735 ( .A(n396), .B(a_in[17]), .Z(n701) );
  MUX U736 ( .IN0(n397), .IN1(n398), .SEL(n702), .F(n699) );
  AND U737 ( .A(n698), .B(n703), .Z(n702) );
  IV U738 ( .A(a_in[17]), .Z(n703) );
  IV U739 ( .A(b_in[17]), .Z(n698) );
  NAND U740 ( .A(n704), .B(n705), .Z(c_alu[16]) );
  AND U741 ( .A(n706), .B(n707), .Z(n705) );
  NAND U742 ( .A(n708), .B(n388), .Z(n707) );
  XOR U743 ( .A(n709), .B(n710), .Z(n708) );
  NAND U744 ( .A(n711), .B(n392), .Z(n706) );
  XNOR U745 ( .A(n712), .B(a_in[16]), .Z(n711) );
  AND U746 ( .A(n713), .B(n714), .Z(n704) );
  NAND U747 ( .A(b_in[16]), .B(n715), .Z(n714) );
  AND U748 ( .A(n396), .B(a_in[16]), .Z(n715) );
  MUX U749 ( .IN0(n397), .IN1(n398), .SEL(n716), .F(n713) );
  AND U750 ( .A(n712), .B(n717), .Z(n716) );
  IV U751 ( .A(a_in[16]), .Z(n717) );
  IV U752 ( .A(b_in[16]), .Z(n712) );
  NAND U753 ( .A(n718), .B(n719), .Z(c_alu[15]) );
  AND U754 ( .A(n720), .B(n721), .Z(n719) );
  NAND U755 ( .A(n722), .B(n388), .Z(n721) );
  XOR U756 ( .A(n723), .B(n724), .Z(n722) );
  NAND U757 ( .A(n725), .B(n392), .Z(n720) );
  XNOR U758 ( .A(n726), .B(a_in[15]), .Z(n725) );
  AND U759 ( .A(n727), .B(n728), .Z(n718) );
  NAND U760 ( .A(b_in[15]), .B(n729), .Z(n728) );
  AND U761 ( .A(n396), .B(a_in[15]), .Z(n729) );
  MUX U762 ( .IN0(n397), .IN1(n398), .SEL(n730), .F(n727) );
  AND U763 ( .A(n726), .B(n731), .Z(n730) );
  IV U764 ( .A(a_in[15]), .Z(n731) );
  IV U765 ( .A(b_in[15]), .Z(n726) );
  NAND U766 ( .A(n732), .B(n733), .Z(c_alu[14]) );
  AND U767 ( .A(n734), .B(n735), .Z(n733) );
  NAND U768 ( .A(n736), .B(n388), .Z(n735) );
  XOR U769 ( .A(n737), .B(n738), .Z(n736) );
  NAND U770 ( .A(n739), .B(n392), .Z(n734) );
  XNOR U771 ( .A(n740), .B(a_in[14]), .Z(n739) );
  AND U772 ( .A(n741), .B(n742), .Z(n732) );
  NAND U773 ( .A(b_in[14]), .B(n743), .Z(n742) );
  AND U774 ( .A(n396), .B(a_in[14]), .Z(n743) );
  MUX U775 ( .IN0(n397), .IN1(n398), .SEL(n744), .F(n741) );
  AND U776 ( .A(n740), .B(n745), .Z(n744) );
  IV U777 ( .A(a_in[14]), .Z(n745) );
  IV U778 ( .A(b_in[14]), .Z(n740) );
  NAND U779 ( .A(n746), .B(n747), .Z(c_alu[13]) );
  AND U780 ( .A(n748), .B(n749), .Z(n747) );
  NAND U781 ( .A(n750), .B(n388), .Z(n749) );
  XOR U782 ( .A(n751), .B(n752), .Z(n750) );
  NAND U783 ( .A(n753), .B(n392), .Z(n748) );
  XNOR U784 ( .A(n754), .B(a_in[13]), .Z(n753) );
  AND U785 ( .A(n755), .B(n756), .Z(n746) );
  NAND U786 ( .A(b_in[13]), .B(n757), .Z(n756) );
  AND U787 ( .A(n396), .B(a_in[13]), .Z(n757) );
  MUX U788 ( .IN0(n397), .IN1(n398), .SEL(n758), .F(n755) );
  AND U789 ( .A(n754), .B(n759), .Z(n758) );
  IV U790 ( .A(a_in[13]), .Z(n759) );
  IV U791 ( .A(b_in[13]), .Z(n754) );
  NAND U792 ( .A(n760), .B(n761), .Z(c_alu[12]) );
  AND U793 ( .A(n762), .B(n763), .Z(n761) );
  NAND U794 ( .A(n764), .B(n388), .Z(n763) );
  XOR U795 ( .A(n765), .B(n766), .Z(n764) );
  NAND U796 ( .A(n767), .B(n392), .Z(n762) );
  XNOR U797 ( .A(n768), .B(a_in[12]), .Z(n767) );
  AND U798 ( .A(n769), .B(n770), .Z(n760) );
  NAND U799 ( .A(b_in[12]), .B(n771), .Z(n770) );
  AND U800 ( .A(n396), .B(a_in[12]), .Z(n771) );
  MUX U801 ( .IN0(n397), .IN1(n398), .SEL(n772), .F(n769) );
  AND U802 ( .A(n768), .B(n773), .Z(n772) );
  IV U803 ( .A(a_in[12]), .Z(n773) );
  IV U804 ( .A(b_in[12]), .Z(n768) );
  NAND U805 ( .A(n774), .B(n775), .Z(c_alu[11]) );
  AND U806 ( .A(n776), .B(n777), .Z(n775) );
  NAND U807 ( .A(n778), .B(n388), .Z(n777) );
  XOR U808 ( .A(n779), .B(n780), .Z(n778) );
  NAND U809 ( .A(n781), .B(n392), .Z(n776) );
  XNOR U810 ( .A(n782), .B(a_in[11]), .Z(n781) );
  AND U811 ( .A(n783), .B(n784), .Z(n774) );
  NAND U812 ( .A(b_in[11]), .B(n785), .Z(n784) );
  AND U813 ( .A(n396), .B(a_in[11]), .Z(n785) );
  MUX U814 ( .IN0(n397), .IN1(n398), .SEL(n786), .F(n783) );
  AND U815 ( .A(n782), .B(n787), .Z(n786) );
  IV U816 ( .A(a_in[11]), .Z(n787) );
  IV U817 ( .A(b_in[11]), .Z(n782) );
  NAND U818 ( .A(n788), .B(n789), .Z(c_alu[10]) );
  AND U819 ( .A(n790), .B(n791), .Z(n789) );
  NAND U820 ( .A(n792), .B(n388), .Z(n791) );
  XOR U821 ( .A(n793), .B(n794), .Z(n792) );
  NAND U822 ( .A(n795), .B(n392), .Z(n790) );
  XNOR U823 ( .A(n796), .B(a_in[10]), .Z(n795) );
  AND U824 ( .A(n797), .B(n798), .Z(n788) );
  NAND U825 ( .A(b_in[10]), .B(n799), .Z(n798) );
  AND U826 ( .A(n396), .B(a_in[10]), .Z(n799) );
  MUX U827 ( .IN0(n397), .IN1(n398), .SEL(n800), .F(n797) );
  AND U828 ( .A(n796), .B(n801), .Z(n800) );
  IV U829 ( .A(a_in[10]), .Z(n801) );
  IV U830 ( .A(b_in[10]), .Z(n796) );
  NAND U831 ( .A(n802), .B(n803), .Z(c_alu[0]) );
  AND U832 ( .A(n804), .B(n805), .Z(n803) );
  NAND U833 ( .A(n806), .B(n388), .Z(n805) );
  NAND U834 ( .A(n807), .B(n808), .Z(n388) );
  OR U835 ( .A(n809), .B(n810), .Z(n807) );
  XOR U836 ( .A(n811), .B(n812), .Z(n806) );
  AND U837 ( .A(n813), .B(n814), .Z(n804) );
  NANDN U838 ( .A(n815), .B(n816), .Z(n814) );
  XNOR U839 ( .A(n817), .B(n818), .Z(n816) );
  AND U840 ( .A(n819), .B(n820), .Z(n817) );
  XNOR U841 ( .A(n821), .B(n822), .Z(n820) );
  NAND U842 ( .A(n823), .B(n824), .Z(n813) );
  NAND U843 ( .A(n825), .B(n826), .Z(n824) );
  NAND U844 ( .A(n476), .B(n827), .Z(n826) );
  NAND U845 ( .A(b_in[31]), .B(n483), .Z(n827) );
  XOR U846 ( .A(n822), .B(n819), .Z(n476) );
  XNOR U847 ( .A(n818), .B(n483), .Z(n819) );
  IV U848 ( .A(a_in[31]), .Z(n483) );
  IV U849 ( .A(n821), .Z(n818) );
  XOR U850 ( .A(n828), .B(n829), .Z(n821) );
  AND U851 ( .A(n490), .B(n830), .Z(n829) );
  XNOR U852 ( .A(n828), .B(n489), .Z(n830) );
  XOR U853 ( .A(n831), .B(b_in[30]), .Z(n489) );
  XNOR U854 ( .A(n828), .B(a_in[30]), .Z(n490) );
  XOR U855 ( .A(n832), .B(n833), .Z(n828) );
  AND U856 ( .A(n516), .B(n834), .Z(n833) );
  XNOR U857 ( .A(n832), .B(n515), .Z(n834) );
  XOR U858 ( .A(n831), .B(b_in[29]), .Z(n515) );
  XNOR U859 ( .A(n832), .B(a_in[29]), .Z(n516) );
  XOR U860 ( .A(n835), .B(n836), .Z(n832) );
  AND U861 ( .A(n530), .B(n837), .Z(n836) );
  XNOR U862 ( .A(n835), .B(n529), .Z(n837) );
  XOR U863 ( .A(n831), .B(b_in[28]), .Z(n529) );
  XNOR U864 ( .A(n835), .B(a_in[28]), .Z(n530) );
  XOR U865 ( .A(n838), .B(n839), .Z(n835) );
  AND U866 ( .A(n544), .B(n840), .Z(n839) );
  XNOR U867 ( .A(n838), .B(n543), .Z(n840) );
  XOR U868 ( .A(n831), .B(b_in[27]), .Z(n543) );
  XNOR U869 ( .A(n838), .B(a_in[27]), .Z(n544) );
  XOR U870 ( .A(n841), .B(n842), .Z(n838) );
  AND U871 ( .A(n558), .B(n843), .Z(n842) );
  XNOR U872 ( .A(n841), .B(n557), .Z(n843) );
  XOR U873 ( .A(n831), .B(b_in[26]), .Z(n557) );
  XNOR U874 ( .A(n841), .B(a_in[26]), .Z(n558) );
  XOR U875 ( .A(n844), .B(n845), .Z(n841) );
  AND U876 ( .A(n572), .B(n846), .Z(n845) );
  XNOR U877 ( .A(n844), .B(n571), .Z(n846) );
  XOR U878 ( .A(n831), .B(b_in[25]), .Z(n571) );
  XNOR U879 ( .A(n844), .B(a_in[25]), .Z(n572) );
  XOR U880 ( .A(n847), .B(n848), .Z(n844) );
  AND U881 ( .A(n586), .B(n849), .Z(n848) );
  XNOR U882 ( .A(n847), .B(n585), .Z(n849) );
  XOR U883 ( .A(n831), .B(b_in[24]), .Z(n585) );
  XNOR U884 ( .A(n847), .B(a_in[24]), .Z(n586) );
  XOR U885 ( .A(n850), .B(n851), .Z(n847) );
  AND U886 ( .A(n600), .B(n852), .Z(n851) );
  XNOR U887 ( .A(n850), .B(n599), .Z(n852) );
  XOR U888 ( .A(n831), .B(b_in[23]), .Z(n599) );
  XNOR U889 ( .A(n850), .B(a_in[23]), .Z(n600) );
  XOR U890 ( .A(n853), .B(n854), .Z(n850) );
  AND U891 ( .A(n614), .B(n855), .Z(n854) );
  XNOR U892 ( .A(n853), .B(n613), .Z(n855) );
  XOR U893 ( .A(n831), .B(b_in[22]), .Z(n613) );
  XNOR U894 ( .A(n853), .B(a_in[22]), .Z(n614) );
  XOR U895 ( .A(n856), .B(n857), .Z(n853) );
  AND U896 ( .A(n628), .B(n858), .Z(n857) );
  XNOR U897 ( .A(n856), .B(n627), .Z(n858) );
  XOR U898 ( .A(n831), .B(b_in[21]), .Z(n627) );
  XNOR U899 ( .A(n856), .B(a_in[21]), .Z(n628) );
  XOR U900 ( .A(n859), .B(n860), .Z(n856) );
  AND U901 ( .A(n642), .B(n861), .Z(n860) );
  XNOR U902 ( .A(n859), .B(n641), .Z(n861) );
  XOR U903 ( .A(n831), .B(b_in[20]), .Z(n641) );
  XNOR U904 ( .A(n859), .B(a_in[20]), .Z(n642) );
  XOR U905 ( .A(n862), .B(n863), .Z(n859) );
  AND U906 ( .A(n668), .B(n864), .Z(n863) );
  XNOR U907 ( .A(n862), .B(n667), .Z(n864) );
  XOR U908 ( .A(n831), .B(b_in[19]), .Z(n667) );
  XNOR U909 ( .A(n862), .B(a_in[19]), .Z(n668) );
  XOR U910 ( .A(n865), .B(n866), .Z(n862) );
  AND U911 ( .A(n682), .B(n867), .Z(n866) );
  XNOR U912 ( .A(n865), .B(n681), .Z(n867) );
  XOR U913 ( .A(n831), .B(b_in[18]), .Z(n681) );
  XNOR U914 ( .A(n865), .B(a_in[18]), .Z(n682) );
  XOR U915 ( .A(n868), .B(n869), .Z(n865) );
  AND U916 ( .A(n696), .B(n870), .Z(n869) );
  XNOR U917 ( .A(n868), .B(n695), .Z(n870) );
  XOR U918 ( .A(n831), .B(b_in[17]), .Z(n695) );
  XNOR U919 ( .A(n868), .B(a_in[17]), .Z(n696) );
  XOR U920 ( .A(n871), .B(n872), .Z(n868) );
  AND U921 ( .A(n710), .B(n873), .Z(n872) );
  XNOR U922 ( .A(n871), .B(n709), .Z(n873) );
  XOR U923 ( .A(n831), .B(b_in[16]), .Z(n709) );
  XNOR U924 ( .A(n871), .B(a_in[16]), .Z(n710) );
  XOR U925 ( .A(n874), .B(n875), .Z(n871) );
  AND U926 ( .A(n724), .B(n876), .Z(n875) );
  XNOR U927 ( .A(n874), .B(n723), .Z(n876) );
  XOR U928 ( .A(n831), .B(b_in[15]), .Z(n723) );
  XNOR U929 ( .A(n874), .B(a_in[15]), .Z(n724) );
  XOR U930 ( .A(n877), .B(n878), .Z(n874) );
  AND U931 ( .A(n738), .B(n879), .Z(n878) );
  XNOR U932 ( .A(n877), .B(n737), .Z(n879) );
  XOR U933 ( .A(n831), .B(b_in[14]), .Z(n737) );
  XNOR U934 ( .A(n877), .B(a_in[14]), .Z(n738) );
  XOR U935 ( .A(n880), .B(n881), .Z(n877) );
  AND U936 ( .A(n752), .B(n882), .Z(n881) );
  XNOR U937 ( .A(n880), .B(n751), .Z(n882) );
  XOR U938 ( .A(n831), .B(b_in[13]), .Z(n751) );
  XNOR U939 ( .A(n880), .B(a_in[13]), .Z(n752) );
  XOR U940 ( .A(n883), .B(n884), .Z(n880) );
  AND U941 ( .A(n766), .B(n885), .Z(n884) );
  XNOR U942 ( .A(n883), .B(n765), .Z(n885) );
  XOR U943 ( .A(n831), .B(b_in[12]), .Z(n765) );
  XNOR U944 ( .A(n883), .B(a_in[12]), .Z(n766) );
  XOR U945 ( .A(n886), .B(n887), .Z(n883) );
  AND U946 ( .A(n780), .B(n888), .Z(n887) );
  XNOR U947 ( .A(n886), .B(n779), .Z(n888) );
  XOR U948 ( .A(n831), .B(b_in[11]), .Z(n779) );
  XNOR U949 ( .A(n886), .B(a_in[11]), .Z(n780) );
  XOR U950 ( .A(n889), .B(n890), .Z(n886) );
  AND U951 ( .A(n794), .B(n891), .Z(n890) );
  XNOR U952 ( .A(n889), .B(n793), .Z(n891) );
  XOR U953 ( .A(n831), .B(b_in[10]), .Z(n793) );
  XNOR U954 ( .A(n889), .B(a_in[10]), .Z(n794) );
  XOR U955 ( .A(n892), .B(n893), .Z(n889) );
  AND U956 ( .A(n389), .B(n894), .Z(n893) );
  XNOR U957 ( .A(n892), .B(n390), .Z(n894) );
  XNOR U958 ( .A(n895), .B(b_in[9]), .Z(n390) );
  XOR U959 ( .A(n896), .B(a_in[9]), .Z(n389) );
  IV U960 ( .A(n892), .Z(n896) );
  XOR U961 ( .A(n897), .B(n898), .Z(n892) );
  AND U962 ( .A(n406), .B(n899), .Z(n898) );
  XNOR U963 ( .A(n897), .B(n405), .Z(n899) );
  XOR U964 ( .A(n831), .B(b_in[8]), .Z(n405) );
  XNOR U965 ( .A(n897), .B(a_in[8]), .Z(n406) );
  XOR U966 ( .A(n900), .B(n901), .Z(n897) );
  AND U967 ( .A(n418), .B(n902), .Z(n901) );
  XNOR U968 ( .A(n900), .B(n417), .Z(n902) );
  XOR U969 ( .A(n831), .B(b_in[7]), .Z(n417) );
  XNOR U970 ( .A(n900), .B(a_in[7]), .Z(n418) );
  XOR U971 ( .A(n903), .B(n904), .Z(n900) );
  AND U972 ( .A(n430), .B(n905), .Z(n904) );
  XNOR U973 ( .A(n903), .B(n429), .Z(n905) );
  XOR U974 ( .A(n831), .B(b_in[6]), .Z(n429) );
  XNOR U975 ( .A(n903), .B(a_in[6]), .Z(n430) );
  XOR U976 ( .A(n906), .B(n907), .Z(n903) );
  AND U977 ( .A(n442), .B(n908), .Z(n907) );
  XNOR U978 ( .A(n906), .B(n441), .Z(n908) );
  XOR U979 ( .A(n831), .B(b_in[5]), .Z(n441) );
  XNOR U980 ( .A(n906), .B(a_in[5]), .Z(n442) );
  XOR U981 ( .A(n909), .B(n910), .Z(n906) );
  AND U982 ( .A(n454), .B(n911), .Z(n910) );
  XNOR U983 ( .A(n909), .B(n453), .Z(n911) );
  XOR U984 ( .A(n831), .B(b_in[4]), .Z(n453) );
  XNOR U985 ( .A(n909), .B(a_in[4]), .Z(n454) );
  XOR U986 ( .A(n912), .B(n913), .Z(n909) );
  AND U987 ( .A(n466), .B(n914), .Z(n913) );
  XNOR U988 ( .A(n912), .B(n465), .Z(n914) );
  XOR U989 ( .A(n831), .B(b_in[3]), .Z(n465) );
  XNOR U990 ( .A(n912), .B(a_in[3]), .Z(n466) );
  XOR U991 ( .A(n915), .B(n916), .Z(n912) );
  AND U992 ( .A(n504), .B(n917), .Z(n916) );
  XNOR U993 ( .A(n915), .B(n503), .Z(n917) );
  XOR U994 ( .A(n831), .B(b_in[2]), .Z(n503) );
  XNOR U995 ( .A(n915), .B(a_in[2]), .Z(n504) );
  XOR U996 ( .A(n918), .B(n919), .Z(n915) );
  AND U997 ( .A(n656), .B(n920), .Z(n919) );
  XNOR U998 ( .A(n918), .B(n655), .Z(n920) );
  XOR U999 ( .A(n831), .B(b_in[1]), .Z(n655) );
  XNOR U1000 ( .A(n918), .B(a_in[1]), .Z(n656) );
  XOR U1001 ( .A(n895), .B(n921), .Z(n918) );
  AND U1002 ( .A(n812), .B(n922), .Z(n921) );
  XNOR U1003 ( .A(n895), .B(n811), .Z(n922) );
  XOR U1004 ( .A(n831), .B(b_in[0]), .Z(n811) );
  XNOR U1005 ( .A(n895), .B(a_in[0]), .Z(n812) );
  IV U1006 ( .A(n831), .Z(n895) );
  XNOR U1007 ( .A(n831), .B(n482), .Z(n822) );
  NAND U1008 ( .A(n923), .B(n808), .Z(n831) );
  OR U1009 ( .A(n924), .B(n809), .Z(n808) );
  AND U1010 ( .A(n815), .B(n925), .Z(n923) );
  IV U1011 ( .A(n823), .Z(n925) );
  OR U1012 ( .A(n926), .B(n809), .Z(n815) );
  OR U1013 ( .A(alu_function[3]), .B(alu_function[2]), .Z(n809) );
  NAND U1014 ( .A(n482), .B(a_in[31]), .Z(n825) );
  IV U1015 ( .A(b_in[31]), .Z(n482) );
  ANDN U1016 ( .B(n927), .A(n928), .Z(n823) );
  AND U1017 ( .A(n929), .B(n930), .Z(n802) );
  MUX U1018 ( .IN0(n397), .IN1(n398), .SEL(n931), .F(n930) );
  NOR U1019 ( .A(a_in[0]), .B(b_in[0]), .Z(n931) );
  NAND U1020 ( .A(n932), .B(alu_function[3]), .Z(n398) );
  ANDN U1021 ( .B(n933), .A(n928), .Z(n932) );
  OR U1022 ( .A(alu_function[0]), .B(alu_function[1]), .Z(n928) );
  IV U1023 ( .A(alu_function[2]), .Z(n933) );
  NANDN U1024 ( .A(n810), .B(n927), .Z(n397) );
  NANDN U1025 ( .A(alu_function[1]), .B(alu_function[0]), .Z(n810) );
  AND U1026 ( .A(n934), .B(n935), .Z(n929) );
  NAND U1027 ( .A(n936), .B(n396), .Z(n935) );
  ANDN U1028 ( .B(n927), .A(n924), .Z(n396) );
  NANDN U1029 ( .A(alu_function[0]), .B(alu_function[1]), .Z(n924) );
  AND U1030 ( .A(b_in[0]), .B(a_in[0]), .Z(n936) );
  NAND U1031 ( .A(n937), .B(n392), .Z(n934) );
  ANDN U1032 ( .B(n927), .A(n926), .Z(n392) );
  NAND U1033 ( .A(alu_function[1]), .B(alu_function[0]), .Z(n926) );
  ANDN U1034 ( .B(alu_function[2]), .A(alu_function[3]), .Z(n927) );
  XOR U1035 ( .A(b_in[0]), .B(a_in[0]), .Z(n937) );
endmodule
