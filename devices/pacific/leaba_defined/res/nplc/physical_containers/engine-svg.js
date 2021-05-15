var NPE_svg=`
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="7.625 9.625 1359.75 414.375">
  <style>
    #NPE-SVG {
      stroke-linecap: round;
      stroke-linejoin: round;
    }
    #NPE-SVG text {
      font-family: Helvetica;
      font-size: 12px;
      font-weight: 400;
      fill: #1f5766;
    }
    #NPE-SVG path.arrow, #NPE-SVG line.arrow {
      marker-end: url(#FilledArrow_Marker);
      stroke: black;
      stroke-width: .2376;
    }
    #NPE-SVG .textRect {
      fill: white;
      stroke: #4bacc6;
      stroke-width: .75;
    }
    #NPE-SVG #NPE_click_rects {
      fill: white;
      fill-opacity: 0;
      stroke: #4bacc6;
      stroke-width: 0;
    }
    #NPE-SVG .clickable:hover, #NPE-SVG .clickable:hover .textRect {
      stroke-width: 3;
    }
  </style>
  <defs>
    <marker orient="auto" overflow="visible" markerUnits="strokeWidth" id="FilledArrow_Marker" stroke-linejoin="miter" stroke-miterlimit="10" viewBox="-1 -10 26 20" markerWidth="26" markerHeight="20" color="black">
      <g>
        <path d="M 23.043772 0 L 0 -8.641414 L 0 8.641414 Z" fill="currentColor" stroke="currentColor" stroke-width="1"/>
      </g>
    </marker>
  </defs>
  <g id="NPE-SVG" fill-opacity="1" stroke-opacity="1" stroke="none" stroke-dasharray="none" fill="none">
    <g id="NPE_Background_layer">
      <g fill="#dbeef3" stroke="black" stroke-linecap="round" stroke-linejoin="round" stroke-dasharray="4.0,4.0" stroke-width="2">
        <path class="background-box" d="M 75.5 82 L 615.5 82 C 617.9853 82 620 84.01472 620 86.5 L 620 401.5 C 620 403.9853 617.9853 406 615.5 406 L 75.5 406 C 73.01472 406 71 403.9853 71 401.5 L 71 86.5 C 71 84.01472 73.01472 82 75.5 82 Z" />
        <path class="background-box" d="M 750.5 82 L 1272.5 82 C 1274.9853 82 1277 84.01472 1277 86.5 L 1277 401.5 C 1277 403.9853 1274.9853 406 1272.5 406 L 750.5 406 C 748.0147 406 746 403.9853 746 401.5 L 746 86.5 C 746 84.01472 748.0147 82 750.5 82 Z"/>
      </g>
    </g>
    <g id="NPE_Layer_1">
      <g>
        <line x1="62" y1="208" x2="154.69216" y2="208" class="arrow"/>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_1_Databus" data-pc-name="level 1 databus">
        <rect x="161" y="190" width="54" height="36" class="textRect"/>
        <text transform="translate(163 194)">
          <tspan x=".3203125" y="11">Data Bus </tspan>
          <tspan x="6.6484375" y="25">update</tspan>
        </text>
      </g>
      <g>
        <path d="M 143 262 L 147.5 262 C 149.98528 262 152 259.98528 152 257.5 L 152 221.5 C 152 219.6535 153.11213 218.06678 154.7031 217.37309" class="arrow"/>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_1_Tables" data-pc-name="level 1 tables">
        <rect x="89" y="244" width="54" height="36" class="textRect"/>
        <text transform="translate(91 255)">
          <tspan x="7.65625" y="11">Tables</tspan>
        </text>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_1_ALU" data-pc-name="level 1 ALUs">
        <rect x="89" y="280" width="54" height="36" class="textRect"/>
        <text transform="translate(91 291)">
          <tspan x="13.328125" y="11">ALU</tspan>
        </text>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_1_RegistersTCAM" data-pc-name="level 1 registers TCAMs">
        <rect x="89" y="316" width="54" height="36" class="textRect"/>
        <text transform="translate(91 328)">
          <tspan font-size="10" x=".2734375" y="10">Reg.TCAM</tspan>
        </text>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_1_TCAM" data-pc-name="level 1 TCAM">
        <rect x="89" y="352" width="54" height="36" class="textRect"/>
        <text transform="translate(91 363)">
          <tspan x="8.001953" y="11">TCAM</tspan>
        </text>
      </g>
      <g>
        <path d="M 62 208 L 75.16667 208 C 77.65195 208 79.66667 210.01472 79.66667 212.5 L 79.66667 257.5 C 79.66667 259.47075 80.93352 261.1456 82.69729 261.75464" class="arrow"/>
      </g>
      <g>
        <path d="M 80 262 L 80 293.5 C 80 295.3465 81.11213 296.93322 82.7031 297.6269" class="arrow"/>
      </g>
      <g>
        <path d="M 80 298 L 80 329.5 C 80 331.3465 81.11213 332.9332 82.7031 333.6269" class="arrow"/>
      </g>
      <g>
        <path d="M 143 298 L 147.5 298 C 149.98528 298 152 295.98528 152 293.5 L 152 268.30784" class="arrow"/>
      </g>
      <g>
        <path d="M 143 334 L 147.5 334 C 149.98528 334 152 331.98528 152 329.5 L 152 308.80784" class="arrow"/>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_3_Key_Selection" data-pc-name="lookup key selection">
        <rect x="377" y="100" width="54" height="36" class="textRect"/>
        <text transform="translate(379 104)">
          <tspan x="11.661133" y="11">Keys </tspan>
          <tspan x="1.319336" y="25">selection</tspan>
        </text>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_4_Key_Construction" data-pc-name="lookup key construction">
        <rect x="521" y="100" width="72" height="36" class="textRect"/>
        <text transform="translate(523 104)">
          <tspan x="23.661133" y="11">Key </tspan>
          <tspan x="1.6503906" y="25">construction</tspan>
        </text>
      </g>
      <g>
        <line x1="431" y1="118" x2="514.69216" y2="118" class="arrow"/>
      </g>
      <g>
        <line x1="503" y1="208" x2="539.21184" y2="208" class="arrow"/>
      </g>
      <g>
        <path d="M 656 15.4 L 656 58.6 L 656 58.6 C 656 61.582336 668.0883 64 683 64 C 697.9117 64 710 61.582336 710 58.6 L 710 15.4 L 710 15.4 C 710 12.417662 697.9117 10 683 10.000001 C 668.0883 10.000002 656 12.417663 656 15.4 Z" fill="white"/>
        <path d="M 656 15.4 L 656 58.6 L 656 58.6 C 656 61.582336 668.0883 64 683 64 C 697.9117 64 710 61.582336 710 58.6 L 710 15.4 L 710 15.4 C 710 12.417662 697.9117 10 683 10.000001 C 668.0883 10.000002 656 12.417663 656 15.4 Z M 656 15.4 L 656 15.4 C 656 18.382337 668.0883 20.8 683 20.8 C 697.9117 20.800002 710 18.38234 710 15.400003 C 710 15.400002 710 15.4 710 15.4 M 656 18.1 L 656 18.1 C 656 21.082337 668.0883 23.5 683 23.499998 C 697.9117 23.499997 710 21.082336 710 18.1 M 656 20.8 L 656 20.8 C 656 23.782337 668.0883 26.2 683 26.2 C 697.9117 26.199998 710 23.782336 710 20.8" stroke="black" stroke-linecap="round" stroke-linejoin="round" stroke-width=".75"/>
        <text transform="translate(658 38.1)" fill="black">
          <tspan fill="black" x="13.665039" y="11">DBs</tspan>
        </text>
      </g>
      <g>
        <path d="M 593 118 L 669.51146 118 C 671.9923 118 674.0051 115.99227 674.01144 113.51147 L 674.1001 78.75093 C 674.1001 78.74711 674.1001 78.74329 674.1001 78.73946 L 674.1001 70.0076" class="arrow"/>
      </g>
      <g>
        <path d="M 683.5 64 L 683.25 126.9972 C 683.25 126.99906 683.25 127.00093 683.25 127.0028 L 683.0001 174.94283 C 683 174.95065 683 174.95847 683 174.96629 L 683 183.69216" class="arrow"/>
      </g>
      <g>
        <g id="lookup-memory" fill="white" stroke="black" stroke-linecap="round" stroke-linejoin="round" stroke-width=".75">
          <rect x="638" y="190" width="18" height="36"/>
          <rect x="656" y="190" width="18" height="36"/>
          <rect x="674" y="190" width="18" height="36"/>
          <rect x="692" y="190" width="18" height="36"/>
          <rect x="710" y="190" width="18" height="36"/>
        </g>
        <g>
          <text transform="translate(634.4294 228)" fill="black">
            <tspan fill="black" x="5.5510826" y="11">Lookup memory</tspan>
          </text>
        </g>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_7_Traps" data-pc-name="traps">
        <rect x="908" y="100" width="54" height="36" class="textRect"/>
        <text transform="translate(910 111)">
          <tspan x="9.882812" y="11">Traps</tspan>
        </text>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_3_Databus" data-pc-name="level 3 databus">
        <rect x="449" y="190" width="54" height="36" class="textRect"/>
        <text transform="translate(451 194)">
          <tspan x=".3203125" y="11">Data Bus </tspan>
          <tspan x="6.6484375" y="25">update</tspan>
        </text>
      </g>
      <g>
        <path d="M 359 208 L 364.5 208 C 366.9853 208 369 205.98528 369 203.5 L 369 122.5 C 369 121.04572 369.68986 119.75257 370.76018 118.92993" class="arrow"/>
      </g>
      <g>
        <path d="M 503 208 L 507.5 208 C 509.9853 208 512 205.98528 512 203.5 L 512 131.5 C 512 129.65351 513.1121 128.06678 514.7031 127.37309" class="arrow"/>
      </g>
      <g>
        <path d="M 962 118 L 966.5 118 C 968.9853 118 971 120.01472 971 122.5 L 971 203.5 C 971 205.34648 972.1121 206.93322 973.7031 207.6269" class="arrow"/>
      </g>
      <g>
        <path d="M 890 208 L 894.5 208 C 896.9853 208 899 205.98528 899 203.5 L 899 122.5 C 899 120.65351 900.1121 119.06678 901.7031 118.37309" class="arrow"/>
      </g>
      <g>
        <path d="M 215 208 L 289.95456 208 L 298.69216 208" class="arrow"/>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_2_Databus" data-pc-name="level 2 databus">
        <rect x="305" y="190" width="54" height="36" class="textRect"/>
        <text transform="translate(307 194)">
          <tspan x=".3203125" y="11">Data Bus </tspan>
          <tspan x="6.6484375" y="25">update</tspan>
        </text>
      </g>
      <g>
        <path d="M 287 262 L 291.5 262 C 293.98528 262 296 259.98528 296 257.5 L 296 221.5 C 296 219.6535 297.11213 218.06678 298.7031 217.37309" class="arrow"/>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_2_Tables" data-pc-name="level 2 tables">
        <rect x="233" y="244" width="54" height="36" class="textRect"/>
        <text transform="translate(235 255)">
          <tspan x="7.65625" y="11">Tables</tspan>
        </text>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_2_ALU" data-pc-name="level 2 ALUs">
        <rect x="233" y="280" width="54" height="36" class="textRect"/>
        <text transform="translate(235 291)">
          <tspan x="13.328125" y="11">ALU</tspan>
        </text>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_2_RegistersTCAM" data-pc-name="level 2 registers TCAMs">
        <rect x="233" y="316" width="54" height="36" class="textRect"/>
        <text transform="translate(235 328)">
          <tspan font-size="10" x=".2734375" y="10">Reg.TCAM</tspan>
        </text>
      </g>
      <g>
        <path d="M 224.33333 208 L 224.33333 257.5 C 224.33333 259.22028 225.29863 260.7151 226.71712 261.47236" class="arrow"/>
      </g>
      <g>
        <path d="M 224 262 L 224 293.5 C 224 295.3465 225.11213 296.93322 226.7031 297.6269" class="arrow"/>
      </g>
      <g>
        <path d="M 224 298 L 224 329.5 C 224 331.3465 225.11213 332.9332 226.7031 333.6269" class="arrow"/>
      </g>
      <g>
        <path d="M 287 298 L 291.5 298 C 293.98528 298 296 295.98528 296 293.5 L 296 268.30784" class="arrow"/>
      </g>
      <g>
        <path d="M 287 334 L 291.5 334 C 293.98528 334 296 331.98528 296 329.5 L 296 308.80784" class="arrow"/>
      </g>
      <g>
        <path d="M 359 208 L 368.2376 208 L 442.69216 208" class="arrow"/>
      </g>
      <g>
        <line x1="359" y1="208" x2="442.69216" y2="208" class="arrow"/>
      </g>
      <g>
        <path d="M 737 208 L 820.9546 208 L 829.6922 208" class="arrow"/>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_6_Databus" data-pc-name="level 6 databus">
        <rect x="836" y="190" width="54" height="36" class="textRect"/>
        <text transform="translate(838 194)">
          <tspan x=".3203125" y="11">Data Bus </tspan>
          <tspan x="6.6484375" y="25">update</tspan>
        </text>
      </g>
      <g>
        <path d="M 818 262 L 822.5 262 C 824.9853 262 827 259.98528 827 257.5 L 827 221.5 C 827 219.6535 828.1121 218.06678 829.7031 217.37309" class="arrow"/>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_6_Tables" data-pc-name="level 6 tables">
        <rect x="764" y="244" width="54" height="36" class="textRect"/>
        <text transform="translate(766 255)">
          <tspan x="7.65625" y="11">Tables</tspan>
        </text>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_6_ALU" data-pc-name="level 6 ALUs">
        <rect x="764" y="280" width="54" height="36" class="textRect"/>
        <text transform="translate(766 291)">
          <tspan x="13.328125" y="11">ALU</tspan>
        </text>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_6_RegistersTCAM" data-pc-name="level 6 registers TCAMs">
        <rect x="764" y="316" width="54" height="36" class="textRect"/>
        <text transform="translate(766 328)">
          <tspan font-size="10" x=".2734375" y="10">Reg.TCAM</tspan>
        </text>
      </g>
      <g>
        <path d="M 728 208 L 737.1852 208 C 737.2201 208 737.2551 207.9996 737.29 207.99878 L 750.0618 207.70108 C 752.5464 207.64317 754.6075 209.6104 754.66545 212.095 C 754.6663 212.12995 754.6667 212.1649 754.6667 212.19986 L 754.6667 257.5 C 754.6667 259.47075 755.9335 261.1456 757.6973 261.75464" class="arrow"/>
      </g>
      <g>
        <path d="M 755 262 L 755 293.5 C 755 295.3465 756.1121 296.93322 757.7031 297.6269" class="arrow"/>
      </g>
      <g>
        <path d="M 755 298 L 755 329.5 C 755 331.3465 756.1121 332.9332 757.7031 333.6269" class="arrow"/>
      </g>
      <g>
        <path d="M 818 298 L 822.5 298 C 824.9853 298 827 295.98528 827 293.5 L 827 268.30784" class="arrow"/>
      </g>
      <g>
        <path d="M 818 334 L 822.5 334 C 824.9853 334 827 331.98528 827 329.5 L 827 308.80784" class="arrow"/>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_8_Key_Selection" data-pc-name="update key selection">
        <rect x="1052" y="100" width="54" height="36" class="textRect"/>
        <text transform="translate(1054 104)">
          <tspan x="11.661133" y="11">Keys </tspan>
          <tspan x="1.319336" y="25">selection</tspan>
        </text>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_9_Key_Construction" data-pc-name="update key construction">
        <rect x="1196" y="100" width="72" height="36" class="textRect"/>
        <text transform="translate(1198 104)">
          <tspan x="23.661133" y="11">Key </tspan>
          <tspan x="1.6503906" y="25">construction</tspan>
        </text>
      </g>
      <g>
        <line x1="1106" y1="118" x2="1189.6922" y2="118" class="arrow"/>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_8_Databus" data-pc-name="level 8 databus">
        <rect x="1124" y="190" width="54" height="36" class="textRect"/>
        <text transform="translate(1126 194)">
          <tspan x=".3203125" y="11">Data Bus </tspan>
          <tspan x="6.6484375" y="25">update</tspan>
        </text>
      </g>
      <g>
        <path d="M 1034 208 L 1039.5 208 C 1041.9853 208 1044 205.98528 1044 203.5 L 1044 122.5 C 1044 121.04572 1044.6899 119.75257 1045.7602 118.92993" class="arrow"/>
      </g>
      <g>
        <path d="M 1178 208 L 1182.5 208 C 1184.9853 208 1187 205.98528 1187 203.5 L 1187 131.5 C 1187 129.65351 1188.1121 128.06678 1189.7031 127.37309" class="arrow"/>
      </g>
      <g>
        <path d="M 890 208 L 964.9546 208 L 973.6922 208" class="arrow"/>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_7_Databus" data-pc-name="level 7 databus">
        <rect x="980" y="190" width="54" height="36" class="textRect"/>
        <text transform="translate(982 194)">
          <tspan x=".3203125" y="11">Data Bus </tspan>
          <tspan x="6.6484375" y="25">update</tspan>
        </text>
      </g>
      <g>
        <path d="M 962 262 L 966.5 262 C 968.9853 262 971 259.98528 971 257.5 L 971 221.5 C 971 219.6535 972.1121 218.06678 973.7031 217.37309" class="arrow"/>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_7_Tables" data-pc-name="level 7 tables">
        <rect x="908" y="244" width="54" height="36" class="textRect"/>
        <text transform="translate(910 255)">
          <tspan x="7.65625" y="11">Tables</tspan>
        </text>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_7_ALU" data-pc-name="level 7 ALUs">
        <rect x="908" y="280" width="54" height="36" class="textRect"/>
        <text transform="translate(910 291)">
          <tspan x="13.328125" y="11">ALU</tspan>
        </text>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_7_RegistersTCAM" data-pc-name="level 7 registers TCAMs">
        <rect x="908" y="316" width="54" height="36" class="textRect"/>
        <text transform="translate(910 328)">
          <tspan font-size="10" x=".2734375" y="10">Reg.TCAM</tspan>
        </text>
      </g>
      <g>
        <path d="M 890 208 L 894.5 208 C 896.9853 208 899 210.01472 899 212.5 L 899 257.5 C 899 259.3465 900.1121 260.93322 901.7031 261.6269" class="arrow"/>
      </g>
      <g>
        <path d="M 899 262 L 899 293.5 C 899 295.3465 900.1121 296.93322 901.7031 297.6269" class="arrow"/>
      </g>
      <g>
        <path d="M 899 298 L 899 329.5 C 899 331.3465 900.1121 332.9332 901.7031 333.6269" class="arrow"/>
      </g>
      <g>
        <path d="M 962 298 L 966.5 298 C 968.9853 298 971 295.98528 971 293.5 L 971 268.30784" class="arrow"/>
      </g>
      <g>
        <path d="M 962 334 L 966.5 334 C 968.9853 334 971 331.98528 971 329.5 L 971 308.80784" class="arrow"/>
      </g>
      <g>
        <path d="M 1034 208 L 1043.2376 208 L 1117.6922 208" class="arrow"/>
      </g>
      <g>
        <path d="M 1106 262 L 1110.5 262 C 1112.9853 262 1115 259.98528 1115 257.5 L 1115 221.5 C 1115 219.6535 1116.1121 218.06678 1117.7031 217.37309" class="arrow"/>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_8_ALU" data-pc-name="level 8 ALUs">
        <rect x="1052" y="244" width="54" height="36" class="textRect"/>
        <text transform="translate(1054 255)">
          <tspan x="13.328125" y="11">ALU</tspan>
        </text>
      </g>
      <g>
        <path d="M 1034 208 L 1038.1667 208 C 1040.652 208 1042.6667 210.01472 1042.6667 212.5 L 1042.6667 257.5 C 1042.6667 259.47075 1043.9335 261.1456 1045.6973 261.75464" class="arrow"/>
      </g>
      <g>
        <line x1="1268" y1="118" x2="1306.6922" y2="118" class="arrow"/>
      </g>
      <g>
        <text transform="translate(73 408)" fill="black">
          <tspan fill="black" x="23.652344" y="11">Level 1</tspan>
        </text>
      </g>
      <g>
        <text transform="translate(217 408)" fill="black">
          <tspan fill="black" x="23.652344" y="11">Level 2</tspan>
        </text>
      </g>
      <g>
        <text transform="translate(361 408)" fill="black">
          <tspan fill="black" x="23.652344" y="11">Level 3</tspan>
        </text>
      </g>
      <g>
        <text transform="translate(523 408)" fill="black">
          <tspan fill="black" x="23.652344" y="11">Level 4</tspan>
        </text>
      </g>
      <g>
        <text transform="translate(649 408)" fill="black">
          <tspan fill="black" x="23.652344" y="11">Level 5</tspan>
        </text>
      </g>
      <g>
        <text transform="translate(748 408)" fill="black">
          <tspan fill="black" x="23.652344" y="11">Level 6</tspan>
        </text>
      </g>
      <g>
        <text transform="translate(892 408)" fill="black">
          <tspan fill="black" x="23.652344" y="11">Level 7</tspan>
        </text>
      </g>
      <g>
        <text transform="translate(1036 408)" fill="black">
          <tspan fill="black" x="23.652344" y="11">Level 8</tspan>
        </text>
      </g>
      <g>
        <text transform="translate(1189 408)" fill="black">
          <tspan fill="black" x="23.652344" y="11">Level 9</tspan>
        </text>
      </g>
      <g>
        <path d="M 143 370 L 147.5 370 C 149.98528 370 152 367.9853 152 365.5 L 152 344.80784" class="arrow"/>
      </g>
      <g>
        <path d="M 80 334 L 80 365.5 C 80 367.3465 81.11213 368.9332 82.7031 369.6269" class="arrow"/>
      </g>
      <g>
        <path d="M 431 118 L 435.5 118 C 437.9853 118 440 120.01472 440 122.5 L 440 194.5 C 440 196.34648 441.11213 197.93322 442.7031 198.62691" class="arrow"/>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_4_Databus" data-pc-name="mini-scoper">
        <rect x="545.5197" y="190" width="54" height="36" class="textRect"/>
        <text transform="translate(547.5197 194)">
          <tspan x="13.999023" y="11">Mini </tspan>
          <tspan x="5.989258" y="25">Scoper</tspan>
        </text>
      </g>
      <g>
        <line x1="599.5197" y1="208" x2="631.69216" y2="208" class="arrow"/>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_0_Databus" data-pc-name="scoper">
        <rect x="8" y="190" width="54" height="36" class="textRect"/>
        <text transform="translate(10 201)">
          <tspan x="5.989258" y="11">Scoper</tspan>
        </text>
      </g>
      <g>
        <path d="M 62 208 C 67.85292 208 73.70585 208 79.55877 208 C 79.55877 189.27693 79.55877 170.55385 79.55877 151.83078 C 175.03918 151.83078 270.5196 151.83078 366 151.83078 C 367 150.83078 368 149.83078 369 148.83078 C 370 149.83078 371 150.83078 372 151.83078 C 392.7196 151.83078 413.4392 151.83078 434.15877 151.83078 C 434.15877 170.55385 434.15877 189.27693 434.15877 208 C 437.00334 208 439.8479 208 442.6925 208" class="arrow"/>
      </g>
      <g>
        <rect x="225.92492" y="140.62892" width="60" height="22.40371" fill="white"/>
        <text transform="translate(229.92492 144.83078)" fill="black">
          <tspan fill="black" x="6.324219" y="11">Bypass</tspan>
        </text>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="unified_buckets" data-pc-name="unified buckets">
        <rect x="1313" y="100" width="54" height="36" class="textRect"/>
        <text transform="translate(1315 104)">
          <tspan x="6.323242" y="11">Unified </tspan>
          <tspan x="3.6572266" y="25">Buckets</tspan>
        </text>
      </g>
    </g>
    <g id="NPE_click_rects">
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_1_0_LVR_Entrance" data-pc-name="entrance to level 1 containers">
        <rect x="76.16667" y="217.4" width="9" height="163.6"/>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Bypass" data-pc-name="bypass">
        <rect x="94.4" y="140.62892" width="258.5" height="22.40371"/>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_2_0_LVR_Entrance" data-pc-name="entrance to level 2 containers">
        <rect x="219" y="217.4" width="9" height="128.1"/>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_3_1_LVR_Entrance" data-pc-name="entrance to lookup key selection">
        <rect x="363" y="108.5" width="9" height="90.5"/>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_4_1_LVR_Entrance" data-pc-name="entrance to lookup key construction">
        <rect x="507.5" y="125.4" width="9" height="73.6"/>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Lookup" data-pc-name="lookups">
        <rect x="448" y="114.8" width="60" height="7"/>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_5_Databus" data-pc-name="level 5 databus">
        <rect x="728.5" y="201.85" width="23.90001" height="12.300003"/>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_6_0_LVR_Entrance" data-pc-name="entrance to level 6 containers">
        <rect x="751.2" y="220.5" width="9" height="122.9"/>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_7_0_LVR_Entrance" data-pc-name="entrance to level 7 containers">
        <rect x="894.5" y="214.5" width="9" height="122.9"/>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Update" data-pc-name="updates">
        <rect x="1118" y="114.8" width="60" height="7"/>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_9_1_LVR_Entrance" data-pc-name="entrance to update key construction">
        <rect x="1182.5" y="125.4" width="9" height="73.6"/>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_8_1_LVR_Entrance" data-pc-name="entrance to update key selection">
        <rect x="1039" y="108.5" width="9" height="90.5"/>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_7_1_LVR_Entrance" data-pc-name="entrance to traps">
        <rect x="894.5" y="108.5" width="9" height="90.5"/>
      </g>
      <g class="clickable" onclick="svg_click(this)" data-pc-id="Level_8_0_LVR_Entrance" data-pc-name="entrance to level 8 containers">
        <rect x="1039" y="212.5" width="9" height="59.16922"/>
      </g>
    </g>
  </g>
</svg>
`
