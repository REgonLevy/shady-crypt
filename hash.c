void hash(char *pw) {

    // The "pw" function argument passes in the work factor (0:2), salt (3:15), and 504 bit (72 ASCII characters) password text to be hashed (16:87) and also is output back with the same work factor and salt (0:15) as well as the 504 bit hash digest (84 characters in standard radix 64 notation, 16:99).

    // Used to temporarily store and manipulate password:

    unsigned int password[100];

    // Used for Toom 3 and Karatsuba multiplication (see Brent and Zimmerman, Modern Computer Arithmetic, pp. 5-8 in the pdf available here: https://arxiv.org/abs/1004.4710):
    
    long long t0[39], t1[39], t2[39];
    long long s0[28], s1[28], s2[28];
    unsigned long long c0[78], c1[78], c2[78];
    long long cc0[56], cc1[56], cc2[56];
    long long w0[156], w1[156], w2[156], w3[156], w4[156];
    long long r[468];
    
    //Used in combination with the above for both upper and lower short products for Barrett reduction in Blum Blum Shub (see Zimmerman and Brent pp. 63-65 for Barrett reduction, pp. 103-107 for short products, and Andreas Klein, Stream Ciphers, Springer (2013) pp. 250-66 for material on BBS):

    long long q[280];

    // For basic arithmetic, carries, and modulus operations in base 2**29:

    long long base = 1 << 29;
    long long mask = base - 1;
    long long c;

    // State array, carry, and temporary variables for large-state Complimentary Multiply With Carry generator (see https://en.wikipedia.org/wiki/Multiply-with-carry_pseudorandom_number_generator):

    unsigned int state[4827], carry, tt, xx;

    // Multiply With Carry index:

    int jj = 4827;

    // Linear congruential generator (see https://en.wikipedia.org/wiki/Linear_congruential_generator):

    unsigned int cng;

    // Xorshift generator (see https://en.wikipedia.org/wiki/Xorshift):

    unsigned int xs;

    // Symbol spread and encoding table for 128-symbol alphabet tANS (see Duda and Niemiec, "Lightweight compression with encryption based on Asymmetric Numeral Systems," https://arxiv.org/pdf/1612.04662.pdf):

    int spread[16384], table[16384];

    // Index and temporary variables for tANS:
    int kk = 16384;
    unsigned int vv, ww, gg;

    // tANS state:

    unsigned int ast = 0;

    // tANS streamed output:

    unsigned int strr = 0;

    // temporary variables for new tANS symbols:

    unsigned int ss1, ss2;

    // Seed/state for BBS stored with 29 bit words.

    int x[234]; 

    // 6760 bit modulus for BBS stored with 29 bit words. M = p * q, where p and q are both randomly generated 3380 bit "safe" primes, with gcd ((p-3)/2, (q-3)/2) = 2. (see Klein, Stream Ciphers, Springer (2013) pp. 250-66). Mp and mpp are subsets of m, multiplied by 2 and 4, respectively, to be used in short products. Hardcoded for efficiency in wasm.

    int m[234] = {406051265,451612,85162260,97415488,320390857,387395898,332196713,470809594,479183839,242971814,200945655,507096842,55019539,368108361,172848110,382679144,123424659,295898576,395881883,413529634,150423281,420949805,188144116,289846250,409401003,498611476,88850530,33206084,524860955,200925878,294805977,189169909,430020447,402324272,484172197,512603989,368313648,205321245,283075656,290500828,378010016,508283750,326491639,475203424,405818247,499142129,26305025,527062886,436991731,490939572,179119634,150374864,358504788,250971028,437178205,256644499,362879866,29916982,144700303,284200955,275809703,426218523,56622790,263203892,309433989,510837654,471780047,227627277,177539454,125118213,251666903,128371161,531968599,27813204,59579062,66295361,31822404,150238127,83120958,135841553,242806763,444424540,441301652,411924427,86303929,486251364,495337750,516990947,484417045,427033386,298938557,338638002,16605475,129716383,95625035,285985771,299056987,477428407,69482064,412973698,96376454,210968763,293457211,484935488,393972271,251746468,150154873,3015240,521854873,444712752,72500457,529039183,303327416,507521043,65440341,453744566,195712356,81563204,117774597,367941764,363659574,438164407,262034656,414781114,312989959,133685198,275669071,462653032,264874486,399565408,157412278,158001737,422076038,156481698,464016451,445835146,71943461,215326182,266495789,317513335,461638422,389998460,137539147,142300280,268931655,80837320,103436729,42666614,334834572,501888502,302997111,38647455,329987690,372972380,205318106,153875221,213615184,212824210,359789544,78155676,366419072,15351075,373520300,155401495,345186271,348649055,336990481,391318028,106025122,216583117,369227320,212274464,499559382,451576115,529264955,72872498,395621361,293139888,253105475,427663968,178310910,507570538,107595020,183036213,323226060,74574662,81735323,186452677,65572204,408515776,242609584,305955688,366400454,210297760,108993991,115645535,157714563,515577342,145761154,449115688,414692642,200635188,419270951,252890623,201521583,319255339,470171477,316995349,483485285,232001414,476370881,74649562,31023521,503825210,484359473,51652850,534198439,241090173,100384429,190965262,442110637,369015117,428649334,531092210,118424844,238275303,52709111,373646410,104597538,202159973,165359561,458516525,71642743,7};

    int mp[56] = {725759732,59833964,289400606,568401910,551619406,852437046,113245580,526407784,618867978,1021675308,943560094,455254554,355078908,250236426,503333806,256742322,1063937198,55626408,119158124,132590722,63644808,300476254,166241916,271683106,485613526,888849080,882603304,823848854,172607858,972502728,990675500,1033981894,968834090,854066772,597877114,677276004,33210950,259432766,191250070,571971542,598113974,954856814,138964128,825947396,192752908,421937526,586914422,969870976,787944542,503492936,300309746,6030480,1043709746,889425504,145000914,1058078366};

    int mpp[56] = {1213309664,2030084172,261761364,1814978264,782849424,326252816,471098388,1471767056,1454638296,1752657628,1048138624,1659124456,1251959836,534740792,1102676284,1850612128,1059497944,1598261632,629649112,632006948,1688304152,625926792,1856065804,1783340584,287773844,861304728,1065983156,1270053340,1846553688,1559993840,550156588,569201120,1075726620,323349280,413746916,170666456,1339338288,2007554008,1211988444,154589820,1319950760,1491889520,821272424,615500884,854460736,851296840,1439158176,312622704,1465676288,61404300,1494081200,621605980,1380745084,1394596220,1347961924,1565272112};

    // Inverse of M. inv = B**2 / M, with B = 2**6760, for use in Barrett reduction. invp and invpp are subsets of inv, multiplied by 2 and 4, respectively, to be used in short products. Hardcoded for efficiency in wasm.

    int inv[234] = {346812487,160620432,54130479,386762231,449409721,161663930,503624968,197045228,527674854,47027697,451217336,494653533,181429756,316520529,306789053,238454739,365695194,258778191,383734765,337395587,74964909,328683437,396923598,224401354,414821064,313777893,91568348,597956,489540157,345318503,38733680,426151614,151413502,312143239,371666681,181267310,104834694,500859266,165575445,185208976,301512072,71402040,176508878,455188364,404373340,60922791,386858204,471290019,295094892,319256599,79038661,264063122,262691852,235537874,140436385,179344887,62505460,355338512,516134581,322637416,300093274,498229092,138543706,281707924,226415103,211468076,129140115,435962479,10674318,89737235,247110586,230029009,225628357,124842247,434280615,218013883,223042583,103643667,199701464,452929949,63527925,113947338,433099451,17383355,166475723,340190007,502300561,125065110,253198959,157705085,525761310,45277768,283100980,22180238,182267851,319169773,220951186,1811179,481035991,269028478,375729000,415013840,407831196,272191315,478084487,498742963,129001812,138766554,240767489,362056994,45075317,345813493,203586951,106628535,279238977,298383528,375106837,31528505,55286398,68150762,350975384,490472683,440448382,217699447,1705466,224942392,168189695,503400218,121253985,295646119,53459707,298324796,373615374,408934240,480563386,253051341,70495330,189278694,88003831,484167351,259106228,384741129,410631455,8520722,211540844,67486686,295226355,19135392,464381589,58105742,273776844,436368425,39019393,91016147,212990117,104122943,272978662,71782556,382471903,185810271,468572129,275710714,401728314,245747938,262072313,116699273,151112384,142026516,266934472,417497070,427538497,386976980,524684109,235922268,441070584,522083298,369678342,317592399,129792734,103019723,126684149,121063280,406884315,45927571,31831291,366124574,118224794,24526730,325830909,194208952,270588633,203754012,415171893,447005774,461726677,222097203,89383770,473741704,229257331,303528260,1045853,47766614,282826610,295908918,169163348,16928239,172850010,410244832,166885632,393097146,518175092,9038141,355744159,74134981,93824711,435410554,223925768,136023682,321067497,78255674,334840327,210552950,259127008,61388976,262074851,327643149,452482582,402749555,327549733,220654564,468317018,245798937,521743048,8};

    int invp[56] = {880896764,435398894,3410932,449884784,336379390,1006800436,242507970,591292238,106919414,596649592,747230748,817868480,961126772,506102682,140990660,378557388,176007662,968334702,518212456,769482258,821262910,17041444,423081688,134973372,590452710,38270784,928763178,116211484,547553688,872736850,78038786,182032294,425980234,208245886,545957324,143565112,764943806,371620542,937144258,551421428,803456628,491495876,524144626,233398546,302224768,284053032,533868944,834994140,855076994,773953960,1049368218,471844536,882141168,1044166596,739356684,635184798};

    int invpp[56] = {519170936,412078892,506736596,484253120,1627537260,183710284,127325164,1464498296,472899176,98106920,1303323636,776835808,1082354532,815016048,1660687572,1788023096,1846906708,888388812,357535080,1894966816,917029324,1214113040,4183412,191066456,1131306440,1183635672,676653392,67712956,691400040,1640979328,667542528,1572388584,2072700368,36152564,1422976636,296539924,375298844,1741642216,895703072,544094728,1284269988,313022696,1339361308,842211800,1036508032,245555904,1048299404,1310572596,1809930328,1610998220,1310198932,882618256,1873268072,983195748,2086972192,32};

    // Work factor (minimum of 1, maximum of 262143):

    int work = password[0] + 64 * password[1] + 4096 * password[2];

    // Symbol stream for 64-symbol alphabet rANS (see Mart Simsker, "A review of 'Asymmetric Numeral Systems'", https://pdfs.semanticscholar.org/7ed6/509ed03f7df6feb2c26d4653669662274834.pdf):

    unsigned int stream[1120];

    // Stretched/enhanced key:

    unsigned int xtt[233];

    // Symbol frequency and cumulative frequency distributions for 64-symbol rANS

    int f[64], cum[64];

    // Modulus for rANS

    int mb;

    // State for rANS in base 2**29:

    long long xcat[300];

    for(int i = 0; i < 100; i ++){
        password[i] = pw[i];
    }

    xs = password[3] + (password[4] << 6) + (password[5] << 12) + (password[6] << 18) + (password[7] << 24) + (password[13] << 30);
    cng = password[8] + (password[9] << 6) + (password[10] << 12) + (password[11] << 18) + (password[12] << 24) + ((password[13] & 12) << 28);
    carry = password[14] + (password[15] << 6);

    for(int i = 0; i < 4827; i++){
        cng = 69069 * cng + 13579;
        xs ^= xs << 13; 
        xs ^= xs >> 17;
        xs ^= xs << 5;
        state[i] = cng + xs;
    }

    state[3003] ^= (password[13] & 48);

    for(int i = 0; i < 128; i++){
        for(int l = 0; l < 128; l++){
            spread[128 * l + i] = 128 * i + l;
            table[128 * i + l] = 128 * l + i;
        }
    }

    for(int i = 0; i < 510510; i++){
        jj = (jj < 4826) ? jj + 1 : 0;
        kk = (kk < 16383) ? kk + 1 : 0;
        xx = state[jj];
        tt = (xx << 12) + carry;
        carry = (xx >> 20) - (tt < xx);
        state[jj] = ~(tt - xx);
        cng = 69069 * cng + 13579;
        xs ^= xs << 13; 
        xs ^= xs >> 17;
        xs ^= xs << 5;
        xx = state[jj] + xs + cng;
        ss1 = xx & 127;
        ss2 = xx >> 25;
        strr <<= 7;
        strr += ast & 127;
        ast = table[(ss2 << 7) + (ast >> 7)];
        if((ww = spread[kk]) >> 7 != ss1){
            vv = (state[jj] & 127) + (ss1 << 7);
            gg = table[vv];

            table[ww] = gg;
            table[vv] = kk;
            spread[kk] = vv;
            spread[gg] = ww;
        }
    }
    
for(int cyc = 0; cyc < work; cyc++){

    for(int i = 0; i < 7; i ++){
        for(int l = 16; l < 88; l++){
            jj = (jj < 4826) ? jj + 1 : 0;
            kk = (kk < 16383) ? kk + 1 : 0;
            xx = state[jj];
            tt = (xx << 12) + carry;
            carry = (xx >> 20) - (tt < xx);
            state[jj] = ~(tt - xx);
            cng = 69069 * cng + 13579;
            xs ^= xs << 13; 
            xs ^= xs >> 17;
            xs ^= xs << 5;
            xx = state[jj] + xs + cng;
            ss1 = xx & 127;
            ss2 = xx >> 25;
            strr <<= 7;
            strr += ast & 127;
            ast = table[(ss2 << 7) + (ast >> 7)];
            if((ww = spread[kk]) >> 7 != ss1){
                vv = (state[jj] & 127) + (ss1 << 7);
                gg = table[vv];

                table[ww] = gg;
                table[vv] = kk;
                spread[kk] = vv;
                spread[gg] = ww;
            }
            xx ^= strr;
            password[l] ^= (xx & 8192) >> (13 - i);
        }
    }

    for(int i = 0; i < 1120; i++) stream[i] = 0;
    for(int i = 0; i < 233; i++) xtt[i] = 0;

    for(int i = 0; i < 8; i++){

        xs ^= password[16 + 9 * i];
        xs ^= password[17 + 9 * i] << 7;
        xs ^= password[18 + 9 * i] << 14;
        xs ^= password[19 + 9 * i] << 21;
        xs ^= password[24 + 9 * i] << 28;
        cng ^= password[20 + 9 * i];
        cng ^= password[21 + 9 * i] << 7;
        cng ^= password[22 + 9 * i] << 14;
        cng ^= password[23 + 9 * i] << 21;
        cng ^= (password[24 + 9 * i] & 112) << 25;

        for(int l = 0; l < 30030; l++) {
            jj = (jj < 4826) ? jj + 1 : 0;
            kk = (kk < 16383) ? kk + 1 : 0;
            xx = state[jj];
            tt = (xx << 12) + carry;
            carry = (xx >> 20) - (tt < xx);
            state[jj] = ~(tt - xx);
            cng = 69069 * cng + 13579;
            xs ^= xs << 13; 
            xs ^= xs >> 17;
            xs ^= xs << 5;
            xx = state[jj] + xs + cng;
            ss1 = xx & 127;
            ss2 = xx >> 25;
            strr <<= 7;
            strr += ast & 127;
            ast = table[(ss2 << 7) + (ast >> 7)];
            if((ww = spread[kk]) >> 7 != ss1){
                vv = (state[jj] & 127) + (ss1 << 7);
                gg = table[vv];

                table[ww] = gg;
                table[vv] = kk;
                spread[kk] = vv;
                spread[gg] = ww;
            }
        }

        for(int l = 0; l < 140; l++){
            for(int ll = 0; ll < 6; ll++){
                jj = (jj < 4826) ? jj + 1 : 0;
                kk = (kk < 16383) ? kk + 1 : 0;
                xx = state[jj];
                tt = (xx << 12) + carry;
                carry = (xx >> 20) - (tt < xx);
                state[jj] = ~(tt - xx);
                cng = 69069 * cng + 13579;
                xs ^= xs << 13; 
                xs ^= xs >> 17;
                xs ^= xs << 5;
                xx = state[jj] + xs + cng;
                ss1 = xx & 127;
                ss2 = xx >> 25;
                strr <<= 7;
                strr += ast & 127;
                ast = table[(ss2 << 7) + (ast >> 7)];
                if((ww = spread[kk]) >> 7 != ss1){
                    vv = (state[jj] & 127) + (ss1 << 7);
                    gg = table[vv];

                    table[ww] = gg;
                    table[vv] = kk;
                    spread[kk] = vv;
                    spread[gg] = ww;
                }
                xx ^= strr;
                stream[l + i * 140] ^= (xx & 8192) >> (13 - ll);
            }
        }

        for(int l= 0; l < 233; l++){
            jj = (jj < 4826) ? jj + 1 : 0;
            kk = (kk < 16383) ? kk + 1 : 0;
            xx = state[jj];
            tt = (xx << 12) + carry;
            carry = (xx >> 20) - (tt < xx);
            state[jj] = ~(tt - xx);
            cng = 69069 * cng + 13579;
            xs ^= xs << 13; 
            xs ^= xs >> 17;
            xs ^= xs << 5;
            xx = state[jj] + xs + cng;
            ss1 = xx & 127;
            ss2 = xx >> 25;
            strr <<= 7;
            strr += ast & 127;
            ast = table[(ss2 << 7) + (ast >> 7)];
            if((ww = spread[kk]) >> 7 != ss1){
                vv = (state[jj] & 127) + (ss1 << 7);
                gg = table[vv];

                table[ww] = gg;
                table[vv] = kk;
                spread[kk] = vv;
                spread[gg] = ww;
            }
            xx ^= strr;
            xtt[l] ^= ((xx >> 13) & 15) << (i << 2);
        }
    }

    for(int i = 0; i < 64; i++) f[i] = 0;

    mb = 0;

    for(int i = 0; i < 1120; i++){
        f[stream[i]]++;
    }

    cum[0] = 0;

    for(int i = 0; i < 63; i++){
        if(f[i]){
            if(f[i] < 14){
                f[i] = 0;
                mb++;
                cum[i + 1] = cum[i] + 1;
            } else if(f[i] < 18){
                f[i] = 1;
                mb += 2;
                cum[i + 1] = cum[i] + 2;
            } else if(f[i] < 22){
                f[i] = 2;
                mb += 4;
                cum[i + 1] = cum[i] + 4;
            } else {
                f[i] = 3;
                mb += 8;
                cum[i + 1] = cum[i] + 8;
            } 
        } else {
            cum[i + 1] = cum[i];
        }
    }

    if(f[63]){
        if(f[63] < 14){
            f[63] = 0;
            mb++;
        } else if(f[63] < 18){
            f[63] = 1;
            mb += 2;
        } else if(f[63] < 22){
            f[63] = 2;
            mb += 4;
        } else {
            f[63] = 3;
            mb += 8;
        } 
    }

    for(int i = 0; i < 300; i++) xcat[i] = 0;

    int cur = 1;
    int mod;
    int ft;

    for(int i = 0; i < 1120; i++){
        ft = f[stream[i]];
        mod = xcat[0] & ((1 << ft) - 1);
        mod += cum[stream[i]];
        for(int l = 0; l < cur; l++){
            xcat[l] >>= ft;
            xcat[l] += (xcat[l + 1] & ((1 << ft) - 1)) << (29 - ft);
        }
        for(int l = cur - 1; l >= 0; l--){
            xcat[l] *= mb;
            xcat[l + 1] += xcat[l] >> 29;
            xcat[l] &= mask;
        }
        xcat[0] += mod;
        if(xcat[cur]) cur++;
    } 

    for(int i = 233; i < cur; i++){
        xcat[i - 233] ^= xcat[i];
    }
    
    for(int i = 0; i < 233; i++){
        x[i] = (int) ((xtt[i] ^ xcat[i]) & mask);
    }
   
    x[233] = 0;
    
    int count = 15;
    for(int i = 16; i < 100; i++) password[i] = 0;

for(int k = 16; k < 88; k++){    

count = (count < 15) ? count + 1 : 3; 

for(int l = 0; l < 7; l++){  

    for(int i = 0; i < 39; i++){
        t0[i] = x[i];
        t1[i] = x[i + 39];
        t2[i] = t0[i] - t1[i];
    }

    for(int i = 0; i < 38; i++){
        if(t2[i] < 0) {
            t2[i] += base;
            t2[i + 1]--;
        }
    }

        c0[0] = t0[0] * t0[0];
        c0[38] = t0[38] * t0[0];
        c0[76] = t0[38] * t0[38];
        c0[77] = 0;
        c1[0] = t1[0] * t1[0];
        c1[38] = t1[38] * t1[0];
        c1[76] = t1[38] * t1[38];
        c1[77] = 0;
        c2[0] = t2[0] * t2[0];
        c2[38] = t2[38] * t2[0];
        c2[76] = t2[38] * t2[38];
        c2[77] = 0;

    for(int i = 1; i < 38; i++){
        c0[i] = t0[i] * t0[0];
        c0[i + 38] = t0[i] * t0[38];
        c1[i] = t1[i] * t1[0];
        c1[i + 38] = t1[i] * t1[38];
        c2[i] = t2[i] * t2[0];
        c2[i + 38] = t2[i] * t2[38];
    }

    for(int i = 1; i < 37; i++){
        for(int j = i + 1; j < 38; j++){
            c0[i + j] += t0[i] * t0[j];
            c1[i + j] += t1[i] * t1[j];
            c2[i + j] += t2[i] * t2[j];
            carry ^= c0[i + j];
            carry ^= c1[i + j];
            carry ^= c2[i + j];
        }
    }

    for(int i = 1; i < 76; i++){
        c0[i] <<= 1;
        c1[i] <<= 1;
        c2[i] <<= 1;
    }

    for(int i = 1; i < 38; i++){
        c0[i + i] += t0[i] * t0[i];
        c1[i + i] += t1[i] * t1[i];
        c2[i + i] += t2[i] * t2[i];
    }

    for(int i = 0; i < 50; i++){
        c0[i + 1] += c0[i] >> 29;
        c0[i] &= mask;
        w0[i] = c0[i];
        c1[i + 1] += c1[i] >> 29;
        c1[i] &= mask;
        w0[i + 78] = c1[i];
        c2[i + 1] += c2[i] >> 29;
        c2[i] &= mask;
    }
    for(int i = 50; i < 77; i++){
        c0[i + 1] += c0[i] >> 29;
        c0[i] &= mask;
        w0[i] = c0[i];
        c1[i + 1] += c1[i] >> 29;
        c1[i] &= mask;
        w0[i + 78] = c1[i];
        c2[i + 1] += (long long) c2[i] >> 29;
        c2[i] &= mask;
    }

    w0[77] = c0[77];
    w0[155] = c1[77];
    w0[116] += c0[77] + c1[77] - c2[77];

    for(int i = 0; i < 77; i++){
        w0[i + 39] += c0[i] + c1[i] - c2[i];
    }

    for(int i = 0; i < 38; i++){
        t0[i] += x[i + 78] + x[i + 156];
        t0[i + 1] += t0[i] >> 29;
        t0[i] &= mask;
        t1[i] += x[i + 117] + x[i + 195];
        t1[i + 1] += t1[i] >> 29;
        t1[i] &= mask;
        t2[i] = t0[i] - t1[i];
    }

    t0[38] += x[116] + x[194];
    t1[38] += x[155] + x[233];
    t2[38] = t0[38] - t1[38];

    for(int i = 0; i < 38; i++){
        if(t2[i] < 0) {
            t2[i] += base;
            t2[i + 1]--;
        }
    }

        c0[0] = t0[0] * t0[0];
        c0[38] = t0[38] * t0[0];
        c0[76] = t0[38] * t0[38];
        c0[77] = 0;
        c1[0] = t1[0] * t1[0];
        c1[38] = t1[38] * t1[0];
        c1[76] = t1[38] * t1[38];
        c1[77] = 0;
        c2[0] = t2[0] * t2[0];
        c2[38] = t2[38] * t2[0];
        c2[76] = t2[38] * t2[38];
        c2[77] = 0;

    for(int i = 1; i < 38; i++){
        c0[i] = t0[i] * t0[0];
        c0[i + 38] = t0[i] * t0[38];
        c1[i] = t1[i] * t1[0];
        c1[i + 38] = t1[i] * t1[38];
        c2[i] = t2[i] * t2[0];
        c2[i + 38] = t2[i] * t2[38];
    }

    for(int i = 1; i < 37; i++){
        for(int j = i + 1; j < 38; j++){
            c0[i + j] += t0[i] * t0[j];
            c1[i + j] += t1[i] * t1[j];
            c2[i + j] += t2[i] * t2[j];
            carry ^= c0[i + j];
            carry ^= c1[i + j];
            carry ^= c2[i + j];
        }
    }

    for(int i = 1; i < 76; i++){
        c0[i] <<= 1;
        c1[i] <<= 1;
        c2[i] <<= 1;
    }

    for(int i = 1; i < 38; i++){
        c0[i + i] += t0[i] * t0[i];
        c1[i + i] += t1[i] * t1[i];
        c2[i + i] += t2[i] * t2[i];
    }

    for(int i = 0; i < 50; i++){
        c0[i + 1] += c0[i] >> 29;
        c0[i] &= mask;
        w1[i] = c0[i];
        c1[i + 1] += c1[i] >> 29;
        c1[i] &= mask;
        w1[i + 78] = c1[i];
        c2[i + 1] += c2[i] >> 29;
        c2[i] &= mask;
    }

    for(int i = 50; i < 77; i++){
        c0[i + 1] += c0[i] >> 29;
        c0[i] &= mask;
        w1[i] = c0[i];
        c1[i + 1] += c1[i] >> 29;
        c1[i] &= mask;
        w1[i + 78] = c1[i];
        c2[i + 1] += (long long) c2[i] >> 29;
        c2[i] &= mask;
    }

    w1[77] = c0[77];
    w1[155] = c1[77];
    w1[116] += c0[77] + c1[77] - c2[77];

    for(int i = 0; i < 77; i++){
        w1[i + 39] += c0[i] + c1[i] - c2[i];
    }

    for(int i = 78; i < 156; i++){
        x[i] <<= 1;
    }

    for(int i = 0; i < 38; i++){
        t0[i] -= x[i + 78];
        t1[i] -= x[i + 117];
        t0[i + 1] += t0[i] >> 29;
        t0[i] &= mask;
        t1[i + 1] += t1[i] >> 29;
        t1[i] &= mask;
        t2[i] = t0[i] - t1[i];
    }

    t0[38] -= x[116];
    t1[38] -= x[155];
    t2[38] = t0[38] - t1[38];

    for(int i = 0; i < 38; i++){
        if(t2[i] < 0){
            t2[i] += base;
            t2[i + 1]--;
        }
    }

        c0[0] = t0[0] * t0[0];
        c0[38] = t0[38] * t0[0];
        c0[76] = t0[38] * t0[38];
        c0[77] = 0;
        c1[0] = t1[0] * t1[0];
        c1[38] = t1[38] * t1[0];
        c1[76] = t1[38] * t1[38];
        c1[77] = 0;
        c2[0] = t2[0] * t2[0];
        c2[38] = t2[38] * t2[0];
        c2[76] = t2[38] * t2[38];
        c2[77] = 0;

    for(int i = 1; i < 38; i++){
        c0[i] = t0[i] * t0[0];
        c0[i + 38] = t0[i] * t0[38];
        c1[i] = t1[i] * t1[0];
        c1[i + 38] = t1[i] * t1[38];
        c2[i] = t2[i] * t2[0];
        c2[i + 38] = t2[i] * t2[38];
    }

    for(int i = 1; i < 37; i++){
        for(int j = i + 1; j < 38; j++){
            c0[i + j] += t0[i] * t0[j];
            c1[i + j] += t1[i] * t1[j];
            c2[i + j] += t2[i] * t2[j];
            carry ^= c0[i + j];
            carry ^= c1[i + j];
            carry ^= c2[i + j];
        }
    }

    for(int i = 1; i < 76; i++){
        c0[i] <<= 1;
        c1[i] <<= 1;
        c2[i] <<= 1;
    }

    for(int i = 1; i < 38; i++){
        c0[i + i] += t0[i] * t0[i];
        c1[i + i] += t1[i] * t1[i];
        c2[i + i] += t2[i] * t2[i];
    }

    for(int i = 0; i < 50; i++){
        c0[i + 1] += c0[i] >> 29;
        c0[i] &= mask;
        w2[i] = c0[i];
        c1[i + 1] += c1[i] >> 29;
        c1[i] &= mask;
        w2[i + 78] = c1[i];
        c2[i + 1] += c2[i] >> 29;
        c2[i] &= mask;
    }

    for(int i = 50; i < 77; i++){
        c0[i + 1] += (long long) c0[i] >> 29;
        c0[i] &= mask;
        w2[i] = c0[i];
        c1[i + 1] += (long long) c1[i] >> 29;
        c1[i] &= mask;
        w2[i + 78] = c1[i];
        c2[i + 1] += (long long) c2[i] >> 29;
        c2[i] &= mask;
    }

    w2[77] = c0[77];
    w2[155] = c1[77];
    w2[116] += c0[77] + c1[77] - c2[77];

    for(int i = 0; i < 77; i++){
        w2[i + 39] += c0[i] + c1[i] - c2[i];
    }

    for(int i = 0; i < 38; i++){
        t0[i] = (long long) x[i] +  x[i + 78] + ((long long) x[i + 156] << 2);
        t1[i] = (long long) x[i + 39] + x[i + 117] + ((long long) x[i + 195] << 2);
        x[i + 1] += (int) (t0[i] >> 29);
        t0[i] &= mask;
        x[i + 40] += (int) (t1[i] >> 29);
        t1[i] &= mask;
        t2[i] = t0[i] - t1[i];
    }

    t0[38] = (long long) x[38] + x[116] + ((long long) x[194] << 2);
    t1[38] = (long long) x[77] + x[155] + ((long long) x[233] << 2);
    t2[38] = t0[38] - t1[38];

    for(int i = 0; i < 38; i++){
        if(t2[i] < 0){
            t2[i] += base;
            t2[i + 1]--;
        }
    }

        c0[0] = t0[0] * t0[0];
        c0[38] = t0[38] * t0[0];
        c0[76] = t0[38] * t0[38];
        c0[77] = 0;
        c1[0] = t1[0] * t1[0];
        c1[38] = t1[38] * t1[0];
        c1[76] = t1[38] * t1[38];
        c1[77] = 0;
        c2[0] = t2[0] * t2[0];
        c2[38] = t2[38] * t2[0];
        c2[76] = t2[38] * t2[38];
        c2[77] = 0;

    for(int i = 1; i < 38; i++){
        c0[i] = t0[i] * t0[0];
        c0[i + 38] = t0[i] * t0[38];
        c1[i] = t1[i] * t1[0];
        c1[i + 38] = t1[i] * t1[38];
        c2[i] = t2[i] * t2[0];
        c2[i + 38] = t2[i] * t2[38];
    }

    for(int i = 1; i < 37; i++){
        for(int j = i + 1; j < 38; j++){
            c0[i + j] += t0[i] * t0[j];
            c1[i + j] += t1[i] * t1[j];
            c2[i + j] += t2[i] * t2[j];
            carry ^= c0[i + j];
            carry ^= c1[i + j];
            carry ^= c2[i + j];
        }
    }

    for(int i = 1; i < 76; i++){
        c0[i] <<= 1;
        c1[i] <<= 1;
        c2[i] <<= 1;
    }

    for(int i = 1; i < 38; i++){
        c0[i + i] += t0[i] * t0[i];
        c1[i + i] += t1[i] * t1[i];
        c2[i + i] += t2[i] * t2[i];
    }

    for(int i = 0; i < 50; i++){
        c0[i + 1] += c0[i] >> 29;
        c0[i] &= mask;
        w3[i] = c0[i];
        c1[i + 1] += c1[i] >> 29;
        c1[i] &= mask;
        w3[i + 78] = c1[i];
        c2[i + 1] += c2[i] >> 29;
        c2[i] &= mask;
    }

    for(int i = 50; i < 77; i++){
        c0[i + 1] += c0[i] >> 29;
        c0[i] &= mask;
        w3[i] = c0[i];
        c1[i + 1] += c1[i] >> 29;
        c1[i] &= mask;
        w3[i + 78] = c1[i];
        c2[i + 1] += (long long) c2[i] >> 29;
        c2[i] &= mask;
    }

    w3[77] = c0[77];
    w3[155] = c1[77];
    w3[116] += c0[77] + c1[77] - c2[77];

    for(int i = 0; i < 77; i++){
        w3[i + 39] += c0[i] + c1[i] - c2[i];
    }

    for(int i = 0; i < 39; i++){
        t0[i] = x[i + 156];
        t1[i] = x[i + 195];
        t2[i] = t0[i] - t1[i];
    }

    for(int i = 0; i < 38; i++){
        if(t2[i] < 0){
            t2[i] += base;
            t2[i + 1]--;
        }
    }

        c0[0] = t0[0] * t0[0];
        c0[38] = t0[38] * t0[0];
        c0[76] = t0[38] * t0[38];
        c0[77] = 0;
        c1[0] = t1[0] * t1[0];
        c1[38] = t1[38] * t1[0];
        c1[76] = t1[38] * t1[38];
        c1[77] = 0;
        c2[0] = t2[0] * t2[0];
        c2[38] = t2[38] * t2[0];
        c2[76] = t2[38] * t2[38];
        c2[77] = 0;

    for(int i = 1; i < 38; i++){
        c0[i] = t0[i] * t0[0];
        c0[i + 38] = t0[i] * t0[38];
        c1[i] = t1[i] * t1[0];
        c1[i + 38] = t1[i] * t1[38];
        c2[i] = t2[i] * t2[0];
        c2[i + 38] = t2[i] * t2[38];
    }

    for(int i = 1; i < 37; i++){
        for(int j = i + 1; j < 38; j++){
            c0[i + j] += t0[i] * t0[j];
            c1[i + j] += t1[i] * t1[j];
            c2[i + j] += t2[i] * t2[j];
            carry ^= c0[i + j];
            carry ^= c1[i + j];
            carry ^= c2[i + j];
        }
    }

    for(int i = 1; i < 76; i++){
        c0[i] <<= 1;
        c1[i] <<= 1;
        c2[i] <<= 1;
    }

    for(int i = 1; i < 38; i++){
        c0[i + i] += t0[i] * t0[i];
        c1[i + i] += t1[i] * t1[i];
        c2[i + i] += t2[i] * t2[i];
    }

    for(int i = 0; i < 50; i++){
        c0[i + 1] += c0[i] >> 29;
        c0[i] &= mask;
        w4[i] = c0[i];
        c1[i + 1] += c1[i] >> 29;
        c1[i] &= mask;
        w4[i + 78] = c1[i];
        c2[i + 1] += c2[i] >> 29;
        c2[i] &= mask;
    }

    for(int i = 50; i < 77; i++){
        c0[i + 1] += c0[i] >> 29;
        c0[i] &= mask;
        w4[i] = c0[i];
        c1[i + 1] += c1[i] >> 29;
        c1[i] &= mask;
        w4[i + 78] = c1[i];
        c2[i + 1] += (long long) c2[i] >> 29;
        c2[i] &= mask;
    }

    w4[77] = c0[77];
    w4[155] = c1[77];
    w4[116] += c0[77] + c1[77] - c2[77];

    for(int i = 0; i < 77; i++){
        w4[i + 39] += c0[i] + c1[i] - c2[i];
    }
    
    w3[0] += (w2[0] << 1) + 3 * w0[0];
    w3[0] >>= 1;

    for(int i = 1; i < 156; i++){
        w3[i] += (w2[i] << 1) + 3 * w0[i];
        w3[i - 1] += (w3[i] & 1) << 28;
        w3[i] >>= 1;
    }

    long long d = 178956971;
    long long b = 0;
    long long a, bp, bpp;

    for(int i = 0; i < 156; i++){

        if(b <= w3[i]) {
            a = w3[i] - b;
            bp = 0;
        } else {
            a = w3[i] - b + base;
            bp = 1;
        }

        w3[i] = (d * a) & mask;
        bpp = (w3[i] * 3 - a) >> 29; 
        b = bp + bpp;
    }

    if(b) {
        w3[155] -= (b/3) << 29;
    }

    for(int i = 155; i > 0; i--){
        w3[i] -= w4[i] << 1;
        w2[i] += w1[i];
        w2[i - 1] += (w2[i] & 1) << 29;
        w2[i] >>= 1;
        w1[i] -= w3[i];
        w3[i] -= w2[i];
        w2[i] -= w0[i] + w4[i];
    }

        w3[0] -= w4[0] << 1;
        w2[0] += w1[0];
        w2[0] >>= 1;
        w1[0] -= w3[0];
        w3[0] -= w2[0];
        w2[0] -= w0[0] + w4[0];

    for(int i = 0; i < 78; i++) {
        r[i] = w0[i];
        r[i + 78] = w0[i + 78] + w1[i];
        r[i + 156] = w1[i + 78] + w2[i];
        r[i + 234] = w2[i + 78] + w3[i];
        r[i + 312] = w3[i + 78] + w4[i];
        r[i + 390] = w4[i + 78];
    }

    for(int i = 38; i < 430; i++){
        r[i + 1] += r[i] >> 29;
        r[i] = r[i] & mask;
    }

    for(int i = 0; i < 233; i++){
        x[i] = (r[i + 233] >> 3) + ((r[i + 234] & 7) << 26);
    }

    x[233] = r[466] >> 3;

    for(int i = 0; i < 28; i++){
        t0[i] = x[i + 66];
        t1[i] = x[i + 94];
        t2[i] = t0[i] - t1[i];
        s0[i] = inv[i + 66];
        s1[i] = inv[i + 94];
        s2[i] = s0[i] - s1[i];
    }

    for(int i = 0; i < 27; i++){
        if(t2[i] < 0) {
            t2[i] += base;
            t2[i + 1]--;
        }
        if(s2[i] < 0) {
            s2[i] += base;
            s2[i + 1]--;
        }
    }

    cc0[0] = t0[0] * s0[0];
    cc1[0] = t1[0] * s1[0];
    cc2[0] = t2[0] * s2[0];
    cc0[55] = 0;
    cc1[55] = 0;
    cc2[55] = 0;

    for(int i = 1; i < 28; i++){
        cc0[i] = t0[0] * s0[i];
        cc1[i] = t1[0] * s1[i];
        cc2[i] = t2[0] * s2[i];
        cc0[i + 27] = t0[27] * s0[i];
        cc1[i + 27] = t1[27] * s1[i];
        cc2[i + 27] = t2[27] * s2[i];
    }   

    cc0[27] += t0[27] * s0[0];
    cc1[27] += t1[27] * s1[0];
    cc2[27] += t2[27] * s2[0];
    
    for(int i = 1; i < 27; i++){
        for(int j = 0; j < 28; j++){
            cc0[i + j] += t0[i] * s0[j];
            cc1[i + j] += t1[i] * s1[j];
            cc2[i + j] += t2[i] * s2[j];
            carry ^= cc0[i + j];
            carry ^= cc1[i + j];
            carry ^= cc2[i + j];
        }
    }

    for(int i = 0; i < 55; i++){
            c = cc0[i] >> 29;
            cc0[i + 1] += c;
            cc0[i] -= c << 29;
            w0[i] = cc0[i];
            c = cc1[i] >> 29;
            cc1[i + 1] += c;
            cc1[i] -= c << 29;
            w0[i + 56] = cc1[i];
            c = cc2[i] >> 29;
            cc2[i + 1] += c;
            cc2[i] -= c << 29;
    }

    w0[55] = cc0[55];
    w0[111] = cc1[55];
    w0[83] += cc0[55] + cc1[55] - cc2[55];

    for(int i = 0; i < 55; i++){
        w0[i + 28] += cc0[i] + cc1[i] - cc2[i];
    }

    for(int i = 0; i < 111; i++){
        c = w0[i] >> 29;
            w0[i + 1] += c;
            w0[i] -= c << 29;
    }

    for(int i = 0; i < 27; i++){
        t0[i] += x[i + 122] + x[i + 178];
        t0[i + 1] += t0[i] >> 29;
        t0[i] &= mask;
        t1[i] += x[i + 150] + x[i + 206];
        t1[i + 1] += t1[i] >> 29;
        t1[i] &= mask;
        t2[i] = t0[i] - t1[i];

        s0[i] += inv[i + 122] + inv[i + 178];
        s0[i + 1] += s0[i] >> 29;
        s0[i] &= mask;
        s1[i] += inv[i + 150] + inv[i + 206];
        s1[i + 1] += s1[i] >> 29;
        s1[i] &= mask;
        s2[i] = s0[i] - s1[i];
    }

    t0[27] += x[149] + x[205];
    t1[27] += x[177] + x[233];
    t2[27] = t0[27] - t1[27];
    s0[27] += inv[149] + inv[205];
    s1[27] += inv[177] + inv[233];
    s2[27] = s0[27] - s1[27];

    for(int i = 0; i < 27; i++){
        if(t2[i] < 0) {
            t2[i] += base;
            t2[i + 1]--;
        }
        if(s2[i] < 0) {
            s2[i] += base;
            s2[i + 1]--;
        }
    }

    cc0[0] = t0[0] * s0[0];
    cc1[0] = t1[0] * s1[0];
    cc2[0] = t2[0] * s2[0];
    cc0[55] = 0;
    cc1[55] = 0;
    cc2[55] = 0;

    for(int i = 1; i < 28; i++){
        cc0[i] = t0[0] * s0[i];
        cc1[i] = t1[0] * s1[i];
        cc2[i] = t2[0] * s2[i];
        cc0[i + 27] = t0[27] * s0[i];
        cc1[i + 27] = t1[27] * s1[i];
        cc2[i + 27] = t2[27] * s2[i];
    }    

    cc0[27] += t0[27] * s0[0];
    cc1[27] += t1[27] * s1[0];
    cc2[27] += t2[27] * s2[0];
    
    for(int i = 1; i < 27; i++){
        for(int j = 0; j < 28; j++){
            cc0[i + j] += t0[i] * s0[j];
            cc1[i + j] += t1[i] * s1[j];
            cc2[i + j] += t2[i] * s2[j];
            carry ^= cc0[i + j];
            carry ^= cc1[i + j];
            carry ^= cc2[i + j];
        }
    }

    for(int i = 0; i < 55; i++) {
        cc0[i + 1] += cc0[i] >> 29;
        cc0[i] &= mask;
        w1[i] = cc0[i];
        cc1[i + 1] += cc1[i] >> 29;
        cc1[i] &= mask;
        w1[i + 56] = cc1[i];
        cc2[i + 1] += cc2[i] >> 29;
        cc2[i] &= mask;
    }

    w1[55] = cc0[55];
    w1[111] = cc1[55];
    w1[83] += cc0[55] + cc1[55] - cc2[55];

    for(int i = 0; i < 55; i++){
        w1[i + 28] += cc0[i] + cc1[i] - cc2[i];
    }

    for(int i = 122; i < 178; i++){
        x[i] <<= 1;
    }

    for(int i = 0; i < 27; i++){
        t0[i] -= x[i + 122];
        t1[i] -= x[i + 150];
        if((c = t0[i] >> 29)){
            t0[i + 1] += c;
            t0[i] -= c << 29;
        }
        if((c = t1[i] >> 29)){
            t1[i + 1] += c;
            t1[i] -= c << 29;
        }
        t2[i] = t0[i] - t1[i];

        s0[i] -= invp[i];
        s1[i] -= invp[i + 28];
        if((c = s0[i] >> 29)){
            s0[i + 1] += c;
            s0[i] -= c << 29;
        }
        if((c = s1[i] >> 29)){
            s1[i + 1] += c;
            s1[i] -= c << 29;
        }
        s2[i] = s0[i] - s1[i];
    }

    t0[27] -= x[149];
    t1[27] -= x[177];
    t2[27] = t0[27] - t1[27];
    s0[27] -= invp[27];
    s1[27] -= invp[55];
    s2[27] = s0[27] - s1[27];

    for(int i = 0; i < 27; i++){
        if(t2[i] < 0){
            t2[i] += base;
            t2[i + 1]--;
        }
        if(s2[i] < 0){
            s2[i] += base;
            s2[i + 1]--;
        }
    }

    cc0[0] = t0[0] * s0[0];
    cc1[0] = t1[0] * s1[0];
    cc2[0] = t2[0] * s2[0];
    cc0[55] = 0;
    cc1[55] = 0;
    cc2[55] = 0;

    for(int i = 1; i < 28; i++){
        cc0[i] = t0[0] * s0[i];
        cc1[i] = t1[0] * s1[i];
        cc2[i] = t2[0] * s2[i];
        cc0[i + 27] = t0[27] * s0[i];
        cc1[i + 27] = t1[27] * s1[i];
        cc2[i + 27] = t2[27] * s2[i];
    }   

    cc0[27] += t0[27] * s0[0];
    cc1[27] += t1[27] * s1[0];
    cc2[27] += t2[27] * s2[0];
    
    for(int i = 1; i < 27; i++){
        for(int j = 0; j < 28; j++){
            cc0[i + j] += t0[i] * s0[j];
            cc1[i + j] += t1[i] * s1[j];
            cc2[i + j] += t2[i] * s2[j];
            carry ^= cc0[i + j];
            carry ^= cc1[i + j];
            carry ^= cc2[i + j];
        }
    }

    for(int i = 0; i < 55; i++) {
        cc0[i + 1] += cc0[i] >> 29;
        cc0[i] &= mask;
        w2[i] = cc0[i];
        cc1[i + 1] += cc1[i] >> 29;
        cc1[i] &= mask;
        w2[i + 56] = cc1[i];
        cc2[i + 1] += cc2[i] >> 29;
        cc2[i] &= mask;
    }

    w2[55] = cc0[55];
    w2[111] = cc1[55];
    w2[83] += cc0[55] + cc1[55] - cc2[55];

    for(int i = 0; i < 55; i++){
        w2[i + 28] += cc0[i] + cc1[i] - cc2[i];
    }

    for(int i = 0; i < 27; i++){
        t0[i] = (long long) x[i + 66] +  x[i + 122] + ((long long) x[i + 178] << 2);
        t1[i] = (long long) x[i + 94] + x[i + 150] + ((long long) x[i + 206] << 2);
        x[i + 67] += (int) (t0[i] >> 29);
        t0[i] &= mask;
        x[i + 95] += (int) (t1[i] >> 29);
        t1[i] &= mask;
        t2[i] = t0[i] - t1[i];

        s0[i] = (long long) inv[i + 66] +  invp[i] + invpp[i];
        s1[i] = (long long) inv[i + 94] + invp[i + 28] + invpp[i + 28];
        s2[i] = s0[i] - s1[i];
    }

    t0[27] = (long long) x[93] + x[149] + ((long long) x[205] << 2);
    t1[27] = (long long) x[121] + x[177] + ((long long) x[233]  << 2);
    t2[27] = t0[27] - t1[27];
    s0[27] = (long long) inv[93] + invp[27] + invpp[27];
    s1[27] = (long long) inv[121] + invp[55] + invpp[55];
    s2[27] = s0[27] - s1[27];

    for(int i = 0; i < 27; i++){
        t0[i + 1] += t0[i] >> 29;
        t0[i] &= mask;
        t1[i + 1] += t1[i] >> 29;
        t1[i] &= mask;
        s0[i + 1] += s0[i] >> 29;
        s0[i] &= mask;
        s1[i + 1] += s1[i] >> 29;
        s1[i] &= mask;
        if(t2[i] < 0){
            t2[i] += base;
            t2[i + 1]--;
        }
        if(s2[i] < 0){
            s2[i] += base;
            s2[i + 1]--;
        }
    }

    cc0[0] = t0[0] * s0[0];
    cc1[0] = t1[0] * s1[0];
    cc2[0] = t2[0] * s2[0];
    cc0[55] = 0;
    cc1[55] = 0;
    cc2[55] = 0;

    for(int i = 1; i < 28; i++){
        cc0[i] = t0[0] * s0[i];
        cc1[i] = t1[0] * s1[i];
        cc2[i] = t2[0] * s2[i];
        cc0[i + 27] = t0[27] * s0[i];
        cc1[i + 27] = t1[27] * s1[i];
        cc2[i + 27] = t2[27] * s2[i];
    }    

    cc0[27] += t0[27] * s0[0];
    cc1[27] += t1[27] * s1[0];
    cc2[27] += t2[27] * s2[0];
    
    for(int i = 1; i < 27; i++){
        for(int j = 0; j < 28; j++){
            cc0[i + j] += t0[i] * s0[j];
            cc1[i + j] += t1[i] * s1[j];
            cc2[i + j] += t2[i] * s2[j];
            carry ^= cc0[i + j];
            carry ^= cc1[i + j];
            carry ^= cc2[i + j];
        }
    }

    for(int i = 0; i < 55; i++) {
        cc0[i + 1] += cc0[i] >> 29;
        cc0[i] &= mask;
        w3[i] = cc0[i];
        cc1[i + 1] += cc1[i] >> 29;
        cc1[i] &= mask;
        w3[i + 56] = cc1[i];
        cc2[i + 1] += cc2[i] >> 29;
        cc2[i] &= mask;
    }

    w3[55] = cc0[55];
    w3[111] = cc1[55];
    w3[83] += cc0[55] + cc1[55] - cc2[55];

    for(int i = 0; i < 55; i++){
        w3[i + 28] += cc0[i] + cc1[i] - cc2[i];
    }

    for(int i = 0; i < 28; i++){
        t0[i] = x[i + 178];
        t1[i] = x[i + 206];
        t2[i] = t0[i] - t1[i];
        s0[i] = inv[i + 178];
        s1[i] = inv[i + 206];
        s2[i] = s0[i] - s1[i];
    }

    for(int i = 0; i < 27; i++){
        if(t2[i] < 0){
            t2[i] += base;
            t2[i + 1]--;
        }
        if(s2[i] < 0){
            s2[i] += base;
            s2[i + 1]--;
        }
    }

    cc0[0] = t0[0] * s0[0];
    cc1[0] = t1[0] * s1[0];
    cc2[0] = t2[0] * s2[0];
    cc0[55] = 0;
    cc1[55] = 0;
    cc2[55] = 0;

    for(int i = 1; i < 28; i++){
        cc0[i] = t0[0] * s0[i];
        cc1[i] = t1[0] * s1[i];
        cc2[i] = t2[0] * s2[i];
        cc0[i + 27] = t0[27] * s0[i];
        cc1[i + 27] = t1[27] * s1[i];
        cc2[i + 27] = t2[27] * s2[i];
    }    

    cc0[27] += t0[27] * s0[0];
    cc1[27] += t1[27] * s1[0];
    cc2[27] += t2[27] * s2[0];
    
    for(int i = 1; i < 27; i++){
        for(int j = 0; j < 28; j++){
            cc0[i + j] += t0[i] * s0[j];
            cc1[i + j] += t1[i] * s1[j];
            cc2[i + j] += t2[i] * s2[j];
            carry ^= cc0[i + j];
            carry ^= cc1[i + j];
            carry ^= cc2[i + j];
        }
    }

    for(int i = 0; i < 55; i++) {
        cc0[i + 1] += cc0[i] >> 29;
        cc0[i] &= mask;
        w4[i] = cc0[i];
        cc1[i + 1] += cc1[i] >> 29;
        cc1[i] &= mask;
        w4[i + 56] = cc1[i];
        cc2[i + 1] += cc2[i] >> 29;
        cc2[i] &= mask;
    }

    w4[55] = cc0[55];
    w4[111] = cc1[55];
    w4[83] += cc0[55] + cc1[55] - cc2[55];

    for(int i = 0; i < 55; i++){
        w4[i + 28] += cc0[i] + cc1[i] - cc2[i];
    }

    for(int i = 0; i < 111; i ++){
        w1[i + 1] += w1[i] >> 29;
        w1[i] &= mask;
        w2[i + 1] += w2[i] >> 29;
        w2[i] &= mask;
        w3[i + 1] += w3[i] >> 29;
        w3[i] &= mask;
        w4[i + 1] += w4[i] >> 29;
        w4[i] &= mask;
    }

    w3[0] += (w2[0] << 1) + 3 * w0[0];
    w3[0] >>= 1;

    for(int i = 1; i < 112; i++){
        w3[i] += (w2[i] << 1) + 3 * w0[i];
        w3[i - 1] += (w3[i] & 1) << 28;
        w3[i] >>= 1;
    }

    b = 0;

    for(int i = 0; i < 112; i++){
        if(b <= w3[i]) {
            a = w3[i] - b;
            bp = 0;
        } else {
            a = w3[i] - b + base;
            bp = 1;
        }
        w3[i] = (d * a) & mask;
        bpp = (w3[i] * 3 - a) >> 29; 
        b = bp + bpp;
    }

    if(b) {
        w3[111] -= (b/3) << 29;
    }

    for(int i = 111; i > 0; i--){
        w3[i] -= w4[i] << 1;
        w2[i] += w1[i];
        w2[i - 1] += (w2[i] & 1) << 29;
        w2[i] >>= 1;
        w1[i] -= w3[i];
        w3[i] -= w2[i];
        w2[i] -= w0[i] + w4[i];
    }

        w3[0] -= w4[0] << 1;
        w2[0] += w1[0];
        w2[0] >>= 1;
        w1[0] -= w3[0];
        w3[0] -= w2[0];
        w2[0] -= w0[0] + w4[0];

    for(int i = 0; i < 56; i++) {
        q[i] = w0[i + 56] + w1[i];
        q[i + 56] = w1[i + 56] + w2[i];
        q[i + 112] = w2[i + 56] + w3[i];
        q[i + 168] = w3[i + 56] + w4[i];
        q[i + 224] = w4[i + 56];
    }

    for(int i = 167; i < 178; i++){
        x[i] >>= 1;
    }

    for(int i = 0; i < 66; i++){
        for(int j = 232 - i; j < 234; j++){
            c = (long long) inv[i] * x[j] + (long long) inv[j] * x[i];
            carry ^= (q[i + j - 188] += c & mask);
            carry ^= (q[i + j - 187] += c >> 29);
        }
    }

    for(int i = 35; i < 47; i++){              
        q[i + 1] += q[i] >> 29;
        q[i] = q[i] & mask;
    }

    for(int i = 0; i < 233; i++){           
        q[i + 46] += q[i + 45] >> 29;
        q[i + 45] &= mask;
        x[i] = (q[i + 45] >> 3) + ((q[i + 46] & 7) << 26);
    }

    x[233] = (int) ((q[278] & mask) >> 3);

    for(int i = 0; i < 28; i++){
        t0[i] = x[i];
        t1[i] = x[i + 28];
        t2[i] = t0[i] - t1[i];
        s0[i] = m[i];
        s1[i] = m[i + 28];
        s2[i] = s0[i] - s1[i];
    }

    for(int i = 0; i < 27; i++){
        if(t2[i] < 0) {
            t2[i] += base;
            t2[i + 1]--;
        }
        if(s2[i] < 0) {
            s2[i] += base;
            s2[i + 1]--;
        }
    }

    cc0[0] = t0[0] * s0[0];
    cc1[0] = t1[0] * s1[0];
    cc2[0] = t2[0] * s2[0];
    cc0[55] = 0;
    cc1[55] = 0;
    cc2[55] = 0;

    for(int i = 1; i < 28; i++){
        cc0[i] = t0[0] * s0[i];
        cc1[i] = t1[0] * s1[i];
        cc2[i] = t2[0] * s2[i];
        cc0[i + 27] = t0[27] * s0[i];
        cc1[i + 27] = t1[27] * s1[i];
        cc2[i + 27] = t2[27] * s2[i];
    }    

    cc0[27] += t0[27] * s0[0];
    cc1[27] += t1[27] * s1[0];
    cc2[27] += t2[27] * s2[0];
    
    for(int i = 1; i < 27; i++){
        for(int j = 0; j < 28; j++){
            cc0[i + j] += t0[i] * s0[j];
            cc1[i + j] += t1[i] * s1[j];
            cc2[i + j] += t2[i] * s2[j];
            carry ^= cc0[i + j];
            carry ^= cc1[i + j];
            carry ^= cc2[i + j];
        }
    }

    for(int i = 0; i < 55; i++) {
        cc0[i + 1] += cc0[i] >> 29;
        cc0[i] &= mask;
        w0[i] = cc0[i];
        cc1[i + 1] += cc1[i] >> 29;
        cc1[i] &= mask;
        w0[i + 56] = cc1[i];
        cc2[i + 1] += cc2[i] >> 29;
        cc2[i] &= mask;
    }

    w0[55] = cc0[55];
    w0[111] = cc1[55];
    w0[83] += cc0[55] + cc1[55] - cc2[55];

    for(int i = 0; i < 55; i++){
        w0[i + 28] += cc0[i] + cc1[i] - cc2[i];
    }

    for(int i = 0; i < 27; i++){
        t0[i] += x[i + 56] + x[i + 112];
        t0[i + 1] += t0[i] >> 29;
        t0[i] &= mask;
        t1[i] += x[i + 84] + x[i + 140];
        t1[i + 1] += t1[i] >> 29;
        t1[i] &= mask;
        t2[i] = t0[i] - t1[i];

        s0[i] += m[i + 56] + m[i + 112];
        s0[i + 1] += s0[i] >> 29;
        s0[i] &= mask;
        s1[i] += m[i + 84] + m[i + 140];
        s1[i + 1] += s1[i] >> 29;
        s1[i] &= mask;
        s2[i] = s0[i] - s1[i];
    }

    t0[27] += x[83] + x[139];
    t1[27] += x[111] + x[167];
    t2[27] = t0[27] - t1[27];
    s0[27] += m[83] + m[139];
    s1[27] += m[111] + m[167];
    s2[27] = s0[27] - s1[27];

    for(int i = 0; i < 27; i++){
        if(t2[i] < 0) {
            t2[i] += base;
            t2[i + 1]--;
        }
        if(s2[i] < 0) {
            s2[i] += base;
            s2[i + 1]--;
        }
    }

    cc0[0] = t0[0] * s0[0];
    cc1[0] = t1[0] * s1[0];
    cc2[0] = t2[0] * s2[0];
    cc0[55] = 0;
    cc1[55] = 0;
    cc2[55] = 0;

    for(int i = 1; i < 28; i++){
        cc0[i] = t0[0] * s0[i];
        cc1[i] = t1[0] * s1[i];
        cc2[i] = t2[0] * s2[i];
        cc0[i + 27] = t0[27] * s0[i];
        cc1[i + 27] = t1[27] * s1[i];
        cc2[i + 27] = t2[27] * s2[i];
    }    

    cc0[27] += t0[27] * s0[0];
    cc1[27] += t1[27] * s1[0];
    cc2[27] += t2[27] * s2[0];
    
    for(int i = 1; i < 27; i++){
        for(int j = 0; j < 28; j++){
            cc0[i + j] += t0[i] * s0[j];
            cc1[i + j] += t1[i] * s1[j];
            cc2[i + j] += t2[i] * s2[j];
            carry ^= cc0[i + j];
            carry ^= cc1[i + j];
            carry ^= cc2[i + j];
        }
    }

    for(int i = 0; i < 55; i++) {
        cc0[i + 1] += cc0[i] >> 29;
        cc0[i] &= mask;
        w1[i] = cc0[i];
        cc1[i + 1] += cc1[i] >> 29;
        cc1[i] &= mask;
        w1[i + 56] = cc1[i];
        cc2[i + 1] += cc2[i] >> 29;
        cc2[i] &= mask;
    }

    w1[55] = cc0[55];
    w1[111] = cc1[55];
    w1[83] += cc0[55] + cc1[55] - cc2[55];

    for(int i = 0; i < 55; i++){
        w1[i + 28] += cc0[i] + cc1[i] - cc2[i];
    }

    for(int i = 56; i < 112; i++){
        x[i] <<= 1;
    }

    for(int i = 0; i < 27; i++){
        t0[i] -= x[i + 56];
        t1[i] -= x[i + 84];
        if((c = t0[i] >> 29)){
            t0[i + 1] += c;
            t0[i] -= c << 29;
        }
        if((c = t1[i] >> 29)){
            t1[i + 1] += c;
            t1[i] -= c << 29;
        }
        t2[i] = t0[i] - t1[i];

        s0[i] -= mp[i];
        s1[i] -= mp[i + 28];
        if((c = s0[i] >> 29)){
            s0[i + 1] += c;
            s0[i] -= c << 29;
        }
        if((c = s1[i] >> 29)){
            s1[i + 1] += c;
            s1[i] -= c << 29;
        }
        s2[i] = s0[i] - s1[i];
    }

    t0[27] -= x[83];
    t1[27] -= x[111];
    t2[27] = t0[27] - t1[27];
    s0[27] -= mp[27];
    s1[27] -= mp[55];
    s2[27] = s0[27] - s1[27];

    for(int i = 0; i < 27; i++){
        if(t2[i] < 0){
            t2[i] += base;
            t2[i + 1]--;
        }
        if(s2[i] < 0){
            s2[i] += base;
            s2[i + 1]--;
        }
    }
   
    cc0[0] = t0[0] * s0[0];
    cc1[0] = t1[0] * s1[0];
    cc2[0] = t2[0] * s2[0];
    cc0[55] = 0;
    cc1[55] = 0;
    cc2[55] = 0;

    for(int i = 1; i < 28; i++){
        cc0[i] = t0[0] * s0[i];
        cc1[i] = t1[0] * s1[i];
        cc2[i] = t2[0] * s2[i];
        cc0[i + 27] = t0[27] * s0[i];
        cc1[i + 27] = t1[27] * s1[i];
        cc2[i + 27] = t2[27] * s2[i];
    }    

    cc0[27] += t0[27] * s0[0];
    cc1[27] += t1[27] * s1[0];
    cc2[27] += t2[27] * s2[0];
    
    for(int i = 1; i < 27; i++){
        for(int j = 0; j < 28; j++){
            cc0[i + j] += t0[i] * s0[j];
            cc1[i + j] += t1[i] * s1[j];
            cc2[i + j] += t2[i] * s2[j];
            carry ^= cc0[i + j];
            carry ^= cc1[i + j];
            carry ^= cc2[i + j];
        }
    }

    for(int i = 0; i < 55; i++) {
        cc0[i + 1] += cc0[i] >> 29;
        cc0[i] &= mask;
        w2[i] = cc0[i];
        cc1[i + 1] += cc1[i] >> 29;
        cc1[i] &= mask;
        w2[i + 56] = cc1[i];
        cc2[i + 1] += cc2[i] >> 29;
        cc2[i] &= mask;
    }

    w2[55] = cc0[55];
    w2[111] = cc1[55];
    w2[83] += cc0[55] + cc1[55] - cc2[55];

    for(int i = 0; i < 55; i++){
        w2[i + 28] += cc0[i] + cc1[i] - cc2[i];
    }

    for(int i = 0; i < 28; i++){
        t0[i] = (long long) x[i] +  x[i + 56] + ((long long) x[i + 112] << 2);
        t1[i] = (long long) x[i + 28] + x[i + 84] + ((long long) x[i + 140] << 2);
        s0[i] = (long long) m[i] +  mp[i] + mpp[i];
        s1[i] = (long long) m[i + 28] + mp[i + 28] + mpp[i + 28];
        s2[i] = s0[i] - s1[i];
        t2[i] = t0[i] - t1[i];
    }

    for(int i = 0; i < 27; i++){
        t0[i + 1] += t0[i] >> 29;
        t0[i] &= mask;
        t1[i + 1] += t1[i] >> 29;
        t1[i] &= mask;
        t2[i + 1] += t2[i] >> 29;
        t2[i] &= mask;
        s0[i + 1] += s0[i] >> 29;
        s0[i] &= mask;
        s1[i + 1] += s1[i] >> 29;
        s1[i] &= mask;
        s2[i + 1] += s2[i] >> 29;
        s2[i] &= mask;
    }

    cc0[0] = t0[0] * s0[0];
    cc1[0] = t1[0] * s1[0];
    cc2[0] = t2[0] * s2[0];
    cc0[55] = 0;
    cc1[55] = 0;
    cc2[55] = 0;

    for(int i = 1; i < 28; i++){
        cc0[i] = t0[0] * s0[i];
        cc1[i] = t1[0] * s1[i];
        cc2[i] = t2[0] * s2[i];
        cc0[i + 27] = t0[27] * s0[i];
        cc1[i + 27] = t1[27] * s1[i];
        cc2[i + 27] = t2[27] * s2[i];
    }    

    cc0[27] += t0[27] * s0[0];
    cc1[27] += t1[27] * s1[0];
    cc2[27] += t2[27] * s2[0];
    
    for(int i = 1; i < 27; i++){
        for(int j = 0; j < 28; j++){
            cc0[i + j] += t0[i] * s0[j];
            cc1[i + j] += t1[i] * s1[j];
            cc2[i + j] += t2[i] * s2[j];
            carry ^= cc0[i + j];
            carry ^= cc1[i + j];
            carry ^= cc2[i + j];
        }
    }

    for(int i = 0; i < 55; i++) {
        cc0[i + 1] += cc0[i] >> 29;
        cc0[i] &= mask;
        w3[i] = cc0[i];
        cc1[i + 1] += cc1[i] >> 29;
        cc1[i] &= mask;
        w3[i + 56] = cc1[i];
        cc2[i + 1] += cc2[i] >> 29;
        cc2[i] &= mask;
    }

    w3[55] = cc0[55];
    w3[111] = cc1[55];
    w3[83] += cc0[55] + cc1[55] - cc2[55];

    for(int i = 0; i < 55; i++){
        w3[i + 28] += cc0[i] + cc1[i] - cc2[i];
    }

    for(int i = 0; i < 28; i++){
        t0[i] = x[i + 112];
        t1[i] = x[i + 140];
        t2[i] = t0[i] - t1[i];
        s0[i] = m[i + 112];
        s1[i] = m[i + 140];
        s2[i] = s0[i] - s1[i];
    }

    for(int i = 0; i < 27; i++){
        if(t2[i] < 0){
            t2[i] += base;
            t2[i + 1]--;
        }
        if(s2[i] < 0){
            s2[i] += base;
            s2[i + 1]--;
        }
    }

    cc0[0] = t0[0] * s0[0];
    cc1[0] = t1[0] * s1[0];
    cc2[0] = t2[0] * s2[0];
    cc0[55] = 0;
    cc1[55] = 0;
    cc2[55] = 0;

    for(int i = 1; i < 28; i++){
        cc0[i] = t0[0] * s0[i];
        cc1[i] = t1[0] * s1[i];
        cc2[i] = t2[0] * s2[i];
        cc0[i + 27] = t0[27] * s0[i];
        cc1[i + 27] = t1[27] * s1[i];
        cc2[i + 27] = t2[27] * s2[i];
    }    

    cc0[27] += t0[27] * s0[0];
    cc1[27] += t1[27] * s1[0];
    cc2[27] += t2[27] * s2[0];
    
    for(int i = 1; i < 27; i++){
        for(int j = 0; j < 28; j++){
            cc0[i + j] += t0[i] * s0[j];
            cc1[i + j] += t1[i] * s1[j];
            cc2[i + j] += t2[i] * s2[j];
            carry ^= cc0[i + j];
            carry ^= cc1[i + j];
            carry ^= cc2[i + j];
        }
    }

    for(int i = 0; i < 55; i++) {
        cc0[i + 1] += cc0[i] >> 29;
        cc0[i] &= mask;
        w4[i] = cc0[i];
        cc1[i + 1] += cc1[i] >> 29;
        cc1[i] &= mask;
        w4[i + 56] = cc1[i];
        cc2[i + 1] += cc2[i] >> 29;
        cc2[i] &= mask;
    }

    w4[55] = cc0[55];
    w4[111] = cc1[55];
    w4[83] += cc0[55] + cc1[55] - cc2[55];

    for(int i = 0; i < 55; i++){
        w4[i + 28] += cc0[i] + cc1[i] - cc2[i];
    }

    w3[0] += (w2[0] << 1) + 3 * w0[0];
    w3[0] >>= 1;

    for(int i = 1; i < 112; i++){
        w3[i] += (w2[i] << 1) + 3 * w0[i];
        w3[i - 1] += (w3[i] & 1) << 28;
        w3[i] >>= 1;
    }

    b = 0;

    for(int i = 0; i < 112; i++){
        if(b <= w3[i]) {
            a = w3[i] - b;
            bp = 0;
        } else {
            a = w3[i] - b + base;
            bp = 1;
        }
        w3[i] = (d * a) & mask;
        bpp = (w3[i] * 3 - a) >> 29; 
        b = bp + bpp;
    }

    if(b) {
        w3[111] -= (b/3) << 29;
    }

    for(int i = 111; i > 0; i--){
        w3[i] -= w4[i] << 1;
        w2[i] += w1[i];
        w2[i - 1] += (w2[i] & 1) << 29;
        w2[i] >>= 1;
        w1[i] -= w3[i];
        w3[i] -= w2[i];
        w2[i] -= w0[i] + w4[i];
    }

        w3[0] -= w4[0] << 1;
        w2[0] += w1[0];
        w2[0] >>= 1;
        w1[0] -= w3[0];
        w3[0] -= w2[0];
        w2[0] -= w0[0] + w4[0];

    for(int i = 0; i < 56; i++) {
        q[i] = w0[i];
        q[i + 56] = w0[i + 56] + w1[i]; 
        q[i + 112] = w1[i + 56] + w2[i];
        q[i + 168] = w2[i + 56] + w3[i];
        q[i + 224] = w3[i + 56] + w4[i];
    }

    for(int i = 56; i < 66; i++){
        x[i] >>= 1;
    }

    for(int i = 0; i < 66; i++){
        for(int j = 168; j < 234 - i; j++){
            c = (long long) m[i] * x[j] + (long long) m[j] * x[i];
            carry ^= (q[i + j] += c & mask);
            carry ^= (q[i + j + 1] += c >> 29);
        }
    }

    for(int i = 0; i < 234; i++){           
        q[i + 1] += q[i] >> 29;
        q[i] = q[i] & mask;
    }

    for(int i = 0; i < 234; i++){           
        r[i] -= q[i];
        if(r[i] < 0){
            r[i] += base;
            r[i + 1]--;
        }
    }

    int stop = 10;

    while(((r[233] > m[233]) || (r[233] == m[233] && r[232] >= m[232])) && stop){

        for(int i = 0; i < 234; i++){
            r[i] -= m[i];
            if(r[i] < 0){
                r[i] += base;
                r[i + 1]--;
            }
        }
        stop--;
    }

    if(!stop){
        r[233] = 0;
    }

    if(r[233] < 0){
        for(int i = 0; i < 234; i++){
            r[i] += m[i];
            if(r[i] > base){
                r[i] -= base;
                r[i + 1]++;
            }
        }
    }

    for(int i = 0; i < 234; i++){
        x[i] = (int) r[i];
    }

    password[k] ^= (x[0] & 1) << l;
    password[count] ^= ((x[0] & 3) >> 1) << l;

}

}

for(int i = 3; i < 16; i++){
    password[i] &= 63;
}
    carry &= 4095;

}


    xs = password[3] + (password[4] << 6) + (password[5] << 12) + (password[6] << 18) + (password[7] << 24) + (password[13] << 30);
    cng = password[8] + (password[9] << 6) + (password[10] << 12) + (password[11] << 18) + (password[12] << 24) + ((password[13] & 12) << 28);

    carry ^= password[14] + (password[15] << 6);

    state[3003] ^= (password[13] & 48);

    for(int i = 0; i < 510510; i++){
        jj = (jj < 4826) ? jj + 1 : 0;
        kk = (kk < 16383) ? kk + 1 : 0;
        xx = state[jj];
        tt = (xx << 12) + carry;
        carry = (xx >> 20) - (tt < xx);
        state[jj] = ~(tt - xx);
        cng = 69069 * cng + 13579;
        xs ^= xs << 13; 
        xs ^= xs >> 17;
        xs ^= xs << 5;
        xx = state[jj] + xs + cng;
        ss1 = xx & 127;
        ss2 = xx >> 25;
        strr <<= 7;
        strr += ast & 127;
        ast = table[(ss2 << 7) + (ast >> 7)];
        if((ww = spread[kk]) >> 7 != ss1){
            vv = (state[jj] & 127) + (ss1 << 7);
            gg = table[vv];

            table[ww] = gg;
            table[vv] = kk;
            spread[kk] = vv;
            spread[gg] = ww;
        }    
    }

    for(int i = 0; i < 7; i ++){
        for(int l = 16; l < 88; l++){
            jj = (jj < 4826) ? jj + 1 : 0;
            kk = (kk < 16383) ? kk + 1 : 0;
            xx = state[jj];
            tt = (xx << 12) + carry;
            carry = (xx >> 20) - (tt < xx);
            state[jj] = ~(tt - xx);
            cng = 69069 * cng + 13579;
            xs ^= xs << 13; 
            xs ^= xs >> 17;
            xs ^= xs << 5;
            xx = state[jj] + xs + cng;
            ss1 = xx & 127;
            ss2 = xx >> 25;
            strr <<= 7;
            strr += ast & 127;
            ast = table[(ss2 << 7) + (ast >> 7)];
            if((ww = spread[kk]) >> 7 != ss1){
                vv = (state[jj] & 127) + (ss1 << 7);
                gg = table[vv];

                table[ww] = gg;
                table[vv] = kk;
                spread[kk] = vv;
                spread[gg] = ww;
            }
            xx ^= strr;
            password[l] ^= (xx & 8192) >> (13 - i);
        }
    }

    for(int i = 0; i < 12; i++){
        for(int l = 0; l < 6; l++){
            password[88 + i] ^= (password[16 + l + 6 * i] & 64) >> (6 - l);
            password[16 + l + 6 * i] &= 63;
        }
    }

    for(int i = 16; i < 100; i++) pw[i] = (char) password[i];

}