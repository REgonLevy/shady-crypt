#include <stdio.h>
#include "unif01.h"
#include "bbattery.h"

static int state[4827], c = 1234;
static int lcg = 123456789, xors = 987654321;
static int s1, s2, ast, stream;
static int j = 4827, k = 1024;
static int spread[1024], table[1024];

void fill(){

    for(int i = 0; i < 4827; i++){
        lcg = 69069 * lcg + 13579;
        xors ^= xors << 13;
        xors ^= (unsigned int) xors >> 17;
        xors ^= xors << 5;
        state[i] = lcg + xors;
    }

    for(int i = 0; i < 32; i++){
        for(int l = 0; l < 32; l++){
            spread[32 * l + i] = 32 * i + l;
            table[32 * i + l] = 32 * l + i;
        }
    }
    
    ast = (lcg + xors) & 1023;

    int flip = 1 << 31;
    int t, x, v, w, g;

    for (int i = 0; i < 30030; i++){

        j = (j < 4826) ? j + 1 : 0;
        k = (k < 1023) ? k + 1 : 0;
        x = state[j];
        t = (x << 12) + c;
        c = ((unsigned int) x >> 20) - ((t ^ flip) < (x ^ flip));
        state[j] = ~(t - x);
        lcg = 69069 * lcg + 13579;
        xors ^= xors << 13;
        xors ^= (unsigned int) xors >> 17;
        xors ^= xors << 5;
        x = state[j] + lcg + xors;
        s1 = x & 31;
        s2 = (unsigned int) x >> 27;
        stream <<= 5;
        stream += ast & 31;
        ast = table[(s2 << 5) + (ast >> 5)];

        if((w = spread[k]) >> 5 != s1){
            v = (state[j] & 15) + (s1 << 5);
            g = table[v];
            table[w] = g;
            table[v] = k;
            spread[k] = v;
            spread[g] = w;
        }
    }
}

int tansgen(){

    int t, x, v, w, g;
    int flip = 1 << 31;

    j = (j < 4826) ? j + 1 : 0;
    k = (k < 1023) ? k + 1 : 0;
    x = state[j];
    t = (x << 12) + c;
    c = ((unsigned int) x >> 20) - ((t ^ flip) < (x ^ flip));
    state[j] = ~(t - x);
    lcg = 69069 * lcg + 13579;
    xors ^= xors << 13;
    xors ^= (unsigned int) xors >> 17;
    xors ^= xors << 5;
    x = state[j] + lcg + xors;
    s1 = x & 31;
    s2 = (unsigned int) x >> 27;
    stream <<= 5;
    stream += ast & 31;
    ast = table[(s2 << 5) + (ast >> 5)];

    if((w = spread[k]) >> 5 != s1){
        v = (state[j] & 15) + (s1 << 5);
        g = table[v];
        table[w] = g;
        table[v] = k;
        spread[k] = v;
        spread[g] = w;
    }

    return x ^ stream;
}


int main() {

    fill();

    int rep[107];
    int test, nr, tn;
    char nums[10];
    int full = 1;

    printf("Enter 1 for TestU01 Small Crush, 2 for TestU01 Crush, 3 for TestU01 Big Crush: ");
    scanf("%d", &test);

    if(test > 3 || test < 1){
        printf("Please pick a valid test.\n");
        return 0;
    }

    printf("\nEnter 0 to run the full test suite, or enter 'R' to repeat individual tests: ");
    scanf("%s", &nums);

    if (nums[0] == 114 || nums[0] == 82){

        for(int i = 0; i < 107; i++){
            rep[i] = 0;
        }
        printf("\nEnter the number of the test you wish to repeat: ");
        scanf("%d", &tn);
        while(tn){
            printf("\nHow many times do you wish to repeat test %d? ", tn);
            scanf("%d", &nr);

            rep[tn] = nr;
            
            printf("\nTo repeat another test, enter the test number, or enter 0 to if you are finished: ");
            scanf("%d", &tn);
        }
        full = 0;
    }

    printf("\nEnter 'C' to choose seeds, or any other key to use the defaults: ");
    scanf("%s", &nums);
    if(nums[0] == 99 || nums[0] == 67){
        printf("\nEnter an integer between -2147483648 and 2147483647, inclusive, for Seeds 1 and 2, and an integer between 0 and 4095, inclusive, for Seed 3. \n\n");
        printf("Seed 1: ");
        scanf("%d", &xors);
        printf("Seed 2: ");
        scanf("%d", &lcg);
        printf("Seed 3: ");
        scanf("%d", &c);
        c &= 4095;
    }

    unif01_Gen* gen = unif01_CreateExternGenBits("Shady tANS Generator", tansgen);
   
    if (full){
        if (test == 1) {
            bbattery_SmallCrush(gen); 
        } else if (test == 2) {
            bbattery_Crush(gen); 
        } else {
            bbattery_BigCrush(gen); 
        }
    } else {
        if (test == 1) {
            bbattery_RepeatSmallCrush(gen, rep); 
        } else if (test == 2) {
            bbattery_RepeatCrush(gen, rep); 
        } else {
            bbattery_RepeatBigCrush(gen, rep); 
        }
    }

    unif01_DeleteExternGenBits(gen);

    return 0;
}
