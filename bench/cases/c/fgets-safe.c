// expect: none
#include <stdio.h>
int main(void) { char name[32]; fgets(name, sizeof name, stdin); return 0; }
