#include <stdio.h>

int main(){
    int x;
    scanf("%d",&x);
    if(x<10){
        printf("%d",x);
    } else if(x<20){
        printf("%d",x+10);
    } else {
        printf("%d",x+20);
    }
    return 0;
}