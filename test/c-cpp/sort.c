#include <stdio.h>

int sort(int* a,int n){
    for(int i=n-1;i>=0;i--){
        for(int j=1;j<=i;j++){
            int x = a[j];
            int y = a[j-1];
            if(x<y){
                a[j] = y;
                a[j-1] = x;
            }
        }
    }
}

int main(){
	int a[100];
    int n;
    scanf("%d",&n);
    for(int i=0;i<n;i++){
        int x;
        scanf("%d",&x);
        a[i] = x;
    }
    sort(a,n);
    for(int i=0;i<n;i++){
        printf("%d ",a[i]);
    }
    printf("\n");
}
