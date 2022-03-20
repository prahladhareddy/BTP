# include <iostream>
using namespace std;
int fun(int a){
    int b;
    cin>>b;
    return b+a;
}

int fun2(int a){
    int c;
    cin>>c;
    return fun(a+c);
}
int main(){
    int a;
    cin>>a;
    cout<<fun(a);
    cout<<fun2(a);
    
}