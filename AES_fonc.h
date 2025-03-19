byte xtime(byte n)
{
    if(getBit(n,7)==1){
        n:<<1;
        n^=27;
    }
    else{
        n<<1;
        return n;
    }
}

void mixcolumns(byte state[4][NB])
{
    for(int c=0;c<NB;c++)
    {
        byte s0=state[0][c],
        s1=state[1][c],
        s2=state[2][c],
        s3=state[3][c];
        byte s0p=xtime(s0)^xtime(s1)^s1^s2^s3,
        s1p=s0^xtime(s1)^xtime(s2)^s2^s3,
        s2p=s0^s1^xtime(s2)^xtime(s3)^s3,
        s3p=xtime(s0)^s0^s1^s2^xtime(s3);

        state[0][c]=s0p;
        state[1][c]=s1p;
        state[2][c]=s2p;
        state[3][c]=s3p;
    }
}


void InvMixcolunm(byte state[4][NB]){
    for(int c=0;c<NB;c++)
    {
        byte s0=state[0][c],
             s1=state[1][c],
             s2=state[2][c],
             s3=state[3][c];
        byte s1_2=xtime(s1),
             s1_4=xtime(s1_2),
             s1_8=xtime(s1_4);
        byte s2_2=xtime(s2),
             s2_4=xtime(s2_2),
             s2_8=xtime(s2_4);
        byte s3_2=xtime(s3),
             s3_4=xtime(s3_2),
             s3_8=xtime(s3_4);
    }
}