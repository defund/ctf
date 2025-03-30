def sample(self, t, sk):
    '''
    samples a preimage for t under sk's public key
    adapted from the the sign method in uov.py
    '''

    #   unpack secret key if necessary
    if self.skc:
        sk = self.expand_sk(sk)

    #   separate components
    j   =   self.seed_sk_sz
    seed_sk =   sk[ : self.seed_sk_sz ]
    so  =   sk[ self.seed_sk_sz :
                self.seed_sk_sz + self.so_sz ]
    p1  =   sk[ self.seed_sk_sz + self.so_sz :
                self.seed_sk_sz + self.so_sz + self.p1_sz ]
    sks =   sk[ self.seed_sk_sz + self.so_sz + self.p1_sz :
                self.seed_sk_sz + self.so_sz + self.p1_sz + self.p2_sz ]

    #   deserialization
    mo  =   [ self.gf_unpack( so[i : i + self.v_sz] )
                for i in range(0, self.so_sz, self.v_sz) ]
    m1  =   self.unpack_mtri(p1, self.v)
    ms  =   self.unpack_mrect(sks, self.v, self.m)

    #   1:  salt <- {0, 1}^salt_len
    salt    =   self.rbg(self.salt_sz)

    #   2:  t <- hash( mu || salt )
    # t   =   self.shake256(msg + salt, self.m_sz)

    #   3:  for ctr = 0 upto 255 do
    ctr =   0
    x   =   None
    while x == None and ctr < 0x100:
        #   4:  v := Expand_v(mu || salt || seed_sk || ctr)
        # v   =   self.gf_unpack(self.shake256(
        #                 msg + salt + seed_sk + bytes([ctr]), self.v_sz))
        v   =   self.gf_unpack(self.shake256(
                        salt + seed_sk + bytes([ctr]), self.v_sz))
        ctr +=  1

        #   5:  L := 0_{m*m}
        ll  =   [ 0 ] * self.m

        #   6:  for i = 1 upto m do
        for i in range(self.m):

        #   7:      Set i-th row of L to v^T S_i
            for j in range(self.v):
                ll[i] ^= self.gf_mulm(ms[j][i], v[j])

        #   9:      y <- v^t * Pi^(1) * v
        #   10:     Solve Lx = t - y for x

        #   "evaluate P1 with the vinegars"
        r = int.from_bytes(t)
        for i in range(self.v):
            u = 0
            for j in range(i, self.v):
                u ^= self.gf_mulm( m1[i][j], v[j] )
            r ^= self.gf_mulm( u, v[i] )
        r = self.gf_unpack(r.to_bytes(self.m_sz))

        x = self.gauss_solve(ll, r)

    #   y = O * x
    y = bytearray(v)        #   subtract from v
    for i in range(self.m):
        for j in range(self.v):
            y[j] ^= self.gf_mul(mo[i][j], x[i])

    #   construct signature
    # sig = self.gf_pack(y) + self.gf_pack(x) + salt

    # return  sig
    return self.gf_pack(y) + self.gf_pack(x)
