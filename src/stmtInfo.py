class stmtInfo:
    def __init__(self,stmt):
        self.init()
        self.__extract_stmt_info(stmt)
    
    def init(self):
        self.tempAss = []
        self.guestAss = []
        self.memAss = False
        self.usedTemps = []
        self.usedguest = []
        self.usedMem = []
        self.addr = 0
        self.memRead = False
        self.condWrite = []
        self.InstEnd = False
        self.BlockEnd = False

        
    def __extract_stmt_info(self,stmt):
        if stmt.tag == 'Ist_NoOp':
            self.__NoOp(stmt)
        if stmt.tag == 'Ist_IMark':
            self.__IMark(stmt)
        if stmt.tag == 'Ist_AbiHint':
            self.__AbiHint(stmt)
        if stmt.tag == 'Ist_Put':
            self.__Put(stmt)
        if stmt.tag == 'Ist_PutI':
            self.__PutI(stmt)
        if stmt.tag == 'Ist_WrTmp':
            self.__WrTmp(stmt)
        if stmt.tag == 'Ist_Store':
            self.__Store(stmt)
        if stmt.tag == 'Ist_CAS':
            self.__CAS(stmt)
        if stmt.tag == 'Ist_LLSC':
            self.__LLSC(stmt)
        if stmt.tag == 'Ist_MBE':
            self.__MBE(stmt)
        if stmt.tag == 'Ist_Dirty':
            self.__Dirty(stmt)
        if stmt.tag == 'Ist_Exit':
            self.__Exit(stmt)
        if stmt.tag == 'Ist_LoadG':
            self.__LoadG(stmt)
        if stmt.tag == 'Ist_StoreG':
            self.__StoreG(stmt)

    def __NoOp(self,stmt):
        print("NoOp found")

    def __IMark(self,stmt):
        self.addr = stmt.addr
        self.InstEnd = True

    def __AbiHint(self,stmt):
        # raise Exception('Not Implimented AbiHint')
        self.InstEnd = True
        self.BlockEnd = True
        pass

    def __Put(self,stmt):
        self.guestAss.append(stmt.offset)
        self.__parseData(stmt.data)
        # raise Exception('Not Implimented Put')

    def __PutI(self,stmt):
        raise Exception('Not Implimented PutI')

    def __WrTmp(self,stmt):
        self.tempAss.append(stmt.tmp)
        self.__parseData(stmt.data)
        # raise Exception('Not Implimented WrTmp')

    def __Store(self,stmt):
        self.memAss = False
        self.usedMem.append(stmt.addr)
        self.__parseData(stmt.data)
        # raise Exception('Not Implimented Store')

    def __CAS(self,stmt):
        raise Exception('Not Implimented CAS')

    def __LLSC(self,stmt):
        raise Exception('Not Implimented LLSC')

    def __MBE(self,stmt):
        raise Exception('Not Implimented MBE')

    def __Dirty(self,stmt):
        raise Exception('Not Implimented Dirty')

    def __Exit(self,stmt):
        self.__parseData(stmt.guard)
        self.condWrite.append(stmt.offsIP)
        self.InstEnd = True
        self.BlockEnd = True
        # raise Exception('Not Implimented Exit')

    def __LoadG(self,stmt):
        raise Exception('Not Implimented LoadG')

    def __StoreG(self,stmt):
        raise Exception('Not Implimented StoreG')

    def __parseData(self,expr):
        # print(expr.tag)
        if expr.tag == 'Iex_Binder':
            self.__Binder(expr)
        if expr.tag == 'Iex_VECRET':
            self.__VECRET(expr)
        if expr.tag == 'Iex_GSPTR':
            self.__GSPTR(expr)
        if expr.tag == 'Iex_GetI':
            self.__GetI(expr)
        if expr.tag == 'Iex_RdTmp':
            self.__RdTmp(expr)
        if expr.tag == 'Iex_Get':
            self.__Get(expr)
        if expr.tag == 'Iex_Qop':
            self.__Qop(expr)
        if expr.tag == 'Iex_Triop':
            self.__Triop(expr)
        if expr.tag == 'Iex_Binop':
            self.__Binop(expr)
        if expr.tag == 'Iex_Unop':
            self.__Unop(expr)
        if expr.tag == 'Iex_Load':
            self.__Load(expr)
        if expr.tag == 'Iex_Const':
            self. __Const(expr)
        if expr.tag == 'Iex_ITE':
            self.__ITE(expr)
        if expr.tag == 'Iex_CCall':
            self.__CCall(expr)

    def __Binder(self,expr):
    	raise Exception('Not Implimented Binder')

    def __VECRET(self,expr):
        raise Exception('Not Implimented VECRET')

    def __GSPTR(self,expr):
        raise Exception('Not Implimented GSPTR')

    def __GetI(self,expr):
        raise Exception('Not Implimented GetI')

    def __RdTmp(self,expr):
        # expr.pp()
        self.usedTemps.append(expr.tmp)
        # raise Exception('Not Implimented RdTmp')

    def __Get(self,expr):
        self.usedguest.append(expr.offset)
        # raise Exception('Not Implimented Get')

    def __Qop(self,expr):
        for arg in expr.args:
            self.__parseData(arg)
        raise Exception('Not Implimented Qop')

    def __Triop(self,expr):
        for arg in expr.args:
            self.__parseData(arg)
        raise Exception('Not Implimented Triop')

    def __Binop(self,expr):
        for arg in expr.args:
            self.__parseData(arg)
        # raise Exception('Not Implimented Binop')

    def __Unop(self,expr):
        self.__parseData(expr.args[0])
        # raise Exception('Not Implimented Unop')

    def __Load(self,expr):
        self.memRead = True
        self.__parseData(expr.addr)
        # raise Exception('Not Implimented Load')

    def __Const(self,expr):
        pass
        # raise Exception('Not Implimented Const')

    def __ITE(self,expr):
        raise Exception('Not Implimented ITE')

    def __CCall(self,expr):
        for arg in expr.args:
            self.__parseData(arg)
        # raise Exception('Not Implimented CCall')