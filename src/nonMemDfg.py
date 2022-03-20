import networkx as nx
from stmtInfo import stmtInfo

def dfsguest(n,cfg,dfg,g,vis,addr):
    if n in vis:
        return
    vis.append(n)
    try:
        stmts = n.block.vex.statements
    except:
        stmts = []
    addr1 = 0
    for stmt in stmts:
        if stmt.tag == 'Ist_IMark':
            addr1 = stmt.addr
        info = stmtInfo(stmt)
        if g in info.usedguest:
            dfg.add_edge(hex(addr),hex(addr1))
            ob = dfg.adj[hex(addr)][hex(addr1)]
            ob[len(ob)] = {"kind" : "dep","passby" : "guest", "num" : g}
        if g in info.guestAss:
            dfg.add_edge(hex(addr),hex(addr1))
            ob = dfg.adj[hex(addr)][hex(addr1)]
            ob[len(ob)] = {"kind" : "kill","passby" : "guest", "num" : g}
            return
    for nei in cfg.graph.successors(n):
        dfsguest(nei,cfg,dfg,g,vis,addr) 

def dfscontrolflow(n,cfg,dfg,vis,addr):
    if n in vis:
        return
    vis.append(n)
    try:
        stmts = n.block.vex.statements
    except:
        stmts = []
    addr1 = 0
    for stmt in stmts:
        if stmt.tag == 'Ist_IMark':
            addr1 = stmt.addr
            dfg.add_edge(hex(addr),hex(addr1))
            ob = dfg.adj[hex(addr)][hex(addr1)]
            ob[len(ob)] = {"kind" : "dep","passby" : "cond", "num" : 0}
    for nei in cfg.graph.successors(n):
        dfscontrolflow(nei,cfg,dfg,vis,addr) 

def dfsglb(n,cfg,dfg,add,vis,addr):
    if n in vis:
        return
    vis.append(n)
    try:
        stmts = n.block.vex.statements
    except:
        stmts = []
    addr1 = 0
    for stmt in stmts:
        if stmt.tag == 'Ist_IMark':
            addr1 = stmt.addr
        info = stmtInfo(stmt)
        if add in info.usedMem:
            dfg.add_edge(hex(addr),hex(addr1))
            ob = dfg.adj[hex(addr)][hex(addr1)]
            ob[len(ob)] = {"kind" : "dep","passby" : "mem", "num" : hex(add)}
        if add in info.memchng:
            dfg.add_edge(hex(addr),hex(addr1))
            ob = dfg.adj[hex(addr)][hex(addr1)]
            ob[len(ob)] = {"kind" : "kill","passby" : "mem", "num" : hex(add)}
            return
    for nei in cfg.graph.successors(n):
        dfsglb(nei,cfg,dfg,add,vis,addr) 

def add_edges(dfg,cfg,nodes,stmts,node_ind,stmt_ind,f):
    addr = stmts[stmt_ind].addr
    dfg.add_node(hex(addr))
    addr1 = 0
    stmt_ind+=1
    guest = []
    temp = []
    memRight = False
    memRead = False
    memChng = []
    memreadlist = []
    inst_comp = False
    for ind in range(stmt_ind,len(stmts)):
        if not(inst_comp) :
            info = stmtInfo(stmts[ind])
            guest.extend(info.guestAss)
            temp.extend(info.tempAss)
            memRight |= info.memAss
            memChng.extend(info.memchng)
            if(info.exit == True):
                for n in cfg.graph.successors(nodes[node_ind]):
                    dfscontrolflow(n,cfg,dfg,[],addr)       
            if stmts[ind].tag == 'Ist_IMark':
                inst_comp = True
                addr1 = info.addr
        else:
            info = stmtInfo(stmts[ind])
            if stmts[ind].tag == 'Ist_IMark':
                addr1 = info.addr
            for g in guest:
                if g in info.usedguest:
                    dfg.add_edge(hex(addr),hex(addr1))
                    ob = dfg.adj[hex(addr)][hex(addr1)]
                    ob[len(ob)] = {"kind" : "dep","passby": "guest", "num" : g}
                if g in info.guestAss:
                    guest.remove(g)
                    dfg.add_edge(hex(addr),hex(addr1))
                    ob = dfg.adj[hex(addr)][hex(addr1)]
                    ob[len(ob)] = {"kind" : "kill","passby" : "guest", "num" : g}
            for t in temp:
                if t in info.usedTemps:
                    dfg.add_edge(hex(addr),hex(addr1))
                    ob = dfg.adj[hex(addr)][hex(addr1)]
                    ob[len(ob)] = {"kind" : "dep","passby" : "temp", "num" : t}
                if t in info.tempAss:
                    temp.remove(t)
                    dfg.add_edge(hex(addr),hex(addr1))
                    ob = dfg.adj[hex(addr)][hex(addr1)]
                    ob[len(ob)] = {"kind" : "kill","passby" : "temp", "num" : t}
            for add in memChng:
                if add in info.usedMem:
                    dfg.add_edge(hex(addr),hex(addr1))
                    ob = dfg.adj[hex(addr)][hex(addr1)]
                    ob[len(ob)] = {"kind" : "dep","passby" : "mem", "num" : hex(add)}
                if add in info.memchng:
                    memChng.remove(add)
                    dfg.add_edge(hex(addr),hex(addr1))
                    ob = dfg.adj[hex(addr)][hex(addr1)]
                    ob[len(ob)] = {"kind" : "kill","passby" : "mem", "num" : hex(add)}
                    
            if info.memRead and memRight and f:
                dfg.add_edge(hex(addr),hex(addr1))
                ob = dfg.adj[hex(addr)][hex(addr1)]
                ob[len(ob)] = {"kind" : "dep","passby" : "memweak", "num" : 0}
                
            if info.memAss and memRight and f:
                dfg.add_edge(hex(addr),hex(addr1))
                ob = dfg.adj[hex(addr)][hex(addr1)]
                memRight = False
                ob[len(ob)] = {"kind" : "kill","passby" : "memweak", "num" : 0}
            
#     print(addr,memChng)
    for g in guest:
        vis = []
        for n in cfg.graph.successors(nodes[node_ind]):
            dfsguest(n,cfg,dfg,g,vis,addr)
            
    for add in memChng:
        vis = []
        for n in cfg.graph.successors(nodes[node_ind]):
            dfsglb(n,cfg,dfg,add,vis,addr)
            
    if f and memRight:
        vis = []
        for n in cfg.graph.successors(nodes[node_ind]):
            dfs3(n,cfg,dfg,vis,addr)   

def get_dfg(cfg,f):
    nodes = list(cfg.graph.nodes)
    dfg = nx.DiGraph()
    for node_ind in range(0,len(nodes)):
        try:
            stmts = list(nodes[node_ind].block.vex.statements)
        except:
            continue
        for stmt_ind in range(0,len(stmts)):
            if stmts[stmt_ind].tag == 'Ist_IMark':
                add_edges(dfg,cfg,nodes,stmts,node_ind,stmt_ind,f)
    return dfg

def getPath(dfg,add1,add2,vis):
    if add1 in vis:
        return(None)
    vis.append(add1)
    if add1 == add2:
        return(add1)
    for e in dfg.adj[add1]:
        for ind in dfg.adj[add1][e]:
            if dfg.adj[add1][e][ind]['kind'] == 'dep':
                s1 = dfg.adj[add1][e][ind]['passby']
                s2 = str(dfg.adj[add1][e][ind]['num'])
                s = getPath(dfg,e,add2,vis)
                if s!= None:
                    return(add1+'\n'+s1+s2+" "+s)
    return None

def printedges(dfg,addr):
    x = dfg.adj[addr];
    for a in x:
        for o in x[a]:
            print(a,x[a][o]['kind'],x[a][o]['passby'],x[a][o]['num'])