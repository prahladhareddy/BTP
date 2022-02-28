import networkx as nx
from stmtInfo import stmtInfo

def dfs(n,cfg,dfg,g,vis,addr):
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
        dfs(nei,cfg,dfg,g,vis,addr) 

def dfs2(n,cfg,dfg,vis,addr):
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
        dfs2(nei,cfg,dfg,vis,addr) 


def add_edges(dfg,cfg,nodes,stmts,node_ind,stmt_ind):
    addr = stmts[stmt_ind].addr
    dfg.add_node(hex(addr))
    addr1 = 0
    stmt_ind+=1
    guest = []
    temp = []
    inst_comp = False
    for ind in range(stmt_ind,len(stmts)):
        if not(inst_comp) :
            info = stmtInfo(stmts[ind])
            guest.extend(info.guestAss)
            temp.extend(info.tempAss)
            if(info.exit == True):
                for n in cfg.graph.successors(nodes[node_ind]):
                    dfs2(n,cfg,dfg,[],addr)       
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
                    
    for g in guest:
        vis = []
        for n in cfg.graph.successors(nodes[node_ind]):
            dfs(n,cfg,dfg,g,vis,addr)   

def get_dfg(cfg):
    nodes = list(cfg.graph.nodes)
    dfg = nx.DiGraph()
    for node_ind in range(0,len(nodes)):
        try:
            stmts = list(nodes[node_ind].block.vex.statements)
        except:
            continue
        for stmt_ind in range(0,len(stmts)):
            if stmts[stmt_ind].tag == 'Ist_IMark':
                add_edges(dfg,cfg,nodes,stmts,node_ind,stmt_ind)
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