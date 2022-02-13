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
            dfg.add_edge(hex(addr),hex(addr1),object = {"kind" : "dep","passby" : "guest", "num" : g})
        if g in info.guestAss:
            dfg.add_edge(hex(addr),hex(addr1),object = {"kind" : "kill","passby" : "guest", "num" : g})
            return
    for nei in cfg.graph.successors(n):
        dfs(nei,cfg,dfg,g,vis,addr) 


def add_edges(dfg,cfg,nodes,stmts,node_ind,stmt_ind):
    addr = stmts[stmt_ind].addr
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
            if stmts[ind].tag == 'Ist_IMark':
                inst_comp = True
                addr1 = info.addr
        else:
            info = stmtInfo(stmts[ind])
            for g in guest:
                if g in info.usedguest:
                    dfg.add_edge(hex(addr),hex(addr1),object = {"kind" : "dep","passby": "guest", "num" : g})
                if g in info.guestAss:
                    guest.remove(g)
                    dfg.add_edge(hex(addr),hex(addr1),object = {"kind" : "kill","passby" : "guest", "num" : g})
            for t in temp:
                if t in info.usedTemps:
                    dfg.add_edge(hex(addr),hex(addr1),object = {"kind" : "dep","passby" : "temp", "num" : t})
                if t in info.tempAss:
                    temp.remove(t)
                    dfg.add_edge(hex(addr),hex(addr1),object = {"kind" : "kill","passby" : "temp", "num" : t})
                    
    for g in guest:
        vis = []
        for n in cfg.graph.successors(nodes[node_ind]):
            dfs(n,cfg,dfg,g,vis,addr)   

def getDfg(cfg):
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
    return(dfg)