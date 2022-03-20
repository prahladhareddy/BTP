import angr
import pyvex
import archinfo
from angrutils import *
import networkx as nx
from nonMemDfg import get_dfg, getPath, printedges

# basic
p = angr.Project("../test/onlyglobal/onlyglobal.exe",auto_load_libs=False)
start_state = p.factory.entry_state()
cfg = p.analyses.CFGEmulated(fail_fast=True, starts=[p.entry], initial_state=start_state)
plot_cfg(cfg, "../test/onlyglobal/onlyglobalvex", vexinst=True, remove_imports=True, remove_path_terminator=True)
plot_cfg(cfg, "../test/onlyglobal/onlyglobalasm", asminst=True, remove_imports=True, remove_path_terminator=True)
dfg = get_dfg(cfg,False)

print(getPath(dfg,'0x401008','0x40104f',[]))