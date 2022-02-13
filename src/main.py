import angr
import pyvex
import archinfo
from angrutils import *
import networkx as nx
from nonMemDfg import getDfg

p = angr.Project("../test/exe/sort.o",auto_load_libs=False)
start_state = p.factory.entry_state()
cfg = p.analyses.CFGEmulated(fail_fast=True, starts=[p.entry], initial_state=start_state)
plot_cfg(cfg, "../test/cfg/sort", vexinst=True, remove_imports=True, remove_path_terminator=True)  

dfg = getDfg(cfg)

print(dfg.nodes)