import angr
import pyvex
import archinfo
from angrutils import *
import networkx as nx
from nonMemDfg import get_dfg, getPath, printedges

# basic
p = angr.Project("../test/basicasm/basic.exe",auto_load_libs=False)
start_state = p.factory.entry_state()
cfg = p.analyses.CFGEmulated(fail_fast=True, starts=[p.entry], initial_state=start_state)
plot_cfg(cfg, "../test/basicasm/basicvex", vexinst=True, remove_imports=True, remove_path_terminator=True)
plot_cfg(cfg, "../test/basicasm/basicasm", asminst=True, remove_imports=True, remove_path_terminator=True)
dfg = get_dfg(cfg)

print(getPath(dfg,'0x40100a','0x40101f',[]))

print(getPath(dfg,'0x40100a','0x401012',[]))

printedges(dfg,'0x40100a')

# if-else
p = angr.Project("../test/ifelseasm/ifelse.exe",auto_load_libs=False)
start_state = p.factory.entry_state()
cfg = p.analyses.CFGEmulated(fail_fast=True, starts=[p.entry], initial_state=start_state)
plot_cfg(cfg, "../test/ifelseasm/ifelsevex", vexinst=True, remove_imports=True, remove_path_terminator=True)
plot_cfg(cfg, "../test/ifelseasm/ifelseasm", asminst=True, remove_imports=True, remove_path_terminator=True)
dfg = get_dfg(cfg)

print(getPath(dfg,'0x401000','0x401042',[]))  # a->out

print(getPath(dfg,'0x401010','0x401042',[]))  # c->out

print(getPath(dfg,'0x401018','0x401042',[]))  # d->out

print(getPath(dfg,'0x401020','0x401042',[]))  # mess-> out

print(getPath(dfg,'0x40102f','0x401034',[]))  # if -> else

printedges(dfg,'0x401038')

# loop
p = angr.Project("../test/loopasm/loop.exe",auto_load_libs=False)
start_state = p.factory.entry_state()
cfg = p.analyses.CFGEmulated(fail_fast=True, starts=[p.entry], initial_state=start_state)
plot_cfg(cfg, "../test/loopasm/loopvex", vexinst=True, remove_imports=True, remove_path_terminator=True)
plot_cfg(cfg, "../test/loopasm/loopasm", asminst=True, remove_imports=True, remove_path_terminator=True)
dfg = get_dfg(cfg)

print(getPath(dfg,'0x401010','0x401036',[])) # msg -> output

print(getPath(dfg,'0x401023','0x401020',[])) # below to above
