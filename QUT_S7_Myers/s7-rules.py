import struct

import settings


def to_float(var):
    if var is None:
        return var
    return struct.unpack(">f", var.to_bytes(4, "big"))[0]


def get_bit(var, bit):  # Bit address start by 0
    if var is None:
        return var
    return (var >> (bit)) & 0x1


"""
    "10.10.10.10:102:DB.3.128": 0,
    "10.10.10.10:102:DB.3.136": 1109393408,
    "10.10.10.10:102:DB.3.137": 0,
    "10.10.10.10:102:DB.3.32": 1060611828,
    "10.10.10.10:102:DB.4.0": 0,
    "10.10.10.10:102:DB.4.161": 0,
    "10.10.10.10:102:DB.4.162": 0,
    "10.10.10.10:102:DB.4.168": 0,
    "10.10.10.10:102:DB.4.169": 0,
    "10.10.10.10:102:DB.5.1": 0,
    "10.10.10.10:102:DB.5.2": 0,
    "10.10.10.10:102:DB.5.4": 0,
    "10.10.10.10:102:DB.5.5": 0,
    "10.10.10.10:102:DB.5.8": 0,

    "10.10.10.10:102:M.0": 0,

    "10.10.10.10:102:M.32": 0,

    "10.10.10.10:102:M.192": 0,

    "10.10.10.10:102:M.224": 0,

    "10.10.10.10:102:M.256": 0,

    "10.10.10.10:102:M.288": 0,

    "10.10.10.10:102:M.320": 0,

    "10.10.10.10:102:M.352": 0

    " M.800" #  Reactor On off?!
    "10.10.10.10:102:M.801": 40, # reactor on off?
    "10.10.10.10:102:M.802": 30, # reactor on off?

    "10.10.10.10:102:M.805": 0,

    "M.808" # water tank?!
    "10.10.10.10:102:M.809": 0,
    "10.10.10.10:102:M.810": 0,
    "10.10.10.10:102:M.811": 0,
    "10.10.10.10:102:M.813": 0,

    # Conveyor Belt?!
    "M.816" # Conveyor Belt on
    "10.10.10.10:102:M.817": 1, # conveyor belt off
    "10.10.10.10:102:M.818": 0, # Conve belt change dir
    "10.10.10.10:102:M.819": 0,
    "10.10.10.10:102:M.820": 0, # conv belt reset
    "10.10.10.10:102:M.821": 0,
    "10.10.10.10:102:M.822": 0,
    "10.10.10.10:102:M.823": 0,

    "10.10.10.10:102:M.825": 1, # Global reset?
    "10.10.10.10:102:M.826": 0,
    "10.10.10.10:102:M.827": 0, # Emergency Stop?

    "10.10.10.10:102:M.2000": 0,
    "10.10.10.10:102:M.2001": 0,

    "10.10.10.10:102:M.2400": 1084227584,
    "10.10.10.10:102:M.2432": 1109393408,
    "10.10.10.10:102:M.2464": 1106247680,
    "10.10.10.10:102:M.2496": 0,


    "10.10.10.10:102:null": []
      0,
      1121463301,
      3238092842,
      80,
      50,
      0,
      0,
      0,
      3238092842,
      1,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0

"""

JS = {
    "protocols": ["s7"],
    "rules": [
        # Conveyor Belt
        {  # 0x0330 816
            "var": ["M.816"],
            "method": lambda x: get_bit(x[0], 0),
            "name": "ConveyorBeltOn",
            "remove": False,
        },
        {  # 0x0331 817
            "var": ["M.816"],
            "method": lambda x: get_bit(x[0], 1),
            "name": "ConveyorBeltOff",
            "remove": False,
        },
        {  # 0x0332 818
            "var": ["M.816"],
            "method": lambda x: get_bit(x[0], 2),
            "name": "ConveyorBeltGateChangeDirection",
            "remove": False,
        },
        {  # 0x0334 820
            "var": ["M.816"],
            "method": lambda x: get_bit(x[0], 4),
            "name": "ConveyorBeltReset",
            "remove": False,
        },
        {
            "var": ["M.816"],
            "remove": True,
        },
        # Water Tank
        {  # 0x0328 808
            "var": ["M.808"],
            "method": lambda x: get_bit(x[0], 2),
            "name": "WaterTankOff",
            "remove": False,
        },
        {  # 0x0329 809
            "var": ["M.808"],
            "method": lambda x: get_bit(x[0], 1),
            "name": "WaterTankOn(Auto)",
            "remove": False,
        },
        {  # 0x032a 810
            "var": ["M.808"],
            "method": lambda x: get_bit(x[0], 0),
            "name": "WaterTankOn(Manual)",
            "remove": False,
        },
        {
            "var": ["M.808"],
            "remove": True,
        },
        # Pipeline Reactor
        {  # 0x0320
            "var": ["M.800"],
            "method": lambda x: get_bit(x[0], 2),
            "name": "ReactorOff",
            "remove": False,
        },
        {  # 0x0322
            "var": ["M.800"],
            "method": lambda x: get_bit(x[0], 0),
            "name": "ReactorOn",
            "remove": False,
        },
        {
            "var": ["M.800"],
            "remove": True,
        },
        {  # 0x0060
            "var": ["M.96"],
            "method": lambda x: to_float(x[0]),
            "name": "LowerTreshold",
            "remove": True,
        },
        {  # 0x0040
            "var": ["M.64"],
            "method": lambda x: to_float(x[0]),
            "name": "UpperTreshold",
            "remove": True,
        },
        {
            "var": ["M.64"],
            "remove": True,
        },
        # Master
        {  # 0x0339 825
            "var": ["M.824"],
            "method": lambda x: get_bit(x[0], 1),
            "name": "GlobalReset",
            "remove": False,
        },
        {  # 0x033b 827
            "var": ["M.824"],
            "method": lambda x: get_bit(x[0], 3),
            "name": "EmergencyStop",
            "remove": False,
        },
        {
            "var": ["M.824"],
            "remove": True,
        },
    ],
}
