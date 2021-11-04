import struct
import math


def to_float(vars):
    if vars[0] is None and vars[1] is None:
        return None
    data = vars[0].to_bytes(2, "big") + vars[1].to_bytes(2, "big")
    return struct.unpack(">f", data)[0]


def to_int(vars):
    if vars[0] is None and vars[1] is None:
        return None
    data = vars[0].to_bytes(2, "big") + vars[1].to_bytes(2, "big")
    return struct.unpack("<i", data)[0]


JS = {
    "protocols": ["modbus"],
    "rules": [
        {  # Scaled Gas Pressure
            "type": "3",
            "var": ["holding.register.3006", "holding.register.3007"],
            "method": to_float,
            "name": "Scaled Gas Pressure",
            "remove": True,
        },
        {  # control schema
            "type": "16",
            "var": ["holding.register.3049"],
            "method": lambda x: x[0],
            "name": "control schema",
            "remove": True,
        },
        {  # system mode
            "type": "16",
            "var": ["holding.register.3050"],
            "method": lambda x: x[0],
            "name": "system mode",
            "remove": True,
        },
        {  # pump
            "type": "16",
            "var": ["holding.register.3051"],
            "method": lambda x: x[0],
            "name": "pump",
            "remove": True,
        },
        {  # solenoid
            "type": "16",
            "var": ["holding.register.3052"],
            "method": lambda x: x[0],
            "name": "solenoid",
            "remove": True,
        },
        {  # PID Setpoint
            "type": "16",
            "var": ["holding.register.3055", "holding.register.3056"],
            "method": to_float,
            "name": "PID Setpoint",
            "remove": True,
        },
        {  # PID Gain
            "type": "16",
            "var": ["holding.register.3057", "holding.register.3058"],
            "method": to_int,
            "name": "PID Gain",
            "remove": True,
        },
        {  # PID Reset
            "type": "16",
            "var": ["holding.register.3059", "holding.register.3060"],
            "method": to_float,
            "name": "PID Reset",
            "remove": True,
        },
        {  # PID Rate
            "type": "16",
            "var": ["holding.register.3061", "holding.register.3062"],
            "method": to_float,
            "name": "PID Rate",
            "remove": True,
        },
        {  # PID Deadband
            "type": "16",
            "var": ["holding.register.3063", "holding.register.3064"],
            "method": to_float,
            "name": "PID Deadband",
            "remove": True,
        },
        {  # PID Cycle Time
            "type": "16",
            "var": ["holding.register.3065", "holding.register.3066"],
            "method": to_float,
            "name": "PID Cycle Time",
            "remove": True,
        },
        {  # Remove
            "type": "3",
            "var": [
                "holding.register.2999",
                "holding.register.3000",
                "holding.register.3001",
                "holding.register.3002",
                "holding.register.3003",
                "holding.register.3004",
                "holding.register.3005",
            ],
            "remove": True,
        },
        {  # Remove
            "type": "16",
            "var": ["holding.register.3054", "holding.register.3053"],
            "remove": True,
        },
        {  # Remove
            "type": "2",
            "var": [
                "discrete.input.2998",
                "discrete.input.2999",
                "discrete.input.3000",
                "discrete.input.3001",
                "discrete.input.3002",
                "discrete.input.3003",
                "discrete.input.3004",
                "discrete.input.3005",
                "discrete.input.3006",
                "discrete.input.3007",
            ],
            "remove": True,
        },
        {  # Remove
            "type": "1",
            "var": [
                "coil.2998",
                "coil.2999",
                "coil.3000",
                "coil.3001",
                "coil.3002",
                "coil.3003",
                "coil.3004",
                "coil.3005",
                "coil.3006",
                "coil.3007",
            ],
            "remove": True,
        },
        {  # Remove
            "type": "8",
            "var": [
                "clear counters and diagnostic register",
                "force listen only",
                "restart communication",
            ],
            "remove": True,
        },
    ],
}
