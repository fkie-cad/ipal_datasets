JS = {
    "protocols": ["modbus"],
    "rename": {
        "84.3.251.18:502:[0-9]+": "PLC1",
        "84.3.251.101:502:[0-2]": "PLC2",
        "84.3.251.102:502:[0-5]": "PLC3",
        "84.3.251.103:502:[0-5]": "PLC4",
    },
    "rules": [
        # Tank 1-8
        {
            "src": "84.3.251.18:502:[0-9]+",
            "type": "3",
            "var": ["holding.register.1"],
            "method": lambda x: x[0],
            "name": "Tank_1",
            "remove": True,
        },
        {
            "dest": "84.3.251.18:502:[0-9]+",
            "type": "3",
            "var": ["holding.register.1"],
            "method": lambda x: x[0],
            "name": "Tank_1",
            "remove": True,
        },
        {
            "src": "84.3.251.18:502:[0-9]+",
            "type": "3",
            "var": ["holding.register.2"],
            "method": lambda x: x[0],
            "name": "Tank_2",
            "remove": True,
        },
        {
            "dest": "84.3.251.18:502:[0-9]+",
            "type": "3",
            "var": ["holding.register.2"],
            "method": lambda x: x[0],
            "name": "Tank_2",
            "remove": True,
        },
        {
            "src": "84.3.251.18:502:[0-9]+",
            "type": "3",
            "var": ["holding.register.3"],
            "method": lambda x: x[0],
            "name": "Tank_3",
            "remove": True,
        },
        {
            "dest": "84.3.251.18:502:[0-9]+",
            "type": "3",
            "var": ["holding.register.3"],
            "method": lambda x: x[0],
            "name": "Tank_3",
            "remove": True,
        },
        {
            "src": "84.3.251.18:502:[0-9]+",
            "type": "3",
            "var": ["holding.register.4"],
            "method": lambda x: x[0],
            "name": "Tank_4",
            "remove": True,
        },
        {
            "dest": "84.3.251.18:502:[0-9]+",
            "type": "3",
            "var": ["holding.register.4"],
            "method": lambda x: x[0],
            "name": "Tank_4",
            "remove": True,
        },
        {
            "src": "84.3.251.18:502:[0-9]+",
            "type": "3",
            "var": ["holding.register.5"],
            "method": lambda x: x[0],
            "name": "Tank_5",
            "remove": True,
        },
        {
            "dest": "84.3.251.18:502:[0-9]+",
            "type": "3",
            "var": ["holding.register.5"],
            "method": lambda x: x[0],
            "name": "Tank_5",
            "remove": True,
        },
        {
            "src": "84.3.251.101:502:[0-2]",
            "type": "3",
            "var": ["holding.register.1"],
            "method": lambda x: x[0],
            "name": "Tank_6",
            "remove": True,
        },
        {
            "dest": "84.3.251.101:502:[0-2]",
            "type": "3",
            "var": ["holding.register.1"],
            "method": lambda x: x[0],
            "name": "Tank_6",
            "remove": True,
        },
        {
            "src": "84.3.251.102:502:[0-5]",
            "type": "3",
            "var": ["holding.register.1"],
            "method": lambda x: x[0],
            "name": "Tank_7",
            "remove": True,
        },
        {
            "dest": "84.3.251.102:502:[0-5]",
            "type": "3",
            "var": ["holding.register.1"],
            "method": lambda x: x[0],
            "name": "Tank_7",
            "remove": True,
        },
        {
            "src": "84.3.251.103:502:[0-5]",
            "type": "3",
            "var": ["holding.register.1"],
            "method": lambda x: x[0],
            "name": "Tank_8",
            "remove": True,
        },
        {
            "dest": "84.3.251.103:502:[0-5]",
            "type": "3",
            "var": ["holding.register.1"],
            "method": lambda x: x[0],
            "name": "Tank_8",
            "remove": True,
        },
        # Pump 1-6
        {
            "src": "84.3.251.18:502:[0-9]+",
            "type": "1",
            "var": ["coil.20"],
            "method": lambda x: x[0] == 1,
            "name": "Pump_1",
            "remove": True,
        },
        {
            "dest": "84.3.251.18:502:[0-9]+",
            "type": "1",
            "var": ["coil.20"],
            "method": lambda x: x[0] == 1,
            "name": "Pump_1",
            "remove": True,
        },
        {
            "src": "84.3.251.18:502:[0-9]+",
            "type": "1",
            "var": ["coil.21"],
            "method": lambda x: x[0] == 1,
            "name": "Pump_2",
            "remove": True,
        },
        {
            "dest": "84.3.251.18:502:[0-9]+",
            "type": "1",
            "var": ["coil.21"],
            "method": lambda x: x[0] == 1,
            "name": "Pump_2",
            "remove": True,
        },
        {
            "src": "84.3.251.18:502:[0-9]+",
            "type": "1",
            "var": ["coil.22"],
            "method": lambda x: x[0] == 1,
            "name": "Pump_3",
            "remove": True,
        },
        {
            "dest": "84.3.251.18:502:[0-9]+",
            "type": "1",
            "var": ["coil.22"],
            "method": lambda x: x[0] == 1,
            "name": "Pump_3",
            "remove": True,
        },
        {
            "src": "84.3.251.18:502:[0-9]+",
            "type": "1",
            "var": ["coil.23"],
            "method": lambda x: x[0] == 1,
            "name": "Pump_4",
            "remove": True,
        },
        {
            "dest": "84.3.251.18:502:[0-9]+",
            "type": "1",
            "var": ["coil.23"],
            "method": lambda x: x[0] == 1,
            "name": "Pump_4",
            "remove": True,
        },
        {
            "src": "84.3.251.102:502:[0-5]",
            "type": "1",
            "var": ["coil.1"],
            "method": lambda x: x[0] == 1,
            "name": "Pump_5",
            "remove": True,
        },
        {
            "dest": "84.3.251.102:502:[0-5]",
            "type": "1",
            "var": ["coil.1"],
            "method": lambda x: x[0] == 1,
            "name": "Pump_5",
            "remove": True,
        },
        {
            "src": "84.3.251.103:502:[0-5]",
            "type": "1",
            "var": ["coil.1"],
            "method": lambda x: x[0] == 1,
            "name": "Pump_6",
            "remove": True,
        },
        {
            "dest": "84.3.251.103:502:[0-5]",
            "type": "1",
            "var": ["coil.1"],
            "method": lambda x: x[0] == 1,
            "name": "Pump_6",
            "remove": True,
        },
        # Flow sensor 1,2,4
        {
            "src": "84.3.251.102:502:[0-5]",
            "type": "3",
            "var": ["holding.register.2"],
            "method": lambda x: x[0],
            "name": "Flow_sensor_1",
            "remove": True,
        },
        {
            "dest": "84.3.251.102:502:[0-5]",
            "type": "3",
            "var": ["holding.register.2"],
            "method": lambda x: x[0],
            "name": "Flow_sensor_1",
            "remove": True,
        },
        {
            "src": "84.3.251.103:502:[0-5]",
            "type": "3",
            "var": ["holding.register.2"],
            "method": lambda x: x[0],
            "name": "Flow_sensor_2",
            "remove": True,
        },
        {
            "dest": "84.3.251.103:502:[0-5]",
            "type": "3",
            "var": ["holding.register.2"],
            "method": lambda x: x[0],
            "name": "Flow_sensor_2",
            "remove": True,
        },
        {
            "src": "84.3.251.103:502:[0-5]",
            "type": "3",
            "var": ["holding.register.3"],
            "method": lambda x: x[0],
            "name": "Flow_sensor_4",
            "remove": True,
        },
        {
            "dest": "84.3.251.103:502:[0-5]",
            "type": "3",
            "var": ["holding.register.3"],
            "method": lambda x: x[0],
            "name": "Flow_sensor_4",
            "remove": True,
        },
        # Valve 10-15,17,18,20,22
        {
            "src": "84.3.251.18:502:[0-9]+",
            "type": "1",
            "var": ["coil.39"],
            "method": lambda x: x[0] == 1,
            "name": "Valv_10",
            "remove": True,
        },
        {
            "dest": "84.3.251.18:502:[0-9]+",
            "type": "1",
            "var": ["coil.39"],
            "method": lambda x: x[0] == 1,
            "name": "Valv_10",
            "remove": True,
        },
        {
            "src": "84.3.251.18:502:[0-9]+",
            "type": "1",
            "var": ["coil.40"],
            "method": lambda x: x[0] == 1,
            "name": "Valv_11",
            "remove": True,
        },
        {
            "dest": "84.3.251.18:502:[0-9]+",
            "type": "1",
            "var": ["coil.40"],
            "method": lambda x: x[0] == 1,
            "name": "Valv_11",
            "remove": True,
        },
        {
            "src": "84.3.251.18:502:[0-9]+",
            "type": "1",
            "var": ["coil.41"],
            "method": lambda x: x[0] == 1,
            "name": "Valv_12",
            "remove": True,
        },
        {
            "dest": "84.3.251.18:502:[0-9]+",
            "type": "1",
            "var": ["coil.41"],
            "method": lambda x: x[0] == 1,
            "name": "Valv_12",
            "remove": True,
        },
        {
            "src": "84.3.251.18:502:[0-9]+",
            "type": "1",
            "var": ["coil.42"],
            "method": lambda x: x[0] == 1,
            "name": "Valv_13",
            "remove": True,
        },
        {
            "dest": "84.3.251.18:502:[0-9]+",
            "type": "1",
            "var": ["coil.42"],
            "method": lambda x: x[0] == 1,
            "name": "Valv_13",
            "remove": True,
        },
        {
            "src": "84.3.251.18:502:[0-9]+",
            "type": "1",
            "var": ["coil.43"],
            "method": lambda x: x[0] == 1,
            "name": "Valv_14",
            "remove": True,
        },
        {
            "dest": "84.3.251.18:502:[0-9]+",
            "type": "1",
            "var": ["coil.43"],
            "method": lambda x: x[0] == 1,
            "name": "Valv_14",
            "remove": True,
        },
        {
            "src": "84.3.251.18:502:[0-9]+",
            "type": "1",
            "var": ["coil.44"],
            "method": lambda x: x[0] == 1,
            "name": "Valv_15",
            "remove": True,
        },
        {
            "dest": "84.3.251.18:502:[0-9]+",
            "type": "1",
            "var": ["coil.44"],
            "method": lambda x: x[0] == 1,
            "name": "Valv_15",
            "remove": True,
        },
        {
            "src": "84.3.251.18:502:[0-9]+",
            "type": "1",
            "var": ["coil.46"],
            "method": lambda x: x[0] == 1,
            "name": "Valv_17",
            "remove": True,
        },
        {
            "dest": "84.3.251.18:502:[0-9]+",
            "type": "1",
            "var": ["coil.46"],
            "method": lambda x: x[0] == 1,
            "name": "Valv_17",
            "remove": True,
        },
        {
            "src": "84.3.251.18:502:[0-9]+",
            "type": "1",
            "var": ["coil.47"],
            "method": lambda x: x[0] == 1,
            "name": "Valv_18",
            "remove": True,
        },
        {
            "dest": "84.3.251.18:502:[0-9]+",
            "type": "1",
            "var": ["coil.47"],
            "method": lambda x: x[0] == 1,
            "name": "Valv_18",
            "remove": True,
        },
        {
            "src": "84.3.251.18:502:[0-9]+",
            "type": "1",
            "var": ["coil.49"],
            "method": lambda x: x[0] == 1,
            "name": "Valv_20",
            "remove": True,
        },
        {
            "dest": "84.3.251.18:502:[0-9]+",
            "type": "1",
            "var": ["coil.49"],
            "method": lambda x: x[0] == 1,
            "name": "Valv_20",
            "remove": True,
        },
        {
            "src": "84.3.251.103:502:[0-5]",
            "type": "1",
            "var": ["coil.2"],
            "method": lambda x: x[0] == 1,
            "name": "Valv_22",
            "remove": True,
        },
        {
            "dest": "84.3.251.103:502:[0-5]",
            "type": "1",
            "var": ["coil.2"],
            "method": lambda x: x[0] == 1,
            "name": "Valv_22",
            "remove": True,
        },
        # Remove empty registers
        {
            "src": "84.3.251.18:502:[0-9]+",
            "var": [
                "holding.register.5",
                "coil.0",
                "coil.1",
                "coil.2",
                "coil.3",
                "coil.4",
                "coil.5",
                "coil.6",
                "coil.7",
                "coil.30",
                "coil.31",
                "coil.32",
                "coil.33",
                "coil.34",
                "coil.35",
                "coil.36",
                "coil.37",
                "coil.38",
                "coil.45",
                "coil.48",
                "coil.49",
            ],
            "remove": True,
        },
        {"dest": "84.3.251.18:502:[0-9]+", "var": ["coil.50"], "remove": True},
        {
            "src": "84.3.251.101:502:[0-2]",
            "var": ["holding.register.1", "coil.1"],
            "remove": True,
        },
        {
            "src": "84.3.251.102:502:[0-5]",
            "var": ["holding.register.1", "holding.register.3", "coil.2"],
            "remove": True,
        },
        {
            "dest": "84.3.251.102:502:[0-5]",
            "var": ["holding.register.3"],
            "remove": True,
        },
        {
            "src": "84.3.251.103:502:[0-5]",
            "var": ["holding.register.3"],
            "remove": True,
        },
        {
            "dest": "84.3.251.103:502:[0-5]",
            "var": ["holding.register.3"],
            "remove": True,
        },
    ],
}
