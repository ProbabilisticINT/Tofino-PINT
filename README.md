# Running PINT on the Tofino ASIC
This repository contains code to run PINT in the Tofino ASIC.

The repository only includes the data plane part of PINT for Tofino, and does not explain how to process the generated telemetry data at the controller.

## Table of contents
* [Requirements](#requirements)
* [Running PINT](#running-pint)
* [Link configuration](#link-configuration)
* [Topology](#topology)


## Requirements
This project requires an installed and set up Tofino switch.

During development, a Stordis BF2556X-1T was used with SDE version 8.9.2.

A single switch is used to emulate multiple switching running PINT.\
This is achieved through external loopback, requiring cabling according to the [link configuration section](#link-configuration)

## Running PINT
1. Compile the [PINT code](p4src/pint.p4)
2. Start the PINT program on the Tofino
3. Configure the Tofino ports, which in our case are [these rules](port_config.txt)
4. Start the switch CPU component using [start_switch_cpu.sh](start_switch_cpu.sh)
5. Inject packets from the switch CPU using [pktgen.py](pktgen.py)

The injected packets will be processed by PINT, and the controller should print the raw generated output

## Link configuration
During development, our Tofino had links connected according to the following image:

![Tofino link configuration](tofino_current_links.png?raw=true "Tofino link configuration")

## Topology
This is the topology used during development of PINT on the Tofino:

![Tofino current topology](tofino_current_topology.png?raw=true "Tofino current topology")

Traffic is sent by [pktgen.py](pktgen.py) from h0(10.0.0.101) towards h1(10.0.0.102), with each switch running the [pint.p4](p4src/pint.p4) pipeline.

The last hop, i.e. the PINT sink, will send the telemetry data down to the switch CPU
