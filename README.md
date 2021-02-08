# Running PINT in the Tofino ASIC
This repository contains code to run PINT in the Tofino ASIC.

The repository only includes the data plane portion of PINT for Tofino, without showing how to process the generated telemetry digests at the controller

## Table of contents
* [Requirements](#requirements)
* [Link configuration](#link-configuration)
* [Development topology](#development-topology)
* [Starting Pitcher](#starting-pitcher)
* [Planned topology](#planned-topology)


## Requirements
1. An installed and pre-configured Tofino switch

## Running PINT
1. Set up a Tofino switch. This project was developed on a Stordis BF2556X-1T running SDE 8.9.2
2. Compile the [PINT code](p4src/pint.p4)
3. Start the PINT program on the Tofino
4. Configure the Tofino ports, which in our case are [these rules](port_config.txt)
5. Start the switch CPU component using [start_switch_cpu.sh](start_switch_cpu.sh)
6. Inject packets from the switch CPU using [pktgen.py](pktgen.py)

The injected packets will be processed by PINT, and the controller should print the raw generated output

## Link configuration
During development, our Tofino had links connected according to the following image:

![Tofino link configuration](tofino_current_links.png?raw=true "Tofino link configuration")

### Topology
This is the topology used during development of Pitcher:

![Tofino current topology](tofino_current_topology.png?raw=true "Tofino current topology")

Traffic is sent by [pktgen.py](pktgen.py) from h0(10.0.0.101) towards h1(10.0.0.102), with each switch running the [pint.p4](p4src/pint.p4) pipeline.

The last hop, i.e. the PINT sink, will send the telemetry data down to the switch CPU
