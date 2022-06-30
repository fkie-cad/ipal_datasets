# IPAL - Datasets

This repository is part of IPAL - an Industrial Protocol Abstraction Layer. IPAL aims to establish an abstract representation of industrial network traffic for subsequent unified and protocol-independent industrial intrusion detection. IPAL consists of a [transcriber](https://github.com/fkie-cad/ipal_transcriber) to automatically translate industrial traffic into the IPAL representation, an [IDS Framework](https://github.com/fkie-cad/ipal_ids_framework) implementing various industrial intrusion detection systems (IIDSs), and a collection of evaluation [datasets](https://github.com/fkie-cad/ipal_datasets). For details about IPAL, please refer to our publications listed down below.

This repository contains a collection of datasets for evaluating industrial IDS. Therefore, this repository contains scripts to convert (transcribe) existing datasets into IPAL format. It does <u>not</u> contain the raw datasets nor the datasets transcribed into IPAL. We merely use placeholders which can be replaced after obtaining the original datasets at the respective publishers (see link in the table below).

| Dataset                 | Type                | Notes                                                        | Link                                                         |
| ----------------------- | ------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| ELEGANT                 | Packet (Modbus)     | The ELEGANT dataset consists of a MiTM and a DoS part. Until now we consider only the MiTM dataset and not the DoS dataset. | [IEEE Dataport](https://ieee-dataport.org/open-access/denial-service-and-man-middle-attacks-programmable-logic-controllers) |
| Electra                 | Packet (Modbus, S7) | Not all IPAL features are present, e.g., crc or length are missing. Also the request data/address fields are not always correct. We skip few duplicated packets. | [Webseite](http://perception.inf.um.es/electra/)             |
| Energy Dataset          | Packet (IEC-104) | A short PCAP of the WATTSON simulator from Fraunhofer FKIE. We use the manipulateTraces tool from the DTMC IDS paper to add attacks to the WATTSON PCAP. | [Paper](https://dl.acm.org/doi/pdf/10.1145/3372297.3420016), [manipulateTraces](https://github.com/jjchromik/manipulateTraces) [DTMC Paper](https://doi.org/10.1007/978-3-319-74947-1_4) |
| GeekLounge              | Packet (S7)         | The dataset does not contain any attacks. We added attacks according to the description of a paper. This results in 6 datasets with 3 attacks types each on requests and responses of S7 packets. | [Website ](https://www.netresec.com/?page=PCAP4SICS), [Paper](https://doi.org/10.1007/978-3-319-99843-5_5) |
| HAI                     | State               | Dataset contains three training and five test files. Train and test are not in linear time order and have overlapping time-regions. | [Github](https://github.com/icsdataset/hai/tree/master/hai-21.03) |
| IEC61850SecurityDataset | Packet (Goose)      |                                                              | [Github](https://github.com/smartgridadsc/IEC61850SecurityDataset) |
| Lemay                   | Packet (Modbus)     | Most attacks are not performed with Modbus and use different protocols not relevant for the transcriber. | [Paper](https://www.usenix.org/conference/cset16/workshop-program/presentation/lemay) [Github](https://github.com/antoine-lemay/Modbus_dataset) |
| MorrisDS4               | Packet (Modbus)     | There are minor differences between the Raw and Arff dataset. These differences affect only the attack packets. Default: Use the Arff dataset. | [Website](https://sites.google.com/a/uah.edu/tommy-morris-uah/ics-data-sets) |
| QUT\_DNP3              | Packet (DNP3, GOOSE)         |  | [Git](https://github.com/qut-infosec/2017QUT_DNP3) [Thesis](https://eprints.qut.edu.au/121760/1/Nicholas_Rodofile_Thesis.pdf) |
| QUT\_S7\_Myers            | Packet (S7).        |  TODO: Check Rules | [Dataset](https://cloudstor.aarnet.edu.au/plus/index.php/s/9qFfeVmfX7K5IDH) [Paper](https://research-repository.griffith.edu.au/bitstream/handle/10072/385711/FOO229943.pdf?sequence=1) |
| QUT\_S7comm            | Packet (S7)        |  | [Dataset](https://github.com/qut-infosec/2017QUT_S7comm) [Paper](https://link.springer.com/chapter/10.1007/978-3-319-59870-3_30) |
| SWaT                    | State               | Attack dataset has a 81s gap which we fill with the previous state. The first 1800s are often skipped in literature. The version 0 of SWaT has a slightly different start of the training data. | [iTrust](https://itrust.sutd.edu.sg/itrust-labs-home/itrust-labs_swat/) |
| TEP-PASAD               | State               | The dataset consists of 5 different scenarios. Each scenario has its own training and test part combined in one single file. | [Github](https://github.com/mikeliturbe/pasad/tree/master/data) |
| WADI                    | State               | WADI has a large gap in the training data of ~73h. Note: we use the row number as index for the timestamp since WADI has a challenging time notation. | [iTrust](https://itrust.sutd.edu.sg/itrust-labs-home/itrust-labs_wadi/) |
| WDT | Packet & State (Modbus) |  | [Paper](https://doi.org/10.1109/ACCESS.2021.3109465) |

###### Publications

- Konrad Wolsing, Eric Wagner, Antoine Saillard, and Martin Henze. 2022. IPAL: Breaking up Silos of Protocol-dependent and Domain-specific In- dustrial Intrusion Detection Systems. In 25th International Symposium on Research in Attacks, Intrusions and Defenses (RAID 2022), October 26–28, 2022, Limassol, Cyprus. ACM, New York, NY, USA, 17 pages. [https://doi.org/10.1145/3545948.3545968 ](https://doi.org/10.1145/3545948.3545968)
- Wolsing, Konrad, Eric Wagner, and Martin Henze. "Poster: Facilitating Protocol-independent Industrial Intrusion Detection Systems." *Proceedings of the 2020 ACM SIGSAC Conference on Computer and Communications Security*. 2020 [https://doi.org/10.1145/3372297.3420019](https://doi.org/10.1145/3372297.3420019)

## Getting Started

##### Prerequisites

Transcribing the datasets requires the `ipal-transcriber` and `tshark` to be installed (see [IPAL - Transcriber](https://github.com/fkie-cad/ipal_transcriber) and https://tshark.dev/setup/install/).

##### Install

- After cloning the repository, initialise Git's submodules with `git submodule init` and `git submodule update`

- To transcribe a dataset into IPAL, one needs to obtain copy of the original datasets, e.g., from the source listed in table above. This dataset needs to be placed under `[dataset-name]/raw/`.
- Use the `transcribe.sh` or `transcribe.py` scripts to convert the dataset into IPAL. The dataset will be exported to `[datset-name]/ipal`.

## License

MIT License. See LICENSE for details.

