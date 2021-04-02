# Malcolm-PCAP

This repository contains a collection of PCAPs that I have pulled from a variety of sources in order to test the network protocol analyzers, log parsers and dashboards of [Malcolm](https://github.com/idaholab/Malcolm).

These PCAP files have been merged and [aligned chronologically](./tools/pcap_time_shift.py) but are otherwise unaltered. I do not claim ownership nor responsibility for the PCAP files nor their contents. Some of the PCAPs may contain examples of malware in their payloads. Use at your own risk.

## PCAP collections online

For reference, here is a list of public packet capture repositories.

* [automayt/ICS-pcap](https://github.com/automayt/ICS-pcap) - A collection of ICS/SCADA PCAPs
* [chrissanders/packets](https://github.com/chrissanders/packets) - Packet Captures
* [contagio](https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html) - Collection of Pcap files from malware analysis
* [DEF CON®](https://www.defcon.org/html/links/dc-ctf.html) - Capture the Flag Archive
* [nesfit/DI-cryptominingdetection/PCAPs](https://github.com/nesfit/DI-cryptominingdetection/tree/master/PCAPs) - PCAP files and data sets to Digital Investigation article 
* [elcabezzonn/Pcaps](https://github.com/elcabezzonn/Pcaps) - spans from malware, to normal traffic, to pentester tools
* [EvilFingers](https://www.evilfingers.com/repository/pcaps.php) ([archive.org](https://web.archive.org/web/20171225100150/www.evilfingers.com/repository/pcaps.php) cache)
* [goffinet/sip_captures](https://github.com/goffinet/sip_captures) - SIP Captures
* [ITI/ICS-Security-Tools/pcaps](https://github.com/ITI/ICS-Security-Tools/tree/master/pcaps) - ICS PCAPs developed as a community asset
* [ACandeias/IntrusionDetection/PCAP](https://github.com/ACandeias/IntrusionDetection/tree/master/PCAP)
* [kargs.net](http://kargs.net/captures/)
* [kholia/my-pcaps](https://github.com/kholia/my-pcaps)
* [M57 Patents Scenario](http://downloads.digitalcorpora.org/corpora/scenarios/2009-m57-patents/net/)
* [Malware PCAPs](https://www.dropbox.com/sh/7fo4efxhpenexqp/AACmuri_l-LDiVDUDJ3hVLqPa?dl=0)
* [Malware-Traffic-Analysis.net](http://www.malware-traffic-analysis.net/training-exercises.html) - Traffic Analysis Exercises
* [DeepEnd Research](https://www.dropbox.com/sh/wje7mxs4nour40k/AAC3Zpoa5wLNwsGRvKxR9AnVa?dl=0) - DeepEnd Research
* [markofu/pcaps](https://github.com/markofu/pcaps)
* [mcfp.felk.cvut.cz](https://mcfp.felk.cvut.cz/publicDatasets/) - publicDatasets
* [NETRESEC](https://www.netresec.com/?page=PcapFiles)
* [PacketLife.net](https://packetlife.net/captures/)
* [packetrat/packethunting](https://github.com/packetrat/packethunting) - Resources and materials for DEF CON 2018 Packet Hunting Workshop
* [Weberblog.net](https://weberblog.net/tag/pcap/) and [the ultimate PCAP](https://weberblog.net/the-ultimate-pcap/)
* [PCAPLib](http://speed.cis.nctu.edu.tw/pcaplib/RemoteAccess.html)
* [Security Onion](https://securityonion.readthedocs.io/en/latest/pcaps.html)
* [PracticalPAcketAnalysis](https://github.com/markofu/pcaps/tree/master/PracticalPacketAnalysis/ppa-capture-files)
* [Network Forensics Puzzle Contest](http://forensicscontest.com/puzzles)
* [WRCCDC Public Archive](https://archive.wrccdc.org/pcaps/)
* [Wireshark Samples](https://wiki.wireshark.org/SampleCaptures)
* [Wireshark Tutorial](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/) - Exporting Objects from a Pcap

## Test PCAP data sets from various projects

* [0xxon/cve-2020-0601](https://github.com/0xxon/cve-2020-0601/tree/master/testing/Traces)
* [0xxon/cve-2020-13777](https://github.com/0xxon/cve-2020-13777/tree/master/testing/Traces)
* [arkime/arkime](https://github.com/arkime/arkime/tree/master/tests/pcap)
* [corelight/CVE-2020-16898](https://github.com/corelight/CVE-2020-16898/tree/master/testing/Traces)
* [corelight/zerologon](https://github.com/corelight/zerologon/tree/master/testing/Traces)
* [cybera/zeek-sniffpass](https://github.com/cybera/zeek-sniffpass/tree/master/tests)
* [dd-wrt](https://svn.dd-wrt.com/browser/src/router/ndpi-netfilter/tests/pcap)
* [lexibrent/zeek-EternalSafety](https://github.com/lexibrent/zeek-EternalSafety/tree/master/tests/traces)
* [ntop/nDPI/tests/pcap](https://github.com/ntop/nDPI/tree/dev/tests/pcap)
* [pevma/mrp](https://github.com/pevma/mrp)
* [precurse/zeek-httpattacks](https://github.com/precurse/zeek-httpattacks/tree/master/tests)
* [the-tcpdump-group/tcpdump](https://github.com/the-tcpdump-group/tcpdump/tree/master/tests)
* [zeek/zeek](https://github.com/zeek/zeek/tree/master/testing/btest/Traces)