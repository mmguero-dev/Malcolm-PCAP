# Malcolm-PCAP

This repository contains a collection of PCAPs that I have pulled from a variety of sources in order to test the network protocol analyzers, log parsers and dashboards of [Malcolm](https://github.com/idaholab/Malcolm).

These PCAP files have been merged and [aligned chronologically](./tools/pcap_time_shift.py) but are otherwise unaltered. I do not claim ownership nor responsibility for the PCAP files nor their contents. Some of the PCAPs may contain examples of malware in their payloads. Use at your own risk.

## PCAP collections online

For reference, here is a list of public packet capture repositories.

* [ACandeias/IntrusionDetection/PCAP](https://github.com/ACandeias/IntrusionDetection/tree/master/PCAP)
* [automayt/ICS-pcap](https://github.com/automayt/ICS-pcap) - A collection of ICS/SCADA PCAPs
* [chrissanders/packets](https://github.com/chrissanders/packets) - Packet Captures
* [contagio](https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html) - Collection of Pcap files from malware analysis
* [DeepEnd Research](https://www.dropbox.com/sh/wje7mxs4nour40k/AAC3Zpoa5wLNwsGRvKxR9AnVa?dl=0) - DeepEnd Research
* [DEF CON®](https://www.defcon.org/html/links/dc-ctf.html) - Capture the Flag Archive
* [elcabezzonn/Pcaps](https://github.com/elcabezzonn/Pcaps) - spans from malware, to normal traffic, to pentester tools
* [EvilFingers](https://www.evilfingers.com/repository/pcaps.php) ([archive.org](https://web.archive.org/web/20171225100150/www.evilfingers.com/repository/pcaps.php) cache)
* [goffinet/sip_captures](https://github.com/goffinet/sip_captures) - SIP Captures
* [ITI/ICS-Security-Tools/pcaps](https://github.com/ITI/ICS-Security-Tools/tree/master/pcaps) - ICS PCAPs developed as a community asset
* [kargs.net](http://kargs.net/captures/)
* [kholia/my-pcaps](https://github.com/kholia/my-pcaps)
* [M57 Patents Scenario](http://downloads.digitalcorpora.org/corpora/scenarios/2009-m57-patents/net/)
* [Malware PCAPs](https://www.dropbox.com/sh/7fo4efxhpenexqp/AACmuri_l-LDiVDUDJ3hVLqPa?dl=0)
* [Malware-Traffic-Analysis.net](http://www.malware-traffic-analysis.net/training-exercises.html) - Traffic Analysis Exercises
* [markofu/pcaps](https://github.com/markofu/pcaps)
* [mcfp.felk.cvut.cz](https://mcfp.felk.cvut.cz/publicDatasets/) - publicDatasets
* [nesfit/DI-cryptominingdetection/PCAPs](https://github.com/nesfit/DI-cryptominingdetection/tree/master/PCAPs) - PCAP files and data sets to Digital Investigation article 
* [NETRESEC](https://www.netresec.com/?page=PcapFiles)
* [Network Forensics Puzzle Contest](http://forensicscontest.com/puzzles)
* [PacketLife.net](https://packetlife.net/captures/)
* [packetrat/packethunting](https://github.com/packetrat/packethunting) - Resources and materials for DEF CON 2018 Packet Hunting Workshop
* [PacketTotal](https://packettotal.com/app/search)
* [PCAPLib](http://speed.cis.nctu.edu.tw/pcaplib/RemoteAccess.html)
* [PracticalPAcketAnalysis](https://github.com/markofu/pcaps/tree/master/PracticalPacketAnalysis/ppa-capture-files)
* [Security Onion](https://securityonion.readthedocs.io/en/latest/pcaps.html)
* [Weberblog.net](https://weberblog.net/tag/pcap/) and [the ultimate PCAP](https://weberblog.net/the-ultimate-pcap/)
* [Wireshark Samples](https://wiki.wireshark.org/SampleCaptures)
* [Wireshark Tutorial](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/) - Exporting Objects from a Pcap
* [WRCCDC Public Archive](https://archive.wrccdc.org/pcaps/)

## Test PCAP data sets from various projects

* [arkime/arkime](https://github.com/arkime/arkime/tree/master/tests/pcap)
* [dd-wrt](https://svn.dd-wrt.com/browser/src/router/ndpi-netfilter/tests/pcap)
* [ntop/nDPI/tests/pcap](https://github.com/ntop/nDPI/tree/dev/tests/pcap)
* [pevma/mrp](https://github.com/pevma/mrp)
* [the-tcpdump-group/tcpdump](https://github.com/the-tcpdump-group/tcpdump/tree/master/tests)
* Zeek and Zeek Plugins
    - [zeek/zeek](https://github.com/zeek/zeek/tree/master/testing/btest/Traces)
    - [0xl3x1/zeek-EternalSafety](https://github.com/0xl3x1/zeek-EternalSafety)
    - [0xxon/cve-2020-0601](https://github.com/0xxon/cve-2020-0601)
    - [0xxon/cve-2020-13777](https://github.com/0xxon/cve-2020-13777)
    - [cisagov/icsnpp-bacnet](https://github.com/cisagov/icsnpp-bacnet)
    - [cisagov/icsnpp-bsap](https://github.com/cisagov/icsnpp-bsap)
    - [cisagov/icsnpp-dnp3](https://github.com/cisagov/icsnpp-dnp3)
    - [cisagov/icsnpp-enip](https://github.com/cisagov/icsnpp-enip)
    - [cisagov/icsnpp-ethercat](https://github.com/cisagov/icsnpp-ethercat)
    - [cisagov/icsnpp-genisys](https://github.com/cisagov/icsnpp-genisys)
    - [cisagov/icsnpp-modbus](https://github.com/cisagov/icsnpp-modbus)
    - [cisagov/icsnpp-opcua-binary](https://github.com/cisagov/icsnpp-opcua-binary)
    - [cisagov/icsnpp-s7comm](https://github.com/cisagov/icsnpp-s7comm)
    - [corelight/CVE-2020-16898](https://github.com/corelight/CVE-2020-16898)
    - [corelight/CVE-2021-38647](https://github.com/corelight/CVE-2021-38647)
    - [corelight/CVE-2021-41773](https://github.com/corelight/CVE-2021-41773)
    - [corelight/cve-2021-44228](https://github.com/corelight/cve-2021-44228)
    - [corelight/cve-2022-26809](https://github.com/corelight/cve-2022-26809)
    - [corelight/http-more-files-names](https://github.com/corelight/http-more-files-names)
    - [corelight/zeek-community-id](https://github.com/corelight/zeek-community-id)
    - [corelight/zeek-spicy-ipsec](https://github.com/corelight/zeek-spicy-ipsec)
    - [corelight/zeek-spicy-openvpn](https://github.com/corelight/zeek-spicy-openvpn)
    - [corelight/zeek-spicy-ospf](https://github.com/corelight/zeek-spicy-ospf)
    - [corelight/zeek-spicy-stun](https://github.com/corelight/zeek-spicy-stun)
    - [corelight/zeek-spicy-wireguard](https://github.com/corelight/zeek-spicy-wireguard)
    - [corelight/zeek-xor-exe-plugin](https://github.com/corelight/zeek-xor-exe-plugin)
    - [corelight/zerologon](https://github.com/corelight/zerologon)
    - [cybera/zeek-sniffpass](https://github.com/cybera/zeek-sniffpass)
    - [precurse/zeek-httpattacks](https://github.com/precurse/zeek-httpattacks)
    - [zeek/spicy-dhcp](https://github.com/zeek/spicy-dhcp)
    - [zeek/spicy-dns](https://github.com/zeek/spicy-dns)
    - [zeek/spicy-http](https://github.com/zeek/spicy-http)
    - [zeek/spicy-ldap](https://github.com/zeek/spicy-ldap)
    - [zeek/spicy-pe](https://github.com/zeek/spicy-pe)
    - [zeek/spicy-tftp](https://github.com/zeek/spicy-tftp)
    - [zeek/spicy-zip](https://github.com/zeek/spicy-zip)
