# Scapy Layers for ETSI C-ITS

This project was created as part of my masters thesis and provides [Scapy](https://scapy.net/) layers for dissecting and crafting [ETSI Cooperative Intelligent Transport Systems (C-ITS)](https://www.etsi.org/technologies/automotive-intelligent-transport) packets. It utilizes [pycrate](https://github.com/pycrate-org/pycrate) to parse the ASN.1 content of these packets, enabling easy analysis and manipulation of C-ITS messages.

## Demo

Take a look at [readCamPcap.py](readCamPcap.py) for an example of how to use this project to dissect CAM messages from a PCAP file. Executing the script will output the dissected CAM messages with their ASN.1 content:
```
###[ Ethernet ]###
  dst       = ff:ff:ff:ff:ff:ff
  src       = ae:93:1b:f6:5e:6b
  type      = 0x8947
###[ GeoBasicHeader ]###
     Version   = 1
     NH        = Secured Packet
     Reserved  = 0
     LT        = 5
     RHL       = 1
###[ GeoSecuredPacket ]### 
{
 "content": {
  "signedData": {
   "hashId": "sha256",
   "signature": {
    "ecdsaNistP256Signature": {
     "rSig": {
      "compressed-y-0": "437300a4b7763390abfa58ac1a290a6163faa8e94cfbf5975a8bfeaebb9645f3"
     },
     "sSig": "9d1670ab654e0e0ff7ca4c15f8d8b85ec98d610d93caa75f875ec9f05fa5446f"
    }
   },
   ...
  }
 },
 "protocolVersion": 3
}
###[ GeoCommonHeader ]###
           NH        = BTP-B (Non-Interactive)
           Reserved1 = 0
           HT        = TopologicallyScopedBroadcast
           HST       = 0
           TC        = 2
           Flags     = 128
           PL        = 138
           MHL       = 1
           Reserved2 = 0
###[ SingleHopBroadcast ]###
              manual    = 0
              HT        = PassengerCar
              reserved1 = 0
              address   = 191946852556395
              timestamp = 881120559
              latitude  = 488410612
              longitude = 91636504
              position_accuracy= 1
              speed     = 2006
              heading   = 747
              reserved2 = 40960
###[ BTP-B header ]###
                 dport     = 2001
                 dport_info= 0
###[ ITS_CAM ]### 
{
 "cam": {
  "camParameters": {
   "basicContainer": {
    "referencePosition": {
     "altitude": {
      "altitudeConfidence": "alt-005-00",
      "altitudeValue": 36060
     },
     "latitude": 488410769,
     "longitude": 91637345,
     "positionConfidenceEllipse": {
      "semiMajorConfidence": 282,
      "semiMajorOrientation": 1027,
      "semiMinorConfidence": 278
     }
    },
    "stationType": 5
   },
   ...
  },
  "generationDeltaTime": 54867
 },
 "header": {
  "messageID": 2,
  "protocolVersion": 2,
  "stationID": 469130859
 }
}
```

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.