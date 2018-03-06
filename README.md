# mass_ct_crawler
Utility for crawling certificate transparency servers and submitting CT information to a MASS server

#List of Suitable CT Servers 

Name | Cert Count | Max Block Size | URL | new Certs per Hour 
-----|------------|----------------|-----|------
Google 'Aviator' log | 46466471 | 1024 | ct.googleapis.com/aviator | 0
Google 'Icarus' log | 186657087 | 1024 | ct.googleapis.com/icarus | 33500
Google 'Pilot' log | 206952402 | 1024 | ct.googleapis.com/pilot | 53100
Google 'Rocketeer' log | 201088116 | 1024 | ct.googleapis.com/rocketeer | 32500
Google 'Skydiver' log | 9944215 | 1024 | ct.googleapis.com/skydiver | 2600
DigiCert Log Server | 4384072 | 65 | ct1.digicert-ct.com/log | 520
DigiCert Log Server 2 | 1565753 | 65 | ct2.digicert-ct.com/log | 200
Symantec log | 7087084 | 1024 | ct.ws.symantec.com | 700
Symantec 'Vega' log | 435605 | 1024 | vega.ws.symantec.com | 
Symantec 'Sirius' log | 112009 | 1024 | sirius.ws.symantec.com | 
Venafi Gen2 CT log | 102606087 | 1001 | ctlog-gen2.api.venafi.com | 0
Comodo 'Sabre' CT log | 31316390 | 1001 | sabre.ct.comodo.com | 16000
Comodo 'Mammoth' CT log | 42553944 | 1001 | mammoth.ct.comodo.com | 15000
Cloudflare 'Nimbus2019' Log| 394333 | | ct.cloudflare.com/logs/nimbus2019 | 10
Cloudflare 'Nimbus2020' Log| 25845 | | ct.cloudflare.com/logs/nimbus2020 | 10
Cloudflare 'Nimbus2021' Log| 6996 | | ct.cloudflare.com/logs/nimbus2021 | 10

(updated: 01-27-2018)

Estimated Domain Duplicate Rate: 29%

For more information about known logs, see: https://www.certificate-transparency.org/known-logs