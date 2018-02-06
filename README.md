# mass_ct_crawler
Utility for crawling certificate transparency servers and submitting CT information to a MASS server

#List of Suitable CT Servers 

Name | Cert Count | Max Block Size | URL
-----|-----|------------|-----------------
Google 'Aviator' log | 46466471 | 1024 | ct.googleapis.com/aviator 
Google 'Icarus' log | 186657087 | 1024 | ct.googleapis.com/icarus
Google 'Pilot' log | 206952402 | 1024 | ct.googleapis.com/pilot
Google 'Rocketeer' log | 201088116 | 1024 | ct.googleapis.com/rocketeer
Google 'Skydiver' log | 9944215 | 1024 | ct.googleapis.com/skydiver
DigiCert Log Server | 4384072 | 65 | ct1.digicert-ct.com/log
DigiCert Log Server 2 | 1565753 | 65 | ct2.digicert-ct.com/log
Symantec log | 7087084 | 1024 | ct.ws.symantec.com
Symantec 'Vega' log | 435605 | 1024 | vega.ws.symantec.com
Symantec 'Sirius' log | 112009 | 1024 | sirius.ws.symantec.com
Venafi Gen2 CT log | 102606087 | 1001 | ctlog-gen2.api.venafi.com
Comodo 'Sabre' CT log | 31316390 | 1001 | sabre.ct.comodo.com
Comodo 'Mammoth' CT log | 42553944 | 1001 | mammoth.ct.comodo.com
(updated: 01-27-2018)

For more information about known logs, see: https://www.certificate-transparency.org/known-logs