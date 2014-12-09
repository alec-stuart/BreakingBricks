-- The Head Section --
description = [[Cisco ASA Version and Vulnerability Scan as an nmap NSE plugin.
Attempt to grab the Cisco ASA version from the Cisco ASA.
Checks for CVE-2014-2128 vulnerability and report exploitable status.]]

---
-- @usage
-- nmap --script cisco-asa-scan.nse -p 443 <target>
-- @output
-- PORT   STATE SERVICE
-- 443/tcp open  https
-- |_cisco-asa-verscan: Version

author = "alec"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "safe"}

local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"

-- The Rule Section --
portrule = shortport.http

-- The Action Section --
action = function(host, port)

    local uri = "/CSCOSSLC/config-auth"
    local options = {header={}}
    options['header']['User-Agent'] = "Cisco AnyConnect VPN Agent"
    local response = http.get(host, port, uri, options)
    output = {}


    if ( response.status == 200 ) then
    	local version = string.match(response.body, '.*<version who="sg">(.*)</version>')
        if (version ~= nil) then
	        verstr = string.gsub(version,"%D","")
            longver = tonumber(verstr)
	        while longver<10000 do
		        longver = longver *10
	        end
            
	        output[#output + 1] = "Cisco ASA version " .. version
            if(longver <83000 and longver < 82551) then
	            checkvuln(host,port)
            elseif(longver <84000 and longver < 83242) then
            	checkvuln(host,port)
            elseif(longver <85000 and longver < 84723) then
            	checkvuln(host,port)
            elseif(longver <87000 and longver < 86114) then
            	checkvuln(host,port)
            elseif(longver <91000 and longver < 90424) then
            	checkvuln(host,port)
            elseif(longver < 92000 and longver < 91512) then
            	checkvuln(host,port)
            elseif(longver < 93000 and longver < 92240) then
            	checkvuln(host,port)
            end
            return #output > 0 and stdnse.strjoin("\n", output) or nil
        else        
            return "Unknown"
        end
    end
end


function checkvuln(host,port)
    output[#output + 1] = "CVE-2014-2128 - Vulnerable version detected!" 
    local uri = '/+CSCOE+/cedlogon.html'
    local options = {header={}}
    options['header']['User-Agent'] = "ASDM/Java/1.7.0_55"
    options['header']['Cookie'] = "ced=../../locale/ru/LC_MESSAGES/webvpn.mo"
    response = http.get(host, port, uri, options)
    if ( response.status == 200 ) then
        local version = string.match(response.body, '.*preview.*')
        if (version ~= nil) then
           output[#output + 1] = "Cisco ASA Portal is vulnerable to remote compromise" 
        else
            output[#output + 1] ="Cisco ASA is not exploitable - Preview has not been launched"
        end

    end
end


