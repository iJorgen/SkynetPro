#!/bin/sh
#  ___ _                 _     ___            
# / __| |___  _ _ _  ___| |_  | _ \ _ _ ___   
# \__ \ / / || | ' \/ -_)  _| |  _/| '_/ _ \  
# |___/_\_\\_, |_||_\___|\__| |_|  |_| \___/  
#          |__/                               
#
#   Skynet Pro is enhanced by Jörgen Andersson with:
#   - Additional TIF/blocklists.
#   - Multiple blocklist URL's as fallback if primary is down.
#   - Summary Totals in Output Tables.
#   - Optimizations and duplicate Removal Across Blocklists.
#   - Performance improvements with IPtables scaling.
#   - Protect all WireGuard server/client traffic with Skynet Pro.
#   - Improved Filter Functions.
#   - UX & Output Consistency.
#   - Code Quality Improvements.
#   - DNS Allow and Ping Allow ipsets with DNAT redirect.
#
#   Code is forked from Skynet Lite by Willem Bartels
#   IP Blocking for ASUS Routers Using IPSet
#   https://github.com/wbartels/IPSet_ASUS_Lite
#
#   Original code is based on Skynet by Adamm
#   Advanced IP Blocking for ASUS Routers using IPSet
#   https://github.com/Adamm00/IPSet_ASUS
#   This script will always be open source and free to use
#


###################
#- Configuration -#
###################


filtertraffic="all"		# inbound | outbound | all
logmode="enabled"		# enabled | disabled
loginvalid="disabled"	# enabled | disabled

blocklist_set="     <Hagezi>     https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/ips/tif.txt | https://codeberg.org/hagezi/mirror2/raw/branch/main/dns-blocklists/ips/tif.txt | https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/ips/tif.txt | https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/ips/tif.txt {12}
                    <IPsum>      https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/2.txt | https://cdn.jsdelivr.net/gh/stamparm/ipsum@master/levels/2.txt {16}
                    <Abuse>      https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/refs/heads/main/abuseipdb-s100-1d.ipv4 | https://iplists.firehol.org/files/abuseipdb_1d.ipset | https://cdn.jsdelivr.net/gh/borestad/blocklist-abuseipdb@main/abuseipdb-s100-1d.ipv4 {12}
                    <Tor>        https://raw.githubusercontent.com/borestad/firehol-mirror/refs/heads/main/dm_tor.ipset | https://iplists.firehol.org/files/dm_tor.ipset | https://cdn.jsdelivr.net/gh/borestad/firehol-mirror@main/dm_tor.ipset {8}
					<DoH>        https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/ips/doh.txt | https://codeberg.org/hagezi/mirror2/raw/branch/main/dns-blocklists/ips/doh.txt | https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/ips/doh.txt | https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/ips/doh.txt {32}
                    <BitWire>    https://raw.githubusercontent.com/bitwire-it/ipblocklist/refs/heads/main/outbound.txt | https://cdn.jsdelivr.net/gh/bitwire-it/ipblocklist@main/outbound.txt {8}"
blocklist_ip=""
blocklist_domain=""
passlist_ip="       45.90.28.0
                    45.90.30.0
                    188.172.192.71
                    38.175.117.129
                    217.146.31.87
                    146.19.3.129
                    188.172.223.3
                    38.175.118.175
                    135.181.102.167
                    185.87.111.48
                    95.179.134.211
                    188.172.219.167
                    45.11.106.155
                    199.247.16.158
                    217.146.22.163
                    194.45.101.249
                    45.142.247.197
                    78.255.154.59
                    38.175.112.132
                    178.255.153.47
                    185.234.213.131
                    217.146.21.59
                    95.179.134.211"
passlist_domain=""

# Allow ICMP + plain DNS (port 53) to these IPs/domains. TCP/443 (DoH) remains blocked.
# Plain DNS is transparently redirected to the local resolver via DNAT.
# Supports both IP addresses and domain names.
passlist_dns="  8.8.8.8
                8.8.4.4
                1.1.1.1
                1.0.0.1"

# Allow ICMP only to these IPs/domains. Port 53 and 443 remain blocked.
# Supports both IP addresses and domain names.
passlist_ping="8.8.8.8
               8.8.4.4
			   1.1.1.1
			   1.0.0.1"


###############
#- Functions -#
###############


unload_IPTables() {
    # =========================================================
    # FORWARD: Remove ACCEPT rules for DNSAllow + PingAllow
    # =========================================================
    while iptables -D FORWARD -o wgc+ -p icmp --icmp-type echo-request -m set --match-set Skynet-PingAllow dst -j ACCEPT 2>/dev/null; do :; done
    while iptables -D FORWARD -o wgc+ -p udp --dport 53 -j ACCEPT 2>/dev/null; do :; done
    while iptables -D FORWARD -o wgc+ -p tcp --dport 53 -j ACCEPT 2>/dev/null; do :; done

    # =========================================================
    # FORWARD: Remove conntrack-aware wgc+ rules
    # --ctstate NEW måste matcha exakt vad load_IPTables() satte
    # =========================================================
    while iptables -D FORWARD -o wgc+ -m set ! --match-set Skynet-Passlist dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null; do :; done
    while iptables -D FORWARD -i wgc+ -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; do :; done
    while iptables -D FORWARD -i wgc+ -m conntrack --ctstate NEW -m set ! --match-set Skynet-Passlist src -m set --match-set Skynet-Master src -j DROP 2>/dev/null; do :; done

    # =========================================================
    # FORWARD: Remove wgs+ rules
    # =========================================================
    while iptables -D FORWARD -o wgs+ -m set ! --match-set Skynet-Passlist src -m set --match-set Skynet-Master src -j DROP 2>/dev/null; do :; done
    while iptables -D FORWARD -i wgs+ -m set ! --match-set Skynet-Passlist dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null; do :; done

    # =========================================================
    # raw PREROUTING: Remove DROP rules
    # =========================================================
    while iptables -t raw -D PREROUTING -i "$iface" -m set ! --match-set Skynet-Passlist src -m set --match-set Skynet-Master src -j DROP 2>/dev/null; do :; done
    while iptables -t raw -D PREROUTING -i wgs+ -m set ! --match-set Skynet-Passlist src -m set --match-set Skynet-Master src -j DROP 2>/dev/null; do :; done
    while iptables -t raw -D PREROUTING -m set ! --match-set Skynet-Passlist src -m set --match-set Skynet-Master src -j DROP 2>/dev/null; do :; done
    while iptables -t raw -D PREROUTING -i br+ -m set ! --match-set Skynet-Passlist dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null; do :; done

    # =========================================================
    # raw OUTPUT: Remove outbound DROP
    # =========================================================
    while iptables -t raw -D OUTPUT -m set ! --match-set Skynet-Passlist dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null; do :; done

    # =========================================================
    # nat PREROUTING: Remove DNS redirect DNAT rules
    # =========================================================
    while iptables -t nat -D PREROUTING -i br0 -p udp --dport 53 ! -d "$(nvram get lan_ipaddr)" -j DNAT --to-destination "$(nvram get lan_ipaddr)":53 2>/dev/null; do :; done
    while iptables -t nat -D PREROUTING -i br0 -p tcp --dport 53 ! -d "$(nvram get lan_ipaddr)" -j DNAT --to-destination "$(nvram get lan_ipaddr)":53 2>/dev/null; do :; done
}


load_IPTables() {
    logger -t "$SCRIPT_NAME" "Loading IPTables rules"

    # ── raw PREROUTING — stateless early drop (before conntrack, lowest overhead) ──
    # wgc+ is intentionally excluded here: blocking return traffic at raw would
    # break outbound-initiated connections through the WireGuard client tunnel.

    # Drop inbound on wgs+ (WireGuard server) from any Skynet-Master source
    # not whitelisted in Skynet-Passlist
    iptables -t raw -I PREROUTING -i wgs+ -m set ! --match-set Skynet-Passlist src -m set --match-set Skynet-Master src -j DROP

    # Drop inbound on all remaining interfaces (WAN etc.) from Skynet-Master
    # not whitelisted in Skynet-Passlist
    iptables -t raw -I PREROUTING -m set ! --match-set Skynet-Passlist src -m set --match-set Skynet-Master src -j DROP

    # ── FORWARD — conntrack-aware blocking for wgc+ (WireGuard client tunnel) ──
    #
    # Rules are inserted in REVERSE order using -I FORWARD 1 so that the
    # final chain order (top to bottom) becomes:
    #
    #   1. ACCEPT  icmp echo-request  out wgc+  dst in Skynet-PingAllow
    #   2. ACCEPT  tcp  dport 53      out wgc+  (DNS before dst-DROP)
    #   3. ACCEPT  udp  dport 53      out wgc+  (DNS before dst-DROP)
    #   4. DROP    all                out wgc+  dst in Skynet-Master, not in Skynet-Passlist
    #   5. ACCEPT  ESTABLISHED/RELATED in wgc+ (return traffic for outbound connections)
    #   6. DROP    NEW                in wgc+  src in Skynet-Master, not in Skynet-Passlist
    #
    # This avoids fragile line-number lookups that break when the chain is
    # modified between queries.

    # Rule 6 (inserted first → ends up at the bottom of our block)
    # Drop new inbound connections via wgc+ from blocked sources
    iptables -I FORWARD 1 -i wgc+ -m conntrack --ctstate NEW -m set ! --match-set Skynet-Passlist src -m set --match-set Skynet-Master src -j DROP

    # Rule 5
    # Allow return traffic for connections that were initiated from inside
    # the network out through the wgc+ tunnel
    iptables -I FORWARD 1 -i wgc+ -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Rule 4
    # Drop outbound traffic via wgc+ to blocked destinations
    iptables -I FORWARD 1 -o wgc+ -m set ! --match-set Skynet-Passlist dst -m set --match-set Skynet-Master dst -j DROP

    # Rule 3 — must be inserted AFTER rule 4 (ends up ABOVE it in the chain)
    # Allow outbound UDP DNS via wgc+ regardless of destination block list
    iptables -I FORWARD 1 -o wgc+ -p udp --dport 53 -j ACCEPT

    # Rule 2 — same reasoning as rule 3
    # Allow outbound TCP DNS via wgc+ regardless of destination block list
    iptables -I FORWARD 1 -o wgc+ -p tcp --dport 53 -j ACCEPT

    # Rule 1 (inserted last → ends up at the top of our block)
    # Allow outbound ICMP echo-request via wgc+ to whitelisted ping targets
    # Placed first so ping to allowed hosts is never caught by the dst-DROP
    iptables -I FORWARD 1 -o wgc+ -p icmp --icmp-type echo-request -m set --match-set Skynet-PingAllow dst -j ACCEPT

    logger -t "$SCRIPT_NAME" "IPTables rules loaded"
}


unload_LogIPTables() {
    # --- WAN inbound LOG ---
    while iptables -t raw -D PREROUTING -i "$iface" -m set ! --match-set Skynet-Passlist src -m set --match-set Skynet-Master src -m limit --limit 5/sec --limit-burst 10 -j LOG --log-prefix "[IN] " --log-tcp-options 2>/dev/null; do :; done

    # --- LAN bridge outbound LOG ---
    while iptables -t raw -D PREROUTING -i br+ -m set ! --match-set Skynet-Passlist dst -m set --match-set Skynet-Master dst -m limit --limit 10/sec --limit-burst 20 -j LOG --log-prefix "[OUT] " --log-tcp-options 2>/dev/null; do :; done

    # --- Router OUTPUT LOG ---
    while iptables -t raw -D OUTPUT -m set ! --match-set Skynet-Passlist dst -m set --match-set Skynet-Master dst -m limit --limit 10/sec --limit-burst 20 -j LOG --log-prefix "[OUT] " --log-tcp-options 2>/dev/null; do :; done

    # --- logdrop INVALID LOG ---
    while iptables -D logdrop -m state --state NEW -j LOG --log-prefix "[INVALID] " --log-tcp-options 2>/dev/null; do :; done

    # --- IOT LOG ---
    while iptables -D FORWARD -i br+ -m set --match-set Skynet-IOT src ! -o tun2+ -m limit --limit 10/sec --limit-burst 20 -j LOG --log-prefix "[IOT] " --log-tcp-options 2>/dev/null; do :; done

    # --- WireGuard clients inbound LOG (FORWARD, inte raw PREROUTING) ---
    while iptables -D FORWARD -i wgc+ -m conntrack --ctstate NEW -m set ! --match-set Skynet-Passlist src -m set --match-set Skynet-Master src -m limit --limit 10/sec --limit-burst 20 -j LOG --log-prefix "[WGC-IN] " --log-tcp-options 2>/dev/null; do :; done

    # --- WireGuard clients outbound LOG ---
    while iptables -D FORWARD -o wgc+ -m set ! --match-set Skynet-Passlist dst -m set --match-set Skynet-Master dst -m limit --limit 10/sec --limit-burst 20 -j LOG --log-prefix "[WGC-OUT] " --log-tcp-options 2>/dev/null; do :; done

    # --- WireGuard server outbound LOG ---
    while iptables -D FORWARD -i wgs+ -m set ! --match-set Skynet-Passlist dst -m set --match-set Skynet-Master dst -m limit --limit 10/sec --limit-burst 20 -j LOG --log-prefix "[WGS-OUT] " --log-tcp-options 2>/dev/null; do :; done

    # --- WireGuard server inbound LOG ---
    while iptables -D FORWARD -o wgs+ -m set ! --match-set Skynet-Passlist src -m set --match-set Skynet-Master src -m limit --limit 10/sec --limit-burst 20 -j LOG --log-prefix "[WGS-IN] " --log-tcp-options 2>/dev/null; do :; done
}


load_LogIPTables() {
    local pos_wan_in= pos_lan_out= pos_router_out= pos_iot=
    local pos_wgc_in= pos_wgc_fwd=
    local pos_wgs_fwd_dst= pos_wgs_fwd_src=
    if [ "$logmode" = "enabled" ]; then
        if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "inbound" ]; then

            # --- WAN inbound LOG ---
            while iptables -t raw -D PREROUTING -i "$iface" -m set ! --match-set Skynet-Passlist src -m set --match-set Skynet-Master src -m limit --limit 5/sec --limit-burst 10 -j LOG --log-prefix "[IN] " --log-tcp-options 2>/dev/null; do :; done
            pos_wan_in="$(iptables --line -nvL PREROUTING -t raw | awk 'NR>2 && /Skynet-Master src/ && /DROP/ && /'"$iface"'/ {print $1; exit}')"
            if [ -z "$pos_wan_in" ]; then
                log_Skynet "[!] LOG position lookup failed for $iface (WAN inbound)"
            else
                iptables -t raw -I PREROUTING "$pos_wan_in" -i "$iface" -m set ! --match-set Skynet-Passlist src -m set --match-set Skynet-Master src -m limit --limit 5/sec --limit-burst 10 -j LOG --log-prefix "[IN] " --log-tcp-options 2>/dev/null
            fi

            # --- WireGuard clients inbound LOG ---
            # NOTE: wgc+ DROP moved from raw PREROUTING to FORWARD (--ctstate NEW)
            # LOG rule follows the same chain/table as the DROP rule
            while iptables -D FORWARD -i wgc+ -m conntrack --ctstate NEW -m set ! --match-set Skynet-Passlist src -m set --match-set Skynet-Master src -m limit --limit 10/sec --limit-burst 20 -j LOG --log-prefix "[WGC-IN] " --log-tcp-options 2>/dev/null; do :; done
            pos_wgc_in="$(iptables --line -nvL FORWARD | awk 'NR>2 && /Skynet-Master src/ && /DROP/ && /wgc\+/ {print $1; exit}')"
            if [ -z "$pos_wgc_in" ]; then
                log_Skynet "[!] LOG position lookup failed for wgc+ (WGC inbound)"
            else
                iptables -I FORWARD "$pos_wgc_in" -i wgc+ -m conntrack --ctstate NEW -m set ! --match-set Skynet-Passlist src -m set --match-set Skynet-Master src -m limit --limit 10/sec --limit-burst 20 -j LOG --log-prefix "[WGC-IN] " --log-tcp-options 2>/dev/null
            fi

            # --- WireGuard server: block malicious replies toward mobile clients LOG ---
            while iptables -D FORWARD -o wgs+ -m set ! --match-set Skynet-Passlist src -m set --match-set Skynet-Master src -m limit --limit 10/sec --limit-burst 20 -j LOG --log-prefix "[WGS-IN] " --log-tcp-options 2>/dev/null; do :; done
            pos_wgs_fwd_src="$(iptables --line -nvL FORWARD | awk 'NR>2 && /Skynet-Master src/ && /DROP/ && /wgs\+/ {print $1; exit}')"
            if [ -z "$pos_wgs_fwd_src" ]; then
                log_Skynet "[!] LOG position lookup failed for wgs+ (WGS inbound)"
            else
                iptables -I FORWARD "$pos_wgs_fwd_src" -o wgs+ -m set ! --match-set Skynet-Passlist src -m set --match-set Skynet-Master src -m limit --limit 10/sec --limit-burst 20 -j LOG --log-prefix "[WGS-IN] " --log-tcp-options 2>/dev/null
            fi

        fi
        if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "outbound" ]; then

            # --- LAN bridge outbound LOG ---
            while iptables -t raw -D PREROUTING -i br+ -m set ! --match-set Skynet-Passlist dst -m set --match-set Skynet-Master dst -m limit --limit 10/sec --limit-burst 20 -j LOG --log-prefix "[OUT] " --log-tcp-options 2>/dev/null; do :; done
            pos_lan_out="$(iptables --line -nvL PREROUTING -t raw | awk 'NR>2 && /Skynet-Master dst/ && /DROP/ && /br\+/ {print $1; exit}')"
            if [ -z "$pos_lan_out" ]; then
                log_Skynet "[!] LOG position lookup failed for br+ (LAN outbound)"
            else
                iptables -t raw -I PREROUTING "$pos_lan_out" -i br+ -m set ! --match-set Skynet-Passlist dst -m set --match-set Skynet-Master dst -m limit --limit 10/sec --limit-burst 20 -j LOG --log-prefix "[OUT] " --log-tcp-options 2>/dev/null
            fi

            # --- Router OUTPUT LOG ---
            while iptables -t raw -D OUTPUT -m set ! --match-set Skynet-Passlist dst -m set --match-set Skynet-Master dst -m limit --limit 10/sec --limit-burst 20 -j LOG --log-prefix "[OUT] " --log-tcp-options 2>/dev/null; do :; done
            pos_router_out="$(iptables --line -nvL OUTPUT -t raw | awk 'NR>2 && /Skynet-Master dst/ && /DROP/ {print $1; exit}')"
            if [ -z "$pos_router_out" ]; then
                log_Skynet "[!] LOG position lookup failed for OUTPUT (router outbound)"
            else
                iptables -t raw -I OUTPUT "$pos_router_out" -m set ! --match-set Skynet-Passlist dst -m set --match-set Skynet-Master dst -m limit --limit 10/sec --limit-burst 20 -j LOG --log-prefix "[OUT] " --log-tcp-options 2>/dev/null
            fi

            # --- WireGuard clients FORWARD outbound LOG ---
            while iptables -D FORWARD -o wgc+ -m set ! --match-set Skynet-Passlist dst -m set --match-set Skynet-Master dst -m limit --limit 10/sec --limit-burst 20 -j LOG --log-prefix "[WGC-OUT] " --log-tcp-options 2>/dev/null; do :; done
            pos_wgc_fwd="$(iptables --line -nvL FORWARD | awk 'NR>2 && /Skynet-Master dst/ && /DROP/ && /wgc\+/ {print $1; exit}')"
            if [ -z "$pos_wgc_fwd" ]; then
                log_Skynet "[!] LOG position lookup failed for wgc+ (WGC outbound)"
            else
                iptables -I FORWARD "$pos_wgc_fwd" -o wgc+ -m set ! --match-set Skynet-Passlist dst -m set --match-set Skynet-Master dst -m limit --limit 10/sec --limit-burst 20 -j LOG --log-prefix "[WGC-OUT] " --log-tcp-options 2>/dev/null
            fi

            # --- WireGuard server FORWARD outbound LOG ---
            while iptables -D FORWARD -i wgs+ -m set ! --match-set Skynet-Passlist dst -m set --match-set Skynet-Master dst -m limit --limit 10/sec --limit-burst 20 -j LOG --log-prefix "[WGS-OUT] " --log-tcp-options 2>/dev/null; do :; done
            pos_wgs_fwd_dst="$(iptables --line -nvL FORWARD | awk 'NR>2 && /Skynet-Master dst/ && /DROP/ && /wgs\+/ {print $1; exit}')"
            if [ -z "$pos_wgs_fwd_dst" ]; then
                log_Skynet "[!] LOG position lookup failed for wgs+ (WGS outbound)"
            else
                iptables -I FORWARD "$pos_wgs_fwd_dst" -i wgs+ -m set ! --match-set Skynet-Passlist dst -m set --match-set Skynet-Master dst -m limit --limit 10/sec --limit-burst 20 -j LOG --log-prefix "[WGS-OUT] " --log-tcp-options 2>/dev/null
            fi

        fi
        if { [ "$(nvram get fw_log_x)" = "drop" ] || [ "$(nvram get fw_log_x)" = "both" ]; } && [ "$loginvalid" = "enabled" ]; then
            while iptables -D logdrop -m state --state NEW -j LOG --log-prefix "[INVALID] " --log-tcp-options 2>/dev/null; do :; done
            iptables -I logdrop -m state --state NEW -j LOG --log-prefix "[INVALID] " --log-tcp-options 2>/dev/null
        fi
        if [ "$iotblocked" = "enabled" ]; then
            while iptables -D FORWARD -i br+ -m set --match-set Skynet-IOT src ! -o tun2+ -m limit --limit 10/sec --limit-burst 20 -j LOG --log-prefix "[IOT] " --log-tcp-options 2>/dev/null; do :; done
            pos_iot="$(iptables --line -nvL FORWARD | awk 'NR>2 && /Skynet-IOT/ && /DROP/ {print $1; exit}')"
            if [ -z "$pos_iot" ]; then
                log_Skynet "[!] LOG position lookup failed for IOT"
            else
                iptables -I FORWARD "$pos_iot" -i br+ -m set --match-set Skynet-IOT src ! -o tun2+ -m limit --limit 10/sec --limit-burst 20 -j LOG --log-prefix "[IOT] " --log-tcp-options 2>/dev/null
            fi
        fi
    fi
}


unload_IPSets() {
	ipset -q destroy Skynet-Master
	ipset -q destroy Skynet-DNSAllow
	ipset -q destroy Skynet-PingAllow
	ipset -n list | filter_Skynet | xargs -I setname ipset -q destroy setname
}


lookup_Domain() {
	set -o pipefail; nslookup "$1" 2>/dev/null | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | awk 'NR > 2'
	if [ $? -ne 0 ]; then log_Skynet "[*] Can't resolve $1"; fi
}


strip_Domain() {
	grep -Eo 'https?://\S+' | cut -d'/' -f3
}


filter_Domain() {
	awk '{gsub("<.+>", ""); print}' | grep -Eo '([a-z0-9-]+\.)+(xn--[a-z0-9-]{4,}|[a-z]{2,})'
}


is_Domain() {
	grep -Eo '^([a-z0-9-]+\.)+(xn--[a-z0-9-]{4,}|[a-z]{2,})$'
}


filter_URL() {
	grep -Eo 'https?://[^ |{[:space:]]+'  | head -1
}


filter_All_URLs() {
	grep -Eo 'https?://[^ |{[:space:]]+'
}


filter_URL_Line() {
	grep -E 'https?://\S+'
}


filter_IP_CIDR() {
	grep -Eo '(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])){3}(/(3[0-2]|[1-2][0-9]|[0-9]))?'
}


filter_set_IP_CIDR() {
	sed -e 's/^ExitAddress //' |
	sed -e 's/^.*"cidr":"//' |
	grep -Eo '^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])){3}(/(3[0-2]|[1-2][0-9]|[0-9]))?'
}


filter_Out_PrivateIP() {
	grep -Ev '^(0\.|10\.|100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.|127\.|169\.254\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.0\.0\.|192\.0\.2\.|192\.168\.|198\.1[8-9]\.|198\.51\.100\.|203\.0\.113\.|2(2[4-9]|[3-4][0-9]|5[0-5])\.)'
}


filter_IP_Line() {
	grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
}


is_IP() {
	grep -Eo '^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])){3}$'
}


filter_Comment() {
	grep -Eo '<.+>' | tr -d '<>' | tr ',/"' ";_'" | awk '{$1 = $1; print}' | grep -E '.+'
}


filter_Update_Cycles() {
	grep -Eo '\{[1-9][0-9]*\}' | tr -d '{}' | grep -E '.+'
}


filter_Skynet() {
	grep -E '^Skynet-'
}


filter_Skynet_Set() {
	grep -E "^Skynet-" | grep -vE "Skynet-(Passlist|Domain|Master|DNSAllow|PingAllow)$"
}


download_Error() {
	if [ "$1" = "22" ]; then
		printf "[*] Download error HTTP/%s " "$2"
	else
		printf "[*] Download error cURL/%s " "$1"
	fi
}


log_Skynet() {
	local msg="$1"
	local timestamp
	timestamp="$(date '+%b %d %T')"
	echo "$timestamp skynet: $msg" >> /jffs/syslog.log
	echo " $msg" >&2
	echo "$timestamp $msg" >> "$dir_skynet/update.log"
}


log_Tail() {
	touch "$1"
	if [ $(wc -l < "$1") -ge 1550 ]; then
		tail -1500 "$1" > "$dir_temp/log" && mv -f "$dir_temp/log" "$1"
	fi
}


lookup_Comment_Init() {
	echo "Skynet-Passlist,$(echo "$passlist_ip" | filter_Comment || echo "passlist")" > "$dir_temp/lookup.csv"
	echo "Skynet-Blocklist,$(echo "$blocklist_ip" | filter_Comment || echo "blocklist_ip")" >> "$dir_temp/lookup.csv"
	echo "Skynet-Domain,$(echo "$blocklist_domain" | filter_Comment || echo "blocklist_domain")" >> "$dir_temp/lookup.csv"
}


lookup_Comment() {
	awk -F, -v setname="$1" '$1 == setname {print $2}' "$dir_temp/lookup.csv"
}


formatted_Number() {
	echo -n $1 | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta'
}


formatted_Time() {
	if ! [ "$1" -ge 0 ] 2>/dev/null; then
		printf 'undefined'
	elif [ $1 -lt 86400 ]; then
		printf '%02d:%02d' $(($1/3600)) $(($1%3600/60))
	elif [ $1 -lt 172800 ]; then
		printf '1 day %02d:%02d' $(($1%86400/3600)) $(($1%3600/60))
	else
		printf '%d days %02d:%02d' $(($1/86400)) $(($1%86400/3600)) $(($1%3600/60))
	fi
}


formatted_File_Age() {
	if [ -r "$1" ]; then
		formatted_Time $(($(date +%s) - $(date +%s -r "$1")))
	fi
}


file_Age() {
	if [ -r "$1" ]; then
		echo -n $(($(date +%s) - $(date +%s -r "$1")))
	fi
}


hash_Set() {
	local data="$version $1" file="$dir_system/$2.md5"
	echo -n "$data" | md5sum | cut -c1-32 > "$file"
}


hash_Unmodified() {
	local data="$version $1" file="$dir_system/$2.md5"
	[ "$(echo -n "$data" | md5sum | cut -c1-32)" = "$(head -1 "$file" 2>/dev/null)" ]
}


update_Counter() {
	local n=$(head -1 "$1" 2>/dev/null)
	echo -n $((n + 1)) | tee "$1"
}


header() {
	if [ "$option" = "cru" ]; then return; fi
	printf '\033[?7l'
	clear; sed -n '2,7s/#//p' "$0"
	echo " Skynet Pro build $build by Jörgen Andersson"
	echo " Forked from Skynet Lite $version by Willem Bartels"
	echo " Original code is based on Skynet By Adamm"
	echo
	if [ -n "$1" ]; then
		printf '%s\n' '-----------------------------------------------------------'
		if [ -n "$2" ]; then
			printf ' %-25s  %30s\n' "$1" "$2"
		elif [ $(echo -n "$1" | wc -m) -gt 57 ]; then
			printf ' %.54s...\n' "$1"
		else
			printf ' %s\n' "$1"
		fi
		printf '%s\n' '-----------------------------------------------------------'
	fi
}


footer() {
	if [ "$option" = "cru" ]; then return; fi
	if [ "$1" != "empty" ]; then
		printf '%s\n' '-----------------------------------------------------------'
		local right_text
		if [ -n "$2" ]; then
			right_text="$2"
		else
			right_text=""
		fi
		printf ' %-25s  %30s\n' \
			"Uptime $(formatted_File_Age "$dir_system/installtime")" \
			"$right_text"
	fi
	printf '\033[?7h\n'
}


load_Passlist() {
	local passlist_router="add Skynet-Temp $(nvram get wan0_ipaddr) comment \"Passlist: wan0_ipaddr\"
		add Skynet-Temp $(nvram get wan0_realip_ip) comment \"Passlist: wan0_realip_ip\"
		add Skynet-Temp $(nvram get wan0_gateway) comment \"Passlist: wan0_gateway\"
		add Skynet-Temp $(nvram get wan0_xgateway) comment \"Passlist: wan0_xgateway\"
		add Skynet-Temp $(nvram get wan0_dns | awk '{print $1}') comment \"Passlist: wan0_dns\"
		add Skynet-Temp $(nvram get wan0_dns | awk '{print $2}') comment \"Passlist: wan0_dns\"
		add Skynet-Temp $(nvram get dhcp_dns1_x) comment \"Passlist: dhcp_dns1_x\"
		add Skynet-Temp $(nvram get dhcp_dns2_x) comment \"Passlist: dhcp_dns2_x\"
		add Skynet-Temp 0.0.0.0/8 comment \"Passlist: This network\"
		add Skynet-Temp 10.0.0.0/8 comment \"Passlist: Private network\"
		add Skynet-Temp 100.64.0.0/10 comment \"Passlist: Carrier-grade NAT\"
		add Skynet-Temp 127.0.0.0/8 comment \"Passlist: Loopback\"
		add Skynet-Temp 169.254.0.0/16 comment \"Passlist: Link local\"
		add Skynet-Temp 172.16.0.0/12 comment \"Passlist: Private network\"
		add Skynet-Temp 192.0.0.0/24 comment \"Passlist: IETF protocol assignments\"
		add Skynet-Temp 192.0.2.0/24 comment \"Passlist: TEST-NET-1\"
		add Skynet-Temp 192.168.0.0/16 comment \"Passlist: Private network\"
		add Skynet-Temp 198.18.0.0/15 comment \"Passlist: Network interconnect device benchmark testing\"
		add Skynet-Temp 198.51.100.0/24 comment \"Passlist: TEST-NET-2\"
		add Skynet-Temp 203.0.113.0/24 comment \"Passlist: TEST-NET-3\"
		add Skynet-Temp 224.0.0.0/3 comment \"Passlist: Multicast/reserved/limited broadcast\""
	local passlist_domain="$passlist_domain
		$(echo "$blocklist_set $(nvram get firmware_server) $(nvram get ntp_server0) $(nvram get ntp_server1)" | strip_Domain)
		cloudflare.com
		fastly.com
		github.com
		raw.githubusercontent.com
		www.internic.net"

	if [ $((updatecount % 96)) -ne 0 ] && hash_Unmodified "$passlist_router $passlist_ip $passlist_domain" "passlist"; then return; fi
	log_Skynet "[i] Update $(lookup_Comment 'Skynet-Passlist')"
	local cache= curl_exit= domain= etag= etag_temp= n=0 response_code= temp= url=
	ipset -q destroy "Skynet-Temp"
	ipset create Skynet-Temp hash:net comment
	# Passlist router and reserved IP addresses
	echo "$passlist_router" | tr -d '\t' | filter_IP_Line | ipset restore -!
	# Passlist static IPs
	echo "$passlist_ip" | filter_IP_CIDR | filter_Out_PrivateIP | awk '!x[$0]++' | awk '{printf "add Skynet-Temp %s comment \"Passlist: %s\"\n", $1, $1}' | ipset restore -!
	# Passlist domains
	for domain in $(echo "$passlist_domain" | filter_Domain | awk '!x[$0]++'); do
		lookup_Domain "$domain" | filter_Out_PrivateIP | awk -v domain="$domain" '{printf "add Skynet-Temp %s comment \"Passlist: %s\"\n", $1, domain}' | ipset restore -! &
		n=$((n + 1)); if [ $((n % 50)) -eq 0 ]; then wait; fi
	done
	wait
	# Passlist root hints
	url="https://www.internic.net/domain/named.root"
	temp="$dir_temp/namedroot"; touch "$temp"
	cache="$dir_cache/namedroot"
	etag_temp="$dir_temp/namedroot_etag"
	etag="$dir_etag/namedroot"; touch "$etag"

	response_code=$(curl -sf --location \
		--limit-rate "$throttle" --user-agent "$useragent" \
		--connect-timeout 5 --retry 2 --retry-max-time 30 \
		--remote-time --time-cond "$cache" \
		--etag-compare "$etag" --etag-save "$etag_temp" \
		--write-out "%{response_code}" --output "$temp" \
		--header "Accept-encoding: gzip" "$url"); curl_exit=$?

	if [ "$response_code" = "200" ] || [ "$response_code" = "304" ]; then
		mv -f "$temp" "$cache"
		mv -f "$etag_temp" "$etag"
	else
		log_Skynet "$(download_Error $curl_exit $response_code) $url"
	fi
	if [ -f "$cache" ]; then
		{ gunzip -c "$cache" 2>/dev/null || cat "$cache"; } | filter_IP_CIDR | filter_Out_PrivateIP | awk '!x[$0]++' | awk '{printf "add Skynet-Temp %s comment \"Passlist: Root hints\"\n", $1}' | ipset restore -!
	fi
	rm -f "$temp" "$etag_temp"
	ipset swap "Skynet-Passlist" "Skynet-Temp"
	ipset destroy "Skynet-Temp"
	hash_Set "$passlist_router $passlist_ip $passlist_domain" "passlist"
}


load_DNSAllow() {
	# Populate Skynet-DNSAllow from passlist_dns (IPs and/or domains).
	# Allows ICMP + plain DNS (port 53). DoH (TCP/443) remains blocked.
	# Private IPs are not filtered out — internal DNS servers are valid entries.
	if hash_Unmodified "$passlist_dns" "passlist_dns"; then return; fi
	log_Skynet "[i] Update DNS Allow"
	local domain= n=0
	ipset -q destroy "Skynet-Temp"
	ipset create Skynet-Temp hash:net comment
	if [ -n "$passlist_dns" ]; then
		echo "$passlist_dns" | filter_IP_CIDR | awk '!x[$0]++' \
			| awk '{printf "add Skynet-Temp %s comment \"DNSAllow: %s\"\n", $1, $1}' \
			| ipset restore -!
		for domain in $(echo "$passlist_dns" | filter_Domain | awk '!x[$0]++'); do
			lookup_Domain "$domain" \
				| awk -v d="$domain" '{printf "add Skynet-Temp %s comment \"DNSAllow: %s\"\n", $1, d}' \
				| ipset restore -! &
			n=$((n + 1)); if [ $((n % 50)) -eq 0 ]; then wait; fi
		done
		wait
	fi
	ipset swap "Skynet-DNSAllow" "Skynet-Temp"
	ipset destroy "Skynet-Temp"
	hash_Set "$passlist_dns" "passlist_dns"
}


load_PingAllow() {
	# Populate Skynet-PingAllow from passlist_ping (IPs and/or domains).
	# Allows ICMP only. Port 53 and 443 remain blocked.
	# hash_Unmodified checked first so the set is cleared if passlist_ping is emptied.
	# Private IPs are not filtered out — internal hosts are valid entries.
	if hash_Unmodified "$passlist_ping" "passlist_ping"; then return; fi
	log_Skynet "[i] Update Ping Allow"
	local domain= n=0
	ipset -q destroy "Skynet-Temp"
	ipset create Skynet-Temp hash:net comment
	if [ -n "$passlist_ping" ]; then
		echo "$passlist_ping" | filter_IP_CIDR | awk '!x[$0]++' \
			| awk '{printf "add Skynet-Temp %s comment \"PingAllow: %s\"\n", $1, $1}' \
			| ipset restore -!
		for domain in $(echo "$passlist_ping" | filter_Domain | awk '!x[$0]++'); do
			lookup_Domain "$domain" \
				| awk -v d="$domain" '{printf "add Skynet-Temp %s comment \"PingAllow: %s\"\n", $1, d}' \
				| ipset restore -! &
			n=$((n + 1)); if [ $((n % 50)) -eq 0 ]; then wait; fi
		done
		wait
	fi
	ipset swap "Skynet-PingAllow" "Skynet-Temp"
	ipset destroy "Skynet-Temp"
	hash_Set "$passlist_ping" "passlist_ping"
}


load_Blocklist() {
	if hash_Unmodified "$blocklist_ip" "blocklist_ip"; then return; fi
	log_Skynet "[i] Update $(lookup_Comment 'Skynet-Blocklist')"
	ipset -q destroy "Skynet-Temp"
	ipset create Skynet-Temp hash:net comment
	echo "$blocklist_ip" | filter_IP_CIDR | filter_Out_PrivateIP | awk '!x[$0]++' | awk '{printf "add Skynet-Temp %s comment \"Blocklist: %s\"\n", $1, $1}' | ipset restore -!
	ipset swap "Skynet-Blocklist" "Skynet-Temp"
	ipset destroy "Skynet-Temp"
	hash_Set "$blocklist_ip" "blocklist_ip"
}


load_Domain() {
	if [ $((updatecount % 48)) -ne 0 ] && hash_Unmodified "$blocklist_domain" "blocklist_domain"; then return; fi
	log_Skynet "[i] Update $(lookup_Comment 'Skynet-Domain')"
	local domain= n=0
	ipset -q destroy "Skynet-Temp"
	ipset create Skynet-Temp hash:net comment
	for domain in $(echo "$blocklist_domain" | filter_Domain); do
		lookup_Domain "$domain" | filter_Out_PrivateIP | awk -v domain="$domain" '{printf "add Skynet-Temp %s comment \"Blocklist: %s\"\n", $1, domain}' | ipset restore -! &
		n=$((n + 1)); if [ $((n % 50)) -eq 0 ]; then wait; fi
	done
	wait
	ipset swap "Skynet-Domain" "Skynet-Temp"
	ipset destroy "Skynet-Temp"
	hash_Set "$blocklist_domain" "blocklist_domain"
}


load_Set() {
	grep -E '^[+][1-9]' < "$dir_temp/diff" | cut -c2- > "$dir_temp/add"
	grep -E '^[-][1-9]' < "$dir_temp/diff" | cut -c2- > "$dir_temp/del"
	awk -v setname="$setname" -v comment="$comment" '{printf "add %s %s comment \"Blocklist: %s\"\n", setname, $1, comment}' "$dir_temp/add" | ipset restore -!
	awk -v setname="$setname" '{printf "del %s %s\n", setname, $1}' "$dir_temp/del" | ipset restore -!
	printf '%s | %6s | %7s | %7s |\n' \
		"$(date '+%b %d %T')" \
		"$(wc -l < "$filtered_temp")" \
		"-$(wc -l < "$dir_temp/del")" \
		"+$(wc -l < "$dir_temp/add")" >> "$dir_debug/$comment.log"
	update_Counter "$dir_update/$setname" >/dev/null
	rm -f "$dir_temp/diff" "$dir_temp/add" "$dir_temp/del"
	log_Tail "$dir_debug/$comment.log"
}


compare_Set() {
	echo " [i] Compare $comment"
	if [ ! -f "$filtered_cache" ]; then
		touch "$filtered_cache"
	fi
	{ unzip -p "$temp" 2>/dev/null || gunzip -c "$temp" 2>/dev/null || cat "$temp"; } \
		| filter_set_IP_CIDR | filter_Out_PrivateIP | LC_ALL=C sort -u > "$filtered_temp"

	if [ ! -s "$filtered_temp" ]; then return 0; fi

	if [ "$url" = 'https://feeds.dshield.org/block.txt' ]; then
		local swap_file="$dir_temp/swap_file"
		awk '{print $0"/24"}' "$filtered_temp" | LC_ALL=C sort -u > "$swap_file"
		mv -f "$swap_file" "$filtered_temp"
	fi

	printf '\033[1A\033[K'

	local dedup_existing="$dir_temp/dedup_existing"
	local dedup_result="$dir_temp/dedup_result"
	: > "$dedup_existing"

	local primary_url primary_hash primary_setname
	primary_url=$(echo "$blocklist_set" | filter_URL_Line | head -1 | filter_URL)
	primary_hash=$(echo -n "$primary_url" | md5sum | cut -c1-24)
	primary_setname="Skynet-$primary_hash"

	if [ "$setname" = "$primary_setname" ]; then
		rm -f "$dedup_existing"
	else
		local existing
		for existing in "$dir_filtered"/Skynet-*; do
			[ -f "$existing" ] || continue
			[ "$existing" = "$filtered_cache" ] && continue
			cat "$existing" >> "$dedup_existing"
		done
	fi

	if [ -s "$dedup_existing" ]; then
		local before after removed
		before=$(wc -l < "$filtered_temp")
		awk 'NR==FNR { seen[$0]=1; next } !($0 in seen)' \
			"$dedup_existing" "$filtered_temp" > "$dedup_result"
		mv -f "$dedup_result" "$filtered_temp"
		after=$(wc -l < "$filtered_temp")
		removed=$((before - after))
		if [ "$removed" -gt 0 ]; then
			log_Skynet "[i] Dedup $comment: $removed duplicates removed ($before → $after)"
		fi
	fi
	rm -f "$dedup_existing"

	diff "$filtered_cache" "$filtered_temp" | grep -E '^[+-][1-9]' > "$dir_temp/diff"
	if [ -s "$dir_temp/diff" ]; then return 1; fi
	return 0
}


download_Set() {
	local cache= comment= curl_exit= dir= etag= etag_temp= filtered_cache= filtered_temp= hashsize= line= list= lookup= response_code= setname= temp= update_cycles= url= urls= used_fallback=
	echo "$blocklist_set" | filter_URL_Line > "$dir_temp/blocklist_set"

	while IFS= read -r line; do
		url=$(echo "$line" | filter_All_URLs | head -1)
		urls=$(echo "$line" | filter_All_URLs)
		comment=$(echo "$line" | filter_Comment || echo "<$(basename "$url")>" | filter_Comment)
		update_cycles=$(echo "$line" | filter_Update_Cycles || echo 4)
		setname="Skynet-$(echo -n "$url" | md5sum | cut -c1-24)"
		echo "$setname,$comment" >> "$dir_temp/lookup.csv"

		if ! ipset -n list "$setname" >/dev/null 2>&1; then
			case "$url" in
				*bitwire*)   hashsize=262144 ;;
				*hagezi*)    hashsize=131072  ;;
				*abuseipdb*) hashsize=65536  ;;
				*ipsum*)     hashsize=32768  ;;
				*)           hashsize=16384  ;;
			esac
			ipset create "$setname" hash:net hashsize "$hashsize" maxelem 524288 comment
			ipset add Skynet-Master "$setname" comment "$comment"
		fi

		if [ $((updatecount % update_cycles)) -ne 0 ]; then
			continue
		fi

		temp="$dir_temp/${setname}_unfiltered"; touch "$temp"
		cache="$dir_cache/$setname"
		etag_temp="$dir_temp/${setname}_etag"
		etag="$dir_etag/$setname"; touch "$etag"
		filtered_temp="$dir_temp/${setname}_filtered"
		filtered_cache="$dir_filtered/$setname"

		curl_exit=1
		used_fallback="false"
		local try_url= url_index=0
		for try_url in $urls; do
			url_index=$((url_index + 1))
			if [ $url_index -eq 1 ]; then
				echo " [i] Download $comment"
				response_code=$(curl -sf --location \
					--limit-rate "$throttle" --user-agent "$useragent" \
					--connect-timeout 5 --retry 2 --retry-max-time 30 \
					--remote-time --time-cond "$cache" \
					--etag-compare "$etag" --etag-save "$etag_temp" \
					--write-out "%{response_code}" --output "$temp" \
					--header "Accept-encoding: gzip" "$try_url"); curl_exit=$?
				printf '\033[1A\033[K'
			else
				log_Skynet "[!] Primary failed, trying fallback $url_index $comment"
				response_code=$(curl -sf --location \
					--limit-rate "$throttle" --user-agent "$useragent" \
					--connect-timeout 5 --retry 2 --retry-max-time 30 \
					--write-out "%{response_code}" --output "$temp" \
					--header "Accept-encoding: gzip" "$try_url"); curl_exit=$?
				if [ $curl_exit -eq 0 ]; then
					used_fallback="true"
				fi
			fi
			if [ $curl_exit -eq 0 ]; then
				break
			fi
			log_Skynet "$(download_Error $curl_exit $response_code) $try_url"
		done

		if [ $curl_exit -eq 0 ]; then
			if [ "$used_fallback" = "true" ]; then
				rm -f "$etag" "$etag_temp"
				touch "$etag"
				log_Skynet "[i] Fallback success $comment"
			fi
			if [ "$response_code" = "304" ]; then
				log_Skynet "[i] Fresh $comment"
			elif compare_Set && [ -s "$cache" ]; then
				log_Skynet "[!] Identical $comment"
				mv -f "$temp" "$cache"
				mv -f "$filtered_temp" "$filtered_cache"
				if [ "$used_fallback" = "false" ] && [ -s "$etag_temp" ]; then
					mv -f "$etag_temp" "$etag"
				fi
			elif [ ! -s "$filtered_temp" ]; then
				log_Skynet "[!] Ignore update $comment (zero entries)"
			else
				log_Skynet "[i] Update $comment"
				load_Set
				mv -f "$temp" "$cache"
				mv -f "$filtered_temp" "$filtered_cache"
				if [ "$used_fallback" = "false" ] && [ -s "$etag_temp" ]; then
					mv -f "$etag_temp" "$etag"
				fi
			fi
		else
			log_Skynet "[*] All URLs failed for $comment"
		fi
		rm -f "$temp" "$filtered_temp" "$etag_temp"
	done < "$dir_temp/blocklist_set"
	sort -t, -k2 < "$dir_temp/lookup.csv" > "$dir_system/lookup.csv"

	if hash_Unmodified "$blocklist_set" "blocklist_set"; then return; fi
	# Remove sets no longer in blocklist_set
	list=$(filter_Skynet_Set < "$dir_system/lookup.csv" | awk -F, '{print $1}')
	for setname in $(ipset list Skynet-Master | filter_Skynet_Set | awk '{print $1}'); do
		if ! echo "$list" | grep -q "$setname"; then
			ipset -q del "Skynet-Master" "$setname"
			ipset -q destroy "$setname"
		fi
	done
	# Cleanup cache/etag/filtered/update directories
	for dir in "$dir_cache" "$dir_etag" "$dir_filtered" "$dir_update"; do
		cd "$dir"
		for setname in $(ls -1 | filter_Skynet_Set); do
			if ! echo "$list" | grep -q "$setname"; then
				rm -f "$dir/$setname"
			fi
		done
	done
	# Cleanup debug directory
	list=$(filter_Skynet_Set < "$dir_system/lookup.csv" | awk -F, '{print $2 ".log"}')
	cd "$dir_debug"
	for comment in $(ls -1); do
		if ! echo "$list" | grep -q "$comment"; then
			rm -f "$dir_debug/$comment"
		fi
	done
	hash_Set "$blocklist_set" "blocklist_set"
}


############################
#- Initialize Skynet Pro  -#
############################


command="$1"
option="$2"
throttle=0
updatecount=0
iotblocked="disabled"
version="3.8.6"
build="2026-06-12 13:08"
useragent="$(curl -V | grep -Eo '^curl.+)') Skynet-Lite/$version https://github.com/wbartels/IPSet_ASUS_Lite"
lockfile="/var/lock/skynet.lock"

dir_skynet="/tmp/skynet"
dir_cache="$dir_skynet/cache"
dir_debug="$dir_skynet/debug"
dir_etag="$dir_skynet/etag"
dir_filtered="$dir_skynet/filtered"
dir_system="$dir_skynet/system"
dir_temp="$dir_skynet/temp"
dir_update="$dir_skynet/update_"
mkdir -p "$dir_cache" "$dir_debug" "$dir_etag" "$dir_filtered" "$dir_system" "$dir_temp" "$dir_update"


exec 99>"$lockfile"
if ! flock -n 99; then
	if [ "$command" = "update" ] && [ "$option" = "cru" ]; then
		log_Skynet "[!] Skynet Lite is locked, next update scheduled"
		exit 1;
	fi
	printf '\n\033[1A'
	printf '[i] Skynet Lite is locked, retry command every 5 seconds...'
	sleep 5
	exec "$0" "$command"
fi


if ! ipset list -n Skynet-Master >/dev/null 2>&1; then
	command="reset"
	option=""
fi


i=0
while [ "$(nvram get ntp_ready)" != "1" ] && [ "$command" != "uninstall" ]; do
	if [ $i -eq 0 ]; then log_Skynet "[i] Waiting for NTP to sync..."; fi
	if [ $i -eq 300 ]; then log_Skynet "[*] NTP failed to start after 5 minutes - Please fix immediately!"; echo; exit 1; fi
	i=$((i + 1)); sleep 1
done


if [ "$command" = "update" ] || [ "$command" = "reset" ]; then
	# Use router gateway and ISP DNS for connectivity check — avoids hitting IPs in blocklists
	gw="$(nvram get wan0_gateway)"
	isp_dns="$(nvram get wan0_dns | awk '{print $1}')"
	for i in 1 2 3 4 5 6 7; do
		if [ -n "$gw" ] && ping -q -w1 -c1 "$gw" >/dev/null 2>&1; then break; fi
		if [ -n "$isp_dns" ] && ping -q -w1 -c1 "$isp_dns" >/dev/null 2>&1; then break; fi
		if ping -q -w1 -c1 9.9.9.9 >/dev/null 2>&1; then break; fi
		if [ $i -eq 1 ]; then log_Skynet "[!] Waiting for internet connectivity..."; fi
		if [ $i -eq 7 ]; then log_Skynet "[*] Internet connectivity error"; echo; exit 1; fi
		sleep 10
	done
fi


if [ "$command" = "update" ] && [ "$option" = "cru" ]; then
	throttle="5M"
	updatecount=$(update_Counter "$dir_system/updatecount")
fi


if [ "$(nvram get wan0_proto)" = "pppoe" ]; then
	iface="ppp0"
else
	iface="$(nvram get wan0_ifname)"
fi


touch "$dir_system/lookup.csv"
cp "$dir_system/lookup.csv" "$dir_temp/lookup.csv"
unset i


#######################
#- Start Skynet Pro  -#
#######################


domain=$(echo "$command" | is_Domain) && command="domain"
ip=$(echo "$command" | is_IP) && command="ip"
case "$command" in
	reset)
		header "Reset"
		log_Skynet "[i] Install"
		rm -f "$dir_cache/"* "$dir_debug/"* "$dir_etag/"* "$dir_filtered/"*
		rm -f "$dir_system/"* "$dir_temp/"* "$dir_update/"*
		true > "$dir_skynet/update.log"
		touch "$dir_system/installtime"
		if [ "$0" != "/jffs/scripts/firewall" ]; then
			mv -f "$0" "/jffs/scripts/firewall"
			log_Skynet "[!] Skynet Pro moved to /jffs/scripts/firewall"
		fi
		if [ ! -f "/jffs/scripts/firewall-start" ]; then
			echo "#!/bin/sh
			/jffs/scripts/firewall" | tr -d '\t' > "/jffs/scripts/firewall-start"
			chmod 755 "/jffs/scripts/firewall-start"
		elif [ -f "/jffs/scripts/firewall-start" ] && ! grep -q "/jffs/scripts/firewall" "/jffs/scripts/firewall-start"; then
			chmod 755 "/jffs/scripts/firewall-start"
			echo "/jffs/scripts/firewall" >> "/jffs/scripts/firewall-start"
		fi
		unload_IPTables
		unload_LogIPTables
		unload_IPSets
		echo 'create Skynet-Passlist hash:net comment
			create Skynet-Master list:set size 64 comment counters
			create Skynet-Blocklist hash:net comment
			create Skynet-Domain hash:net comment
			add Skynet-Master Skynet-Blocklist comment "blocklist_ip"
			add Skynet-Master Skynet-Domain comment "blocklist_domain"' | tr -d '\t' | ipset restore -!
		ipset -q destroy Skynet-DNSAllow
		ipset -q destroy Skynet-PingAllow
		ipset create Skynet-DNSAllow  hash:net comment
		ipset create Skynet-PingAllow hash:net comment
		load_IPTables
		load_LogIPTables
		lookup_Comment_Init
		load_Passlist
		load_DNSAllow
		load_PingAllow
		load_Blocklist
		load_Domain
		download_Set
		cru d Skynet_update
		cru a Skynet_update "12,27,42,57 * * * * nice -n 19 /jffs/scripts/firewall update cru"
		update_Counter "$dir_system/updatecount" >/dev/null
		footer
	;;


	update)
		header "Update"
		lookup_Comment_Init
		load_Passlist
		load_DNSAllow
		load_PingAllow
		load_Blocklist
		load_Domain
		download_Set
		footer
	;;


	uninstall)
		header "Uninstall"
		log_Skynet "[*] Uninstall Skynet Pro..."
		cru d Skynet_update
		if [ -f "/jffs/scripts/firewall-start" ]; then
			chmod 755 "/jffs/scripts/firewall-start"
			config=$(grep -v "/jffs/scripts/firewall" "/jffs/scripts/firewall-start")
			echo "$config" > "/jffs/scripts/firewall-start"
		fi
		unload_IPTables
		unload_LogIPTables
		unload_IPSets
		rm -fr "$dir_skynet"
		rm -f "$lockfile" "$0"
		echo " [i] Skynet Pro has been successfully uninstalled"
		footer "empty"; exit 0
	;;


	domain)
		lookup_Domain "$domain" > "$dir_temp/ip.txt" 2>&1
		header "Search for $(tr '\n' ' ' < $dir_temp/ip.txt)"
		while IFS=, read -r setname comment; do
			ip_found="false"
			while IFS=, read -r ip; do
				if ipset -q test "$setname" "$ip"; then
					echo " [*] $comment"
					ip_found="true"; break
				fi
			done < "$dir_temp/ip.txt"
			if [ "$ip_found" = "false" ]; then
				echo " [ ] $comment"
			fi
		done < "$dir_system/lookup.csv"
		footer
	;;


	ip)
		header "Search for $ip"
		while IFS=, read -r setname comment; do
			if ipset -q test "$setname" "$ip"; then
				echo " [*] $comment"
			else
				echo " [ ] $comment"
			fi
		done < "$dir_system/lookup.csv"
		footer
	;;


	log)
		header "Update log"
		if [ -s "$dir_skynet/update.log" ]; then
			awk '{print " " $0}' "$dir_skynet/update.log"
		else
			echo " [i] Empty"
		fi
		footer
	;;


	warning)
		header "Warning log"
		if ! awk '{print " " $0}' "$dir_skynet/update.log" | grep -E '[!]'; then
			echo " [i] Empty"
		fi
		footer
	;;


	error)
		header "Error log"
		if ! awk '{print " " $0}' "$dir_skynet/update.log" | grep -E '[*]'; then
			echo " [i] Empty"
		fi
		footer
	;;


	fresh)
		header "Blocklist" "Client file age"
		true > "$dir_temp/file.csv"
		filter_Skynet_Set < "$dir_system/lookup.csv" | while IFS=, read -r setname comment; do
			age=$(file_Age "$dir_update/$setname")
			echo "$comment,$(formatted_Time "$age"),$age" >> "$dir_temp/file.csv"
		done
		sort -t, -k3n < "$dir_temp/file.csv" | awk -F, '{printf " %-40s  %15s\n", $1, $2}'
		footer
	;;


	frequency)
		header "Blocklist" "Average update time"
		true > "$dir_temp/file.csv"
		filter_Skynet_Set < "$dir_system/lookup.csv" | while IFS=, read -r setname comment; do
			sec=-1
			n=$(head -1 "$dir_update/$setname" 2>/dev/null)
			if [ "$n" -gt 0 ] 2>/dev/null; then
				sec=$(($(file_Age "$dir_system/installtime") / n))
			fi
			echo "$comment,$(formatted_Time "$sec"),$sec" >> "$dir_temp/file.csv"
		done
		sort -t, -k3n < "$dir_temp/file.csv" | awk -F, '{printf " %-40s  %15s\n", $1, $2}'
		footer
	;;


	entries)
		header "List" "Number of entries"
		true > "$dir_temp/file.ssv"
		while IFS=, read -r setname comment; do
			n=$(ipset -t list "$setname" | grep -F 'Number of entries' | grep -Eo '[0-9]+')
			echo "$comment;$n;$(formatted_Number $n)" >> "$dir_temp/file.ssv"
		done < "$dir_system/lookup.csv"
		sort -t';' -k2nr < "$dir_temp/file.ssv" | awk -F';' '{printf " %-40s  %15s\n", $1, $3}'

		# Show DNSAllow and PingAllow entry counts separately
		dns_n=$(ipset -t list Skynet-DNSAllow 2>/dev/null | grep -F 'Number of entries' | grep -Eo '[0-9]+')
		ping_n=$(ipset -t list Skynet-PingAllow 2>/dev/null | grep -F 'Number of entries' | grep -Eo '[0-9]+')
		printf ' %-40s  %15s\n' "DNSAllow" "$(formatted_Number ${dns_n:-0})"
		printf ' %-40s  %15s\n' "PingAllow" "$(formatted_Number ${ping_n:-0})"

		filter_Skynet_Set < "$dir_system/lookup.csv" | while IFS=, read -r setname comment; do
			n=$(ipset -t list "$setname" 2>/dev/null | grep -F 'Number of entries' | grep -Eo '[0-9]+')
			echo "${n:-0}"
		done | awk '{s+=$1} END {print s}' > "$dir_temp/total.txt"
		total=$(cat "$dir_temp/total.txt")
		footer "" "Total: $(formatted_Number $total)"
	;;


	dnsallow)
		# Manage Skynet-DNSAllow entries at runtime without restarting.
		# Usage: firewall dnsallow add <ip>   — add an IP
		#        firewall dnsallow del <ip>   — remove an IP
		#        firewall dnsallow list       — show all entries
		case "$option" in
			add)
				entry=$(echo "$3" | is_IP)
				if [ -z "$entry" ]; then
					echo " [!] Invalid IP: $3"
				elif ipset -q test Skynet-DNSAllow "$entry"; then
					echo " [i] Already in DNSAllow: $entry"
				else
					ipset add Skynet-DNSAllow "$entry" comment "DNSAllow: $entry"
					echo " [i] Added to DNSAllow: $entry"
				fi
			;;
			del)
				entry=$(echo "$3" | is_IP)
				if [ -z "$entry" ]; then
					echo " [!] Invalid IP: $3"
				elif ipset -q test Skynet-DNSAllow "$entry"; then
					ipset del Skynet-DNSAllow "$entry"
					echo " [i] Removed from DNSAllow: $entry"
				else
					echo " [i] Not in DNSAllow: $entry"
				fi
			;;
			list|*)
				header "DNS Allow" "Entries: $(ipset -t list Skynet-DNSAllow | grep -F 'Number of entries' | grep -Eo '[0-9]+')"
				ipset list Skynet-DNSAllow | grep -E '^\s*(([0-9]{1,3}\.){3}[0-9]{1,3})' \
					| awk '{printf " %-20s  %s\n", $1, $3}'
				footer
			;;
		esac
	;;


	pingallow)
		# Manage Skynet-PingAllow entries at runtime without restarting.
		# Usage: firewall pingallow add <ip>  — add an IP
		#        firewall pingallow del <ip>  — remove an IP
		#        firewall pingallow list      — show all entries
		case "$option" in
			add)
				entry=$(echo "$3" | is_IP)
				if [ -z "$entry" ]; then
					echo " [!] Invalid IP: $3"
				elif ipset -q test Skynet-PingAllow "$entry"; then
					echo " [i] Already in PingAllow: $entry"
				else
					ipset add Skynet-PingAllow "$entry" comment "PingAllow: $entry"
					echo " [i] Added to PingAllow: $entry"
				fi
			;;
			del)
				entry=$(echo "$3" | is_IP)
				if [ -z "$entry" ]; then
					echo " [!] Invalid IP: $3"
				elif ipset -q test Skynet-PingAllow "$entry"; then
					ipset del Skynet-PingAllow "$entry"
					echo " [i] Removed from PingAllow: $entry"
				else
					echo " [i] Not in PingAllow: $entry"
				fi
			;;
			list|*)
				header "Ping Allow" "Entries: $(ipset -t list Skynet-PingAllow | grep -F 'Number of entries' | grep -Eo '[0-9]+')"
				ipset list Skynet-PingAllow | grep -E '^\s*(([0-9]{1,3}\.){3}[0-9]{1,3})' \
					| awk '{printf " %-20s  %s\n", $1, $3}'
				footer
			;;
		esac
	;;


	help)
		header "Commands"
		echo " firewall"
		echo " firewall 8.8.8.8"
		echo " firewall dns.google"
		echo " firewall fresh"
		echo " firewall frequency"
		echo " firewall entries"
		echo " firewall dnsallow list"
		echo " firewall dnsallow add <ip>"
		echo " firewall dnsallow del <ip>"
		echo " firewall pingallow list"
		echo " firewall pingallow add <ip>"
		echo " firewall pingallow del <ip>"
		echo " firewall log"
		echo " firewall warning"
		echo " firewall error"
		echo " firewall update"
		echo " firewall reset"
		echo " firewall uninstall"
		echo " firewall help"
		footer
	;;


	*)
		header "Blocklist" "Packets blocked"
		true > "$dir_temp/file.ssv"
		ipset list Skynet-Master | filter_Skynet | awk '{print $1 "," $3}' | while IFS=, read -r setname blocked; do
			echo "$(lookup_Comment "$setname");$blocked;$(formatted_Number $blocked)" >> "$dir_temp/file.ssv"
		done
		sort -t';' -k2nr -k1,1 < "$dir_temp/file.ssv" | awk -F';' '{printf " %-40s  %15s\n", $1, $3}'

		total=$(awk -F';' '{s+=$2} END {print s}' < "$dir_temp/file.ssv")
		footer "" "Total blocked: $(formatted_Number ${total:-0})"
	;;
esac


rm -f "$dir_temp/"*
log_Tail "$dir_skynet/update.log"
