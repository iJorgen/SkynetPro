# SkynetPro - Firewall & Security Enhancements

Lightweight firewall addition for ARM/HND based ASUS Routers using IPSet.
SkynetPro is forked from Skynet Lite by Willem Bartels and is based on the IPTables from Skynet by Adamm.

## Key features
- Small one file shell script, no need for an external USB drive.
- Additional Threat Intelligence Sources added.
- Deduplication of entries to optimize ipset sizes and resource usage.
- Summary Totals in Output Tables
- Support for plain text gzip transfer-encoding.
- Performance improvements with IPtables scaling
- Only download and update changed blocklist sets.
- Use incremental update for all blocklist sets.
- Improved Filter Functions
- For all other lists the ipset swap feature is used.
- UX & Output Consistency
- Code Quality Improvements

## Installation
Ensure you have an [Asuswrt-Merlin](https://www.asuswrt-merlin.net/) firmware and enabled the JFFS2 partition:
```
Administration > System > Enable JFFS custom scripts and configs: Yes > Apply
```

Type the following line in your favorite SSH Client:

```Shell
curl https://raw.githubusercontent.com/iJorgen/SkynetPro/master/firewall.sh --output /jffs/scripts/firewall && chmod 755 /jffs/scripts/firewall && /jffs/scripts/firewall reset
```

## Uninstall

Type the following line in your favorite SSH Client:

```Shell
/jffs/scripts/firewall uninstall
```

## Commands

```
firewall
firewall 8.8.8.8
firewall dns.google
firewall fresh
firewall frequency
firewall entries
firewall debug
firewall warning
firewall error
firewall update
firewall reset
firewall uninstall
firewall help
```

To make the commands above available from all directories, type the following line in your favorite SSH Client:

```Shell
echo 'export PATH=$PATH:/jffs/scripts' >> '/jffs/configs/profile.add'
```
