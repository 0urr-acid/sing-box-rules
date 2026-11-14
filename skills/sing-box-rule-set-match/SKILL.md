---
name: sing-box-rule-set-match
description: Find the source binary sing-box rule set that sends an IP address or domain to an unwanted route by checking the files in output/check.
---

# Identify the Source of a Rule

Work from the project root. Use the IP address or domain from the connection being diagnosed; for a domain, pass the hostname without the URL scheme or path.

1. Check that `sing-box` is available and verify the syntax with `sing-box rule-set match --help`.
2. Run the following for each file in `output/check/`:

   ```bash
   sing-box rule-set match -f binary "output/check/name.srs" "104.26.0.157"
   ```

   Check all files, including those in subdirectories. Record the filename, exit code, stdout, and stderr. In the installed version, a match is printed to stderr as `match rules.[0]: ip_cidr=<binary>`, and an exit code of 0 can also occur when there is no match. Do not treat a successful exit code as proof of a match. Track read or format errors separately from non-matches.
3. Find references to the matching rule set in `rules/` with `rg -n -F 'name.srs' rules`. This links the source rule set to a routing group, for example `rules/node-main/proxylist.txt` → `node-main-ip`.
4. To identify the exact subnet, decompile the matching source into a temporary JSON file:

   ```bash
   sing-box rule-set decompile "output/check/name.srs" -o /tmp/sing-box-source-check.json
   ```

   Use Python's `ipaddress` module to check whether the IP address belongs to any of the `ip_cidr` entries, taking the IP version into account. A text search for the exact IP address is insufficient: a broader subnet may contain it. Compare the result with the corresponding JSON file in `output_debug/`.
5. Report the number of files checked, all matching sources, the exact subnets, and where each source is referenced. Do not claim that the local rule sets are identical to those loaded on the device unless this has been verified separately. This check alone does not require changing rules or rebuilding.

Verified example: IP address `104.26.0.157` matches `geoip-re-filter.srs`, which is referenced in `rules/node-main/proxylist.txt`; in the built `output_debug/node-main-ip.json`, it is covered by `104.16.0.0/12`. When diagnosing again, check the current files rather than relying on this example.
