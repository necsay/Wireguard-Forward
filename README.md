# Wireguard-Forward

<h3>What this script does:</h3>

<ol>
  <li>Checks if ipv4 forwarding is enabled and enable if it's not running.</li>
  <li>Allows forwarding and port access on UFW firewall</li>
  <li>Sets up iptables rules for forwarding on WireGuard config file.</li>
</ol>

The script is not yet fully tested. However, it does not delete anything, not a single line.


To do:
<ol>
  <li>Logs.</li>
  <li>Rolling back changes.</li>
  <li>Graphical/Selectible cli.</li>
  <li>Interface management.</li>
</ol>
