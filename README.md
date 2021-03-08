# Wireguard-Forward
<h3>You should have a functioning WireGuard VPN configuration file before using this script!</h3>
<h3>This script is meant only for allowing port forwarding.</h3>


<h3>What this script does:</h3>

<ol>
  <li>Checks if ipv4 forwarding is enabled and enable if it's not running.</li>
  <li>Allows forwarding and port access on UFW firewall</li>
  <li>Sets up iptables rules for forwarding on WireGuard config file.</li>
</ol>



To do:
<ol>
  <li>Logs.</li>
  <li>Rolling back changes.</li>
</ol>
