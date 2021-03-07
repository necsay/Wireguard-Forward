#!/bin/bash

#Check for root permissions
if [ "${EUID}" -ne 0 ]; then
	echo "This script requires root permissions!"
	exit
fi

#some visuals
RED='\033[0;41m'
NC='\033[0m'
GREEN='\033[0;42m'
ORANGE='\033[0;43m'




#Check if WireGuard is installed
if ! command -v wg &> /dev/null
then
    echo -e "\n${RED}WARNING: WireGuard does not seem to be installed.${NC}\n"
    exit
fi

#Set up path for conf file
file_path="/etc/wireguard/wg0.conf"
wg_conf="wg0.conf"
wg_interface="wg0"

var1="void"
while [ $var1 != "yes" ]; do
	echo -e "Using the default path: $file_path for conf file."
	echo -e "Please enter 1 or 2"
	var2="void"
	select yn in "Confirm" "Change"; do
		case $yn in
			Confirm ) break;;
			Change ) var2="change"; file_path="void"; break;;
		esac
	done

	if [ $var2 == "change" ]; then
		echo -e "Please enter Wireguard Config file full path:"
		read file_path
	fi
	
	while [ ! -e $file_path ] ; do
		echo -e "${RED}Config file does not exist!\nPlease enter:${NC}"
		read file_path
	done
	wg_conf=${file_path##*/}
	wg_interface=${wg_conf%.*}
	echo -e "Your config path is: $file_path"
	echo -e "Your WireGuard config file is = $wg_conf"
	echo -e "Your WireGuard interface is = $wg_interface"
	echo -e "Do you wish to proceed?"
	select yn in "Yes" "No"; do
		case $yn in
			Yes ) var1="yes"; break;;
			No ) var1="void"; exit;;
		esac
	done
done

# Check forwarding and enable

sysctl_state=$(sysctl -a | grep net.ipv4.ip_forward | grep -v 'update\|pmtu' | cut -d "=" -f2 | xargs)

if [ $sysctl_state == "0" ]; then
	echo -e "${RED}WARNING: ipv4 forwarding is not enabled${NC}"
	echo -e "Do you wish to enable and continue?\nThe script will not continue unless ipv4 forwarding is enabled."
	echo -e "Please enter 1 or 2"
	select yn in "Yes" "No"; do
		case $yn in
			Yes ) break;; 
			No ) exit;;
		esac
	done
	echo "net.ipv4.ip_forward = 1" >/etc/sysctl.d/wireguard.conf
	sysctl --system	
fi


	
#Double check sysctl
sysctl_state=$(sysctl -a | grep net.ipv4.ip_forward | grep -v 'update\|pmtu' | cut -d "=" -f2 | xargs)

if [ $sysctl_state == "0" ]; then
	echo -e "${RED}ERROR : Could not enable ipv4 forwarding.${NC}"
	exit
fi


# Check if UFW is installed
conf="null"
if ! command -v ufw &> /dev/null
then
    echo -e "\n${RED}WARNING : UFW not found${NC}"
    echo -e "Do you wish to continue?\nIf you install UFW after running this script, forwarding will be blocked."
    echo -e "Please enter 1 or 2"
	select yn in "Yes" "No"; do
	    case $yn in
	        Yes ) conf="noufw"; break;;
	        No ) echo "Terminated"; exit;;
	    esac
	done
fi



if [ $conf != "noufw" ]; then
	ufw=$(ufw status | cut -c9- | tr A-Z a-z)
	if [ $ufw != "active" ]; then
		echo -e "\n${ORANGE}WARNING : UFW is installed but not enabled.${NC}\n"
		echo -e "Do you wish to enable?"
		echo -e "This script does not require UFW to be running."
		echo -e "Please enter 1 or 2"
		select yn in "Yes" "No"; do
			case $yn in
				Yes ) echo -e "${GREEN}"; ufw enable; echo -e "${NC}"; break;;
				No ) break;;
			esac
		done
	fi
	ufw=$(ufw status | cut -c9- | tr A-Z a-z)
	if [ ${ufw} != "active" ]; then
		echo -e "${ORANGE}Error : Sorry, UFW could not be enabled !"
		exit
	fi
fi


# Get VPN ip
ip_re='^[0-1]?[0-9]?[0-9]\.[0-1]?[0-9]?[0-9]\.[0-1]?[0-9]?[0-9]\.[0-1]?[0-9]?[0-9]$|^[2]?[0-4]?[0-9]\.[2]?[0-4]?[0-9]\.[2]?[0-4]?[0-9]\.[2]?[0-4]?[0-9]$|^[2]?[5]?[0-4]\.[2]?[5]?[0-4]\.[2]?[5]?[0-4]\.[2]?[5]?[0-4]$'
var3="false"
sv_ip=$(grep -iF "Address" $file_path |  grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')
	echo -e "Your vpn address is $sv_ip"
	echo -e "Please enter 1 or 2"
	select yn in "Correct" "Incorrect"; do
		case $yn in
			Correct ) var3="true"; break;;
			Incorrect ) break;;
		esac
	done

if [ $var3 != "true" ]; then
	echo -e "Sorry, please enter address manually:"
	read sv_ip
fi
	
while [[ ! $sv_ip =~ $ip_re ]]; do
	echo -e "This doesn't look like a valid address, please try again:"
	read sv_ip
done

if [ $var3 != "true" ]; then
	echo -e "Do you wish to proceed?"
	select yn in "Yes" "No"; do
		case $yn in
			Yes ) break;;
			No ) echo "Terminated by user"; exit;;
		esac
	done
fi

sv_network=${sv_ip%.*}
sv_local=${sv_ip##*.}

# Get interface


sv_interface=$(ip r | awk '/^default/ {print $5}')
	echo -e "Your public IP interface is $sv_interface"
	echo -e "Please enter 1 or 2"
	select yn in "Correct" "Incorrect"; do
		case $yn in
			Correct ) cor="true";break;;
			Incorrect ) break;;
		esac
	done

if [ $cor != "true" ]; then
	echo -e "Sorry, please enter interface manually:"
	read sv_ip
	echo -e "You have entered $sv_interface"
	echo -e "Do you wish to proceed?"
	select yn in "Yes" "No"; do
		case $yn in
			Yes ) break;;
			No ) exit;;
		esac
	done
fi

#Get internal port
port_re='^[0-9]?[0-9]?[0-9]?[0-9]$|^[0-5]?[0-9]?[0-9]?[0-9]?[0-9]$|^[6]?[0-4]?[0-9]?[0-9]?[0-9]$|^[6]?[5]?[0-4]?[0-9]?[0-9]$|^[6]?[5]?[5]?[0-2]?[0-9]$|^[6]?[5]?[5]?[3]?[0-5]$'

echo -e "Please enter the internal port that will be forwarded"
read sv_port
while [[ sv_port =~ $port_re ]]; do
echo -e "Error: Port not valid, please enter again:"
read sv_port
done

echo -e "Please enter the external port that will be listening"
read cl_port
while [[ cl_port =~ $port_re ]]; do
echo -e "Error: Port not valid, please enter:"
read cl_port
done

while true; do 
	echo -e "Please enter the external IP on VPN:"
	read cl_ip
	if [[ ! $cl_ip =~ $ip_re ]]; then
	echo -e "This doesn't look like a valid address, please try again:"
	read cl_ip
	fi
	cl_network=${cl_ip%.*}
	cl_4th_octet=${cl_ip##*.}

	if [ $cl_network != $sv_network ]; then
	echo -e "${RED}WARNING: Server is on: $sv_network.x but client is on: $cl_network.x\nOperation out of scope of this script.${NC}"
	echo -e "Please try entering a correct IP:"
	continue
	fi
	
	if [ $cl_4th_octet == $sv_local ]; then
	echo -e "${RED}WARNING: Server is: $sv_ip client is: $cl_ip Please enter a different IP for client:${NC}"
	continue
	fi
	break
done

#Finalizing

if [ conf != noufw ]; then
ufw allow $sv_port
ufw route allow in on $sv_interface out on $wg_interface to $cl_ip port $cl_port proto tcp
fi

wg-quick down $wg_interface

echo -e "Requests coming to port $sv_port will be forwarded to $cl_ip:$cl_port"

insert="PostUp = iptables -t nat -A PREROUTING -i $sv_interface -p tcp --dport $sv_port -j DNAT --to-destination $cl_ip:$cl_port\nPostUp = iptables -A FORWARD -i $sv_interface -o $wg_interface -p tcp --syn --dport $sv_port -m conntrack --ctstate NEW -j ACCEPT\nPostUp = iptables -A FORWARD -i $sv_interface -o $wg_interface -p tcp --dport $sv_port -m conntrack --ctstate ESTABLISHED -j ACCEPT\nPostUp = iptables -A FORWARD -i $wg_interface -o $sv_interface -p tcp --sport $cl_port -m conntrack --ctstate ESTABLISHED -j ACCEPT\nPostUp = iptables -t nat -A POSTROUTING -o $wg_interface -p tcp --dport $sv_port -d $cl_ip -j SNAT --to-source $sv_ip"
sed -i "/^Interface.*/a $insert" $file_path

wg-quick up $wg_interface

echo "${GREEN} Operation successful.${NC}"




