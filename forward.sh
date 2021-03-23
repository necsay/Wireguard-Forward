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

PS3="Please enter 1 or 2: "



#Check if WireGuard is installed
if ! command -v wg &> /dev/null
then
    echo -e "${RED}ERROR: WireGuard does not seem to be installed.${NC}\n"
    exit
fi

#Set up path for conf file
declare -a all_paths=()

space_re=" |'"

while read -r line
do
	test=${line##*/}
    if [[ ! $test =~ $space_re ]]; then
	all_paths+=("$line")
    else
    echo -e "Skipping $line \n${ORANGE}Reason${NC}: No spaces allowed in config file."
    fi
done < <(find /etc/wireguard -maxdepth 1 -name '*.conf')

if [ "${all_paths[0]}" == "" ]; then
    echo -e "${RED}ERROR${NC}: There doesn't seem to be any config files in /etc/wireguard\nThis script is only meant for forwarding ports on a working connection."
    exit
fi

sel_re="^[1-${#all_paths[@]}]$"

cnter=0
for i in "${all_paths[@]}"
	do
	cnter=$((cnter+1))
	echo -e "$cnter)${i##*/}"
done
	
read -p "Please select your config file:" sl_cf

while [[ ! $sl_cf =~ $sel_re ]]; do
	
	echo -e "${RED}Error${NC}: Wrong input please try again."
	cnter=0
	for i in "${all_paths[@]}"
		do
		cnter=$((cnter+1))
		echo -e "$cnter)${i##*/}"
	done
	
	read -p "Please select your config file:" sl_cf
	
done
	
sl_cf=$((sl_cf-1))
file_path=${all_paths[$sl_cf]}
wg_conf=${file_path##*/} #remove left side of "/" all chars
wg_interface=${wg_conf%.*}  #remove right side of "."

# Check forwarding and enable

sysctl_state=$(sysctl -a | grep net.ipv4.ip_forward | grep -v 'update\|pmtu' | cut -d "=" -f2 | xargs)

if [ $sysctl_state == "0" ]; then
	echo -e "${RED}ERROR${NC}: ipv4 forwarding is not enabled"
	echo -e "Do you wish to enable and continue?\nThe script will not continue unless ipv4 forwarding is enabled."
	select yn in "Enable" "Quit"; do
		case $yn in
			Enable ) break;; 
			Quit ) echo -e "Terminated by user"; exit;;
		esac
	done
	echo "net.ipv4.ip_forward = 1" >/etc/sysctl.d/wireguard.conf
	sysctl --system	
fi


	
#Double check sysctl
sysctl_state=$(sysctl -a | grep net.ipv4.ip_forward | grep -v 'update\|pmtu' | cut -d "=" -f2 | xargs)

if [ $sysctl_state == "0" ]; then
	echo -e "${RED}ERROR${NC}: Could not enable ipv4 forwarding."
	exit
fi


# Check if UFW is installed
conf="null"
if ! command -v ufw &> /dev/null
then
    echo -e "${RED}WARNING{NC}: UFW not found$"
    echo -e "Do you wish to continue?\nIf you install UFW after running this script, forwarding will be blocked."
	select yn in "Continue" "Quit"; do
	    case $yn in
	        Continue ) conf="noufw"; break;;
	        Quit ) echo -e "Terminated by user"; exit;;
	    esac
	done
fi



if [ "$conf" != "noufw" ]; then
	ufw=$(ufw status | grep -iF active |cut -d ":" -f2 | xargs | tr A-Z a-z)
	if [ "$ufw" != "active" ]; then
		echo -e "\n${ORANGE}WARNING${NC}: UFW is installed but not enabled.\n"
		echo -e "Do you wish to enable?"
		echo -e "This script does not require UFW to be running."
		echo -e "${ORANGE}WARNING${NC}: If you are using SSH you may lose your connection."
		select yn in "Enable" "Continue"; do
			case $yn in
				Enable ) echo -e "${GREEN}"; ufw enable; echo -e "${NC}"; break;;
				Continue ) conf="break"; break;;
			esac
		done
	fi
	if [[ "$conf" != "break" ]]; then
		ufw=$(ufw status | grep -iF active |cut -d ":" -f2 | xargs | tr A-Z a-z)
		if [ "$ufw" != "active" ]; then
			echo -e "${ORANGE}ERROR${NC}: Sorry, UFW could not be enabled."
			exit
		fi
	fi
fi


# Get VPN ip

sv_ip=$(grep -iF "Address" $file_path |  grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')
sv_network=${sv_ip%.*}
sv_local=${sv_ip##*.}

if [[ ! "$sv_ip" =~ $ip_re ]]; then
		echo -e "${RED}ERROR${NC}: Your IP configuration in $wg_conf is not valid:"
		exit
fi

# Get server public interface

default_interface=$(ip r | awk '/^default/ {print $5}')
echo -e "Your default interface is $default_interface"

declare -a all_interfaces=()

while read -r line
do
	fix=${line#*:}
	fix=${fix%:*}
	if [[ ! "$fix" == "lo" ]]; then
		all_interfaces+=("$fix")    
	fi
    
done < <(ip link show | tr -d '[:blank:]' | awk 'FNR%2')


if [ "${all_interfaces[0]}" == "" ]; then
    echo -e "${RED}ERROR${NC}: There doesn't seem to be any network interfaces."
    exit
fi

sel_re="^[1-${#all_interfaces[@]}]$"

cnter=0
for i in "${all_interfaces[@]}"
	do
	cnter=$((cnter+1))
	echo -e "$cnter)$i"
done
	
read -p "Please select your public IP interface:" sl_nt

while [[ ! $sl_nt =~ $sel_re ]]; do
	
	echo -e "${RED}Error${NC}: Wrong input please try again."
	cnter=0
	for i in "${all_interfaces[@]}"
		do
		cnter=$((cnter+1))
		echo -e "$cnter)$i"
	done
	
	read -p "Please select your public IP interface:" sl_nt
	
done
	
sl_nt=$((sl_nt-1))
sv_interface=${all_interfaces[$sl_nt]}

#Get internal port
port_re='^[0-9]?[0-9]?[0-9]?[0-9]$|^[0-5]?[0-9]?[0-9]?[0-9]?[0-9]$|^[6]?[0-4]?[0-9]?[0-9]?[0-9]$|^[6]?[5]?[0-4]?[0-9]?[0-9]$|^[6]?[5]?[5]?[0-2]?[0-9]$|^[6]?[5]?[5]?[3]?[0-5]$'

read -p "Please enter the internal port that will be forwarded:" sv_port

while [[ ! $sv_port =~ $port_re ]]; do
echo -e "${RED}Error${NC}: Not a valid port, please try again!"
read -p "Please enter the internal port that will be forwarded:" sv_port
done

read -p "Please enter the external port that will be listening:" cl_port

while [[ ! $cl_port =~ $port_re ]]; do
echo -e "${RED}Error${NC}: Not a valid port, please try again!"
read -p "Please enter the external port that will be listening:" cl_port
done

#Get target IP
ip_re='^[0-1]?[0-9]?[0-9]\.[0-1]?[0-9]?[0-9]\.[0-1]?[0-9]?[0-9]\.[0-1]?[0-9]?[0-9]$|^[2]?[0-4]?[0-9]\.[2]?[0-4]?[0-9]\.[2]?[0-4]?[0-9]\.[2]?[0-4]?[0-9]$|^[2]?[5]?[0-4]\.[2]?[5]?[0-4]\.[2]?[5]?[0-4]\.[2]?[5]?[0-4]$'

while true; do 
	read -p "Please enter the target IP on VPN:" cl_ip
	if [[ ! $cl_ip =~ $ip_re ]]; then
		echo -e "${RED}Error${NC}: Not a valid address, please try again:"
		continue
	fi
	cl_network=${cl_ip%.*}
	cl_4th_octet=${cl_ip##*.}

	if [ $cl_network != $sv_network ]; then
		echo -e "${RED}Error${NC}: Server is on: $sv_network.x but client is on: $cl_network.x\nOperation out of scope of this script. Please try again."
		continue
	fi
	
	if [ $cl_4th_octet == $sv_local ]; then
		echo -e "${RED}Error${NC}: Server is: $sv_ip client is: $cl_ip Source and target are the same.\nPlease try again."
		continue
	fi
	break
done

#Finalizing
echo -e "Requests coming to $sv_ip:$sv_port on $wg_interface will be forwarded to $cl_ip:$cl_port on $wg_interface"

echo -e "Do you wish to continue?"
select yn in "Proceed" "Quit"; do
    case $yn in
        Proceed ) break;;
        Quit ) echo "Terminated by user"; exit;;
    esac
done

if [ conf != noufw ]; then
ufw allow $sv_port
ufw route allow in on $sv_interface out on $wg_interface to $cl_ip port $cl_port
fi

wg-quick down $wg_interface
echo -e "Please hold for a moment."
sleep 3

insert="PostUp = iptables -t nat -A PREROUTING -i $sv_interface -p tcp --dport $sv_port -j DNAT --to-destination $cl_ip:$cl_port\nPostUp = iptables -A FORWARD -i $sv_interface -o $wg_interface -p tcp --syn --dport $sv_port -m conntrack --ctstate NEW -j ACCEPT\nPostUp = iptables -A FORWARD -i $sv_interface -o $wg_interface -p tcp --dport $sv_port -m conntrack --ctstate ESTABLISHED -j ACCEPT\nPostUp = iptables -A FORWARD -i $wg_interface -o $sv_interface -p tcp --sport $cl_port -m conntrack --ctstate ESTABLISHED -j ACCEPT\nPostUp = iptables -t nat -A POSTROUTING -o $wg_interface -p tcp --dport $sv_port -d $cl_ip -j SNAT --to-source $sv_ip"
sed -i "/\[Interface\]/ a $insert" $file_path

wg-quick up $wg_interface

echo -e "${GREEN}Operation successful.${NC}"
