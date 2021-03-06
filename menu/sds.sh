V#!/bin/bash
#Create Shadowsocks
clear
echo -e ""
echo -e "==================="
echo -e "|   SHADOWSOCKS   |"
echo -e "-------------------"
echo -e ""
echo -e "List :"
echo -e ""
echo -e "[1] Addss"
echo -e "[2] Cekss"
echo -e "[3] Delss"
echo -e "[4] Renewss"
echo -e "[5] Xp-ss"
echo -e ""
read -p "Mana yang ingin anda pilih : " Jawapan

# Function Addss
if [[ $Answer =~ ^([1])$ ]]
        then
        IP=$(wget -qO- icanhazip.com);
lastport1=$(grep "port_tls" /etc/shadowsocks-libev/akun.conf | tail -n1 | awk '{print $2}')
lastport2=$(grep "port_http" /etc/shadowsocks-libev/akun.conf | tail -n1 | awk '{print $2}')
if [[ $lastport1 == '' ]]; then
tls=2443
else
tls="$((lastport1+1))"
fi
if [[ $lastport2 == '' ]]; then
http=3443
else
http="$((lastport2+1))"
fi
echo ""
echo "Masukkan password"

until [[ $user =~ ^[a-zA-Z0-9_]+$ && ${CLIENT_EXISTS} == '0' ]]; do
		read -rp "Password: " -e user
		CLIENT_EXISTS=$(grep -w $user /etc/shadowsocks-libev/akun.conf | wc -l)

		if [[ ${CLIENT_EXISTS} == '1' ]]; then
			echo ""
			echo "Akun sudah ada, silahkan masukkan password lain."
			exit 1
		fi
	done
read -p "Expired (hari): " masaaktif
exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
tgl=$(echo "$exp" | cut -d- -f3)
bln=$(echo "$exp" | cut -d- -f2)
cat > /etc/shadowsocks-libev/$user-tls.json<<END
{   
    "server":"0.0.0.0",
    "server_port":$tls,
    "password":"$user",
    "timeout":60,
    "method":"aes-256-cfb",
    "fast_open":true,
    "no_delay":true,
    "nameserver":"1.1.1.1",
    "mode":"tcp_and_udp",
    "plugin":"obfs-server",
    "plugin_opts":"obfs=tls"
}
END
cat > /etc/shadowsocks-libev/$user-http.json <<-END
{
    "server":"0.0.0.0",
    "server_port":$http,
    "password":"$user",
    "timeout":60,
    "method":"aes-256-cfb",
    "fast_open":true,
    "no_delay":true,
    "nameserver":"1.1.1.1",
    "mode":"tcp_and_udp",
    "plugin":"obfs-server",
    "plugin_opts":"obfs=http"
}
END
chmod +x /etc/shadowsocks-libev/$user-tls.json
chmod +x /etc/shadowsocks-libev/$user-http.json

systemctl start shadowsocks-libev-server@$user-tls.service
systemctl enable shadowsocks-libev-server@$user-tls.service
systemctl start shadowsocks-libev-server@$user-http.service
systemctl enable shadowsocks-libev-server@$user-http.service

echo -e "### $user $exp
port_tls $tls
port_http $http">>"/etc/shadowsocks-libev/akun.conf"
tmp1=$(echo -n "aes-256-cfb:${user}@${IP}:$tls" | base64 -w0)
tmp2=$(echo -n "aes-256-cfb:${user}@${IP}:$http" | base64 -w0)
linkss1="ss://${tmp1}?plugin=obfs-local;obfs=tls;obfs-host=bing.com"
linkss2="ss://${tmp2}?plugin=obfs-local;obfs=http;obfs-host=bing.com"
clear
	echo -e ""
	echo -e "=======-Shadowsocks-======="
	echo -e "IP/Host        : $IP"
	echo -e "Host           : $domain"
	echo -e "Port OBFS TLS  : $tls"
	echo -e "Port OBFS HTTP : $http"
	echo -e "Password       : $user"
	echo -e "Method         : aes-256-cfb"
	echo -e "Aktif Sampai   : $exp"
	echo -e "==========================="
	echo -e "Link OBFS TLS : $linkss1"
	echo -e "==========================="
	echo -e "Link OBFS HTTP : $linkss2"
	echo -e "==========================="
	echo -e "Script by RedoxxoVpn"
else
	echo -e ""
fi

# Function Cekss
if [[ $Answer =~ ^([3])$ ]]
        then
            clear
                        echo -e ""
                        echo -e "================"
                        echo -e "|    Cekss     |"
                        echo -e "----------------"
                        echo -e ""
                        cekss "https://raw.githubusercontent.com/x-idssh/xxx/main/menu/cekss.sh"
                        echo -e ""
                else
                        echo -e "" 
        fi
            
# Function Delss
if [[ $Answer =~ ^([3])$ ]]
        then
            clear
                        echo -e ""
                        echo -e "================"
                        echo -e "|   Dropbear   |"
                        echo -e "----------------"
                        echo -e ""
                        netstat -tunlp | grep dropbear
                        echo -e ""
                else
                        echo
        fi

# Function Xp-ss
if [[ $Answer =~ ^([4])$ ]]
        then
            clear
            xp-ss
            echo -e "[0] Back to Menu"
            echo -e ""
            read -p "Enter your choice : " Xp-ss
            if [[ $Xp-ss =~ ^([0])$ ]]
                then
                    clear
                    redoxxo
                else
                    echo -e ""
            fi

        else
            echo -e ""
fi

# Function Renewss
if [[ $Answer =~ ^([5])$ ]]
        then
            clear
            renewss
            echo -e "[0] Back to Menu"
            echo -e ""
            read -p "Enter your choice : " Renewss
            if [[ $Renewss =~ ^([0])$ ]]
                then
                    clear
                    redoxxo
                else
                    echo -e ""
            fi

        else
            echo -e ""
fi
