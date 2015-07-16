#!/bin/bash
sudo timedatectl set-timezone Europe/Bucharest

sudo sed -i 's/iface eth0 inet dhcp/#iface eth0 inet dhcp/g' /etc/network/interfaces
sudo echo "iface eth0 inet static" >> /etc/network/interfaces
sudo echo "address 10.199.100.45" >> /etc/network/interfaces
sudo echo "netmask 255.255.254.0" >> /etc/network/interfaces
sudo echo "network 10.199.100.0" >> /etc/network/interfaces
sudo echo "gateway 10.199.100.168" >> /etc/network/interfaces
sudo echo "broadcast 10.199.101.255" >> /etc/network/interfaces
sudo echo "dns-domain dom1.ad.sys" >> /etc/network/interfaces
sudo echo "dns-nameservers 10.199.100.2 10.238.127.102 8.8.8.8" >> /etc/network/interfaces
#sudo ifconfig -a eth0 10.199.100.45 netmask 255.255.254.0 up
#sudo route add default gw 10.199.100.168
echo "------------------------------------------------------------------------------"
echo "					UPDATE"
echo "------------------------------------------------------------------------------"
echo "username:" 
read username
#username=$(whoami)

sudo sed -i 's/APT::Periodic::AutocleanInterval "0";/APT::Periodic::AutocleanInterval "7";/g' /etc/apt/apt.conf.d/10periodic
sudo apt-get update
sudo apt-get upgrade -y
echo "------------------------------------------------------------------------------"
echo "					TOOLS"
echo "------------------------------------------------------------------------------"
sudo apt-get install -y mc
sudo apt-get install -y python-software-properties
sudo add-apt-repository -y ppa:nilarimogard/webupd8
sudo apt-get update
sudo apt-get install -y launchpad-getkeys
sudo launchpad-getkeys
sudo /etc/init.d/apparmor stop
sudo update-rc.d -f apparmor remove
sudo apt-get remove -y apparmor apparmor-utils
sudo apt-get install -y ntp ntpdate
sudo ntpdate pool.ntp.org
sudo apt-get install -y smartmontools
sudo apt-get install -y traceroute
sudo apt-get install -y acct
echo "------------------------------------------------------------------------------"
echo "					WEBMIN"
echo "------------------------------------------------------------------------------"
echo "deb http://download.webmin.com/download/repository sarge contrib" |sudo tee -a /etc/apt/sources.list
echo "deb http://webmin.mirror.somersettechsolutions.co.uk/repository sarge contrib" |sudo tee -a /etc/apt/source.list
wget http://www.webmin.com/jcameron-key.asc
sudo apt-key add jcameron-key.asc
sudo launchpad-getkeys
sudo apt-get update
sudo apt-get install -y webmin

# sudo apt-get install -y samba samba-common libpam-smbpass
sudo apt-get install -y python-glade2 system-config-samba
sudo cp /etc/samba/smb.conf /etc/samba/smb.conf.bak
# sudo apt-get install -y apache2
# sudo apt-get install -y php5
# sudo /etc/init.d/apache2 restart
# sudo apt-get install -y mysql-server mysql-common mysql-client php5-mysql
sudo apt-get install -y libapache2-mod-php5 libapache2-mod-auth-mysql phpmyadmin
sudo /etc/init.d/apache2 restart
echo "ServerName sabuh35005" |sudo tee -a /etc/apache2/apache2.conf
sudo sed -i 's/ServerSignature On/#ServerSignature On/g' /etc/apache2/conf-enabled/security.conf
sudo sed -i 's/DocumentRoot \/var\/www\/html/DocumentRoot \/var\/www/g' /etc/apache2/sites-enabled/000-default.conf
sudo /etc/init.d/apache2 restart






echo "------------------------------------------------------------------------------"
echo "					PHP"
echo "------------------------------------------------------------------------------"

sudo cp /etc/php5/apache2/php.ini /etc/php5/apache2/php.ini.backup
sudo sed -i 's/disable_functions/;disable_functions/g' /etc/php5/apache2/php.ini
sudo sed -i 's/expose_php/;expose_php/g' /etc/php5/apache2/php.ini
           
sudo echo "disable_functions = exec,system,shell_exec,passthru" >> /etc/php5/apache2/php.ini
sudo echo "register_globals = Off" >> /etc/php5/apache2/php.ini
sudo echo "expose_php = Off" >> /etc/php5/apache2/php.ini
#sudo echo "magic_quotes_gpc = On" >> /etc/php5/apache2/php.ini            


sudo /etc/init.d/apache2 restart

echo "------------------------------------------------------------------------------"
echo "					Apache ModSecurity"
echo "------------------------------------------------------------------------------"
# 9. Protect from attacks - ModSecurity
#sudo apt-get install -y libapache2-mod-security2
#sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
#sudo sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/g' /etc/modsecurity/modsecurity.conf
#sudo sed -i 's/SecRequestBodyLimit 13107200/SecRequestBodyLimit 50000000/g' /etc/modsecurity/modsecurity.conf
#sudo sed -i 's/SecRequestBodyInMemoryLimit 131072/SecRequestBodyInMemoryLimit 50000000/g' /etc/modsecurity/modsecurity.conf
#sudo wget https://github.com/SpiderLabs/owasp-modsecurity-crs/archive/master.zip
#sudo unzip master.zip
#sudo cp -r owasp-modsecurity-crs-master/* /etc/modsecurity/
#sudo mv /etc/modsecurity/modsecurity_crs_10_setup.conf.example /etc/modsecurity/modsecurity_crs_10_setup.conf
#sudo ls /etc/modsecurity/base_rules | xargs -I {} sudo ln -s /etc/modsecurity/base_rules/{} /etc/modsecurity/activated_rules/{}
#sudo ls /etc/modsecurity/optional_rules | xargs -I {} sudo ln -s /etc/modsecurity/optional_rules/{} /etc/modsecurity/activated_rules/{}
#sudo sed -i 's/<\/IfModule>/#/g' /etc/apache2/mods-available/security2.conf
#sudo echo "Include /etc/modsecurity/activated_rules/*.conf" >> /etc/apache2/mods-available/security2.conf
#sudo echo "</IfModule>" >> /etc/apache2/mods-available/security2.conf
#sudo a2enmod security2
#sudo a2enmod headers
#sudo /etc/init.d/apache2 restart

echo "------------------------------------------------------------------------------"
echo "					Apache ModEvasive"
echo "------------------------------------------------------------------------------"


sudo apt-get install -y libapache2-mod-evasive
sudo mkdir /var/log/mod_evasive

sudo chown www-data:www-data /var/log/mod_evasive/

if [ -f /etc/apache2/mods-available/mod-evasive.conf ]; then
	
	sudo mv /etc/apache2/mods-available/mod-evasive.conf /etc/apache2/mods-available/mod-evasive.conf.backup
fi


sudo echo "# Script Entry - Apache2 ModEvasive Configuration " > /etc/apache2/mods-available/mod-evasive.conf
sudo echo "<ifmodule mod_evasive20.c>" >> /etc/apache2/mods-available/mod-evasive.conf
sudo echo "   DOSHashTableSize 3097" >> /etc/apache2/mods-available/mod-evasive.conf
sudo echo "   DOSPageCount  2" >> /etc/apache2/mods-available/mod-evasive.conf
sudo echo "   DOSSiteCount  50" >> /etc/apache2/mods-available/mod-evasive.conf
sudo echo "   DOSPageInterval 1" >> /etc/apache2/mods-available/mod-evasive.conf
sudo echo "   DOSSiteInterval  1" >> /etc/apache2/mods-available/mod-evasive.conf
sudo echo "   DOSBlockingPeriod  10" >> /etc/apache2/mods-available/mod-evasive.conf
sudo echo "   DOSLogDir   /var/log/mod_evasive" >> /etc/apache2/mods-available/mod-evasive.conf
sudo echo "   DOSEmailNotify  $username@localhost" >> /etc/apache2/mods-available/mod-evasive.conf
sudo echo "   DOSWhitelist   127.0.0.1" >> /etc/apache2/mods-available/mod-evasive.conf
sudo echo "</ifmodule>" >> /etc/apache2/mods-available/mod-evasive.conf

sudo a2enmod evasive

sudo /etc/init.d/apache2 restart


echo "------------------------------------------------------------------------------"
echo "					Secure Shared Memory"
echo "------------------------------------------------------------------------------"

# Make sure fstab does not already contain a tmpfs reference
sudo echo "tmpfs     /dev/shm     tmpfs     defaults,noexec,nosuid     0     0" >> /etc/fstab




echo "------------------------------------------------------------------------------"
echo "					Network"
echo "------------------------------------------------------------------------------"



sudo cp /etc/sysctl.conf /etc/sysctl.conf.backup

sudo cd /etc/sysctl.d
sudo wget https://raw.github.com/dannysheehan/ubuntu/master/sysctl.d/60-ftmon-recommmended.conf
sudo sysctl --system

sudo sed -i 's/net.ipv4.conf.default.rp_filter/#net.ipv4.conf.default.rp_filter/g' /etc/sysctl.conf
sudo sed -i 's/net.ipv4.conf.all.rp_filter/#net.ipv4.conf.all.rp_filter/g' /etc/sysctl.conf
sudo sed -i 's/net.ipv4.icmp_echo_ignore_broadcasts/#net.ipv4.icmp_echo_ignore_broadcasts/g' /etc/sysctl.conf
sudo sed -i 's/net.ipv4.tcp_syncookies/#net.ipv4.tcp_syncookies/g' /etc/sysctl.conf
sudo sed -i 's/net.ipv4.conf.all.accept_source_route/#net.ipv4.conf.all.accept_source_route/g' /etc/sysctl.conf
sudo sed -i 's/net.ipv6.conf.all.accept_source_route/#net.ipv6.conf.all.accept_source_route/g' /etc/sysctl.conf
sudo sed -i 's/net.ipv4.conf.default.accept_source_route/#net.ipv4.conf.default.accept_source_route/g' /etc/sysctl.conf
sudo sed -i 's/net.ipv6.conf.default.accept_source_route/#net.ipv6.conf.default.accept_source_route/g' /etc/sysctl.conf
sudo sed -i 's/net.ipv4.conf.all.log_martians/#net.ipv4.conf.all.log_martians/g' /etc/sysctl.conf
            
sudo echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
sudo echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
sudo echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
sudo echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
sudo echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
sudo echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
sudo echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
sudo echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
sudo echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf

sudo sysctl -p



echo "------------------------------------------------------------------------------"
echo "					FAIL2BAN"
echo "------------------------------------------------------------------------------"
sudo apt-get install -y fail2ban
sudo sed -i s/root@localhost/$username@localhost/g /etc/fail2ban/jail.conf


echo "------------------------------------------------------------------------------"
echo "					Firewall"
echo "------------------------------------------------------------------------------"
# 1. Install and configure Firewall
sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https
sudo ufw allow 10000
sudo ufw enable
sudo ufw logging on
sudo ufw status verbose 




echo "------------------------------------------------------------------------------"
echo "					PSAD"
echo "------------------------------------------------------------------------------"



sudo apt-get install -y psad
sudo cp /etc/psad/psad.conf /etc/psad/psad.conf.backup

sudo sed -i 's/ENABLE_AUTO_IDS/#ENABLE_AUTO_IDS/g' /etc/psad/psad.conf
sudo sed -i 's/EMAIL_ADDRESSES/#EMAIL_ADDRESSES/g' /etc/psad/psad.conf
sudo sed -i 's/HOSTNAME/#HOSTNAME/g' /etc/psad/psad.conf

sudo echo "HOSTNAME $(hostname);" >> /etc/psad/psad.conf
sudo echo "EMAIL_ADDRESSES  $(hostname)@localhost;" >> /etc/psad/psad.conf
sudo echo "ENABLE_AUTO_IDS Y;" >> /etc/psad/psad.conf
#sudo echo "ENABLE_AUTO_IDS_EMAILS Y;" >> /etc/psad/psad.conf

echo "# Update iptables to add log rules for PSAD"
sudo iptables -A INPUT -j LOG
sudo iptables -A FORWARD -j LOG
sudo ip6tables -A INPUT -j LOG
sudo ip6tables -A FORWARD -j LOG

sudo psad -R
sudo psad --sig-update
sudo psad -H



echo "------------------------------------------------------------------------------"
echo "					RKHunter"
echo "------------------------------------------------------------------------------"


sudo apt-get install -y rkhunter

sudo sed -i 's/CRON_DAILY_RUN=""/CRON_DAILY_RUN="true"/g' /etc/default/rkhunter
sudo sed -i 's/CRON_DB_UPDATE=""/CRON_DB_UPDATE="true"/g' /etc/default/rkhunter
sudo mv /etc/cron.weekly/rkhunter /etc/cron.weekly/rkhunter_update
sudo mv /etc/cron.daily/rkhunter /etc/cron.weekly/rkhunter_run

                              
sudo rkhunter --update
sudo rkhunter --propupd

sudo rkhunter --check --nocolors --skip-keypress




echo "------------------------------------------------------------------------------"
echo "					Logwatch"
echo "------------------------------------------------------------------------------"

sudo apt-get install -y logwatch
sudo sed -i 's/Output = stdout/Output = mail/g' /usr/share/logwatch/default.conf/logwatch.conf
sudo sed -i "s/MailTo = root/MailTo = $username/g" /usr/share/logwatch/default.conf/logwatch.conf
# sudo sed -i "s/Format = text/Format = html/g" /usr/share/logwatch/default.conf/logwatch.conf

echo "------------------------------------------------------------------------------"
echo "						END"
echo "------------------------------------------------------------------------------"

sudo apt-get update
sudo apt-get upgrade -y
sudo init 6
