#!/usr/bin/env bash
#set -x
#Written by Chike Egbuna to assist engineers to  automate most of the SSL installaton on most Linux installations.
type getenforce &> /dev/null
if [[ "$?" -ne 0 ]]; then
	state=$(getenforce)
fi
#os=$(awk -F= '/\<ID\>/{gsub(/"/,"");print $2}' /etc/os-release)
os=$(sed -n '/ID_LIKE/s/.*="\?\([^ ]*\).*/\1/p' /etc/os-release)



#Splash screen function to waste time between tasks. `Hello Engineer` takes 8 seconds alone to complete.
splash_screen() {
        local me
        local file
        #local os
        #os=$(awk -F= '/^ID=/{gsub(/"/,"");print $2}' /etc/os-release)
        #Grab user without sudo mask to set permissions for files and directories for logging
        me=$(whoami)
        file="/var/log/Chike_tools/logs"
        string="Preparing a simple tool."
        clear

        #Is python installed?
        dir="/usr/bin/python3"
        if [[ "$os" == "debian" || "$os" == "ubuntu" ]];then
                if [[ ! -d "$dir" ]];then
                        if [[ ! -f "$file" ]];then
                                sudo touch "$file"
                                echo "$file created while installing Python3" &>> /var/log/Chike_tools/logs 2>&1
                        fi
                        sudo apt -y install python3 &>> /var/log/Chike_tools/logs 2>&1
                fi
        elif [[ "$os" == "rhel" || "$os" == "centos" ]];then
                if [[ ! -d "$dir" ]];then
                        if [[ ! -f "$file" ]];then
                                sudo touch "$file"
                        fi
                        sudo yum -y install python3 &>> /var/log/Chike_tools/logs 2>&1
                fi
        fi
                echo "$string" 
                echo
                echo "Automating The BORING!!..! Stuff"
                echo
                echo 

        #Is curl installed?
        curled="/usr/bin/curl"
        if [[ "$os" == "debian" || "$os" == "ubuntu" ]];then
                if [[ ! -d "$curled" ]];then
                        sudo apt -y install curl &>> /var/log/Chike_tools/logs 2>&1
                fi
        elif [[ "$os" == "rhel" || "$os" == "centos" ]];then 
                if [[ ! -d "$curled" ]];then
                        sudo yum -y install curl &>> /var/log/Chike_tools/logs 2>&1
                fi
        fi


        
        clear
        echo "Hello $(echo $engineer_name | sed -z 's/./&\n/g')" | while read -r line; do
                printf '%s' "$line"
                sleep 1
        done &
        wait
        echo ""
        echo ""

#Embedded python script that actually delivers the splash screen. Everything else is noise
python3 <(echo "import random
import os
i = random.randrange(9) + 1
website=\"https://raw.githubusercontent.com/DanCRichards/ASCII-Art-Splash-Screen/master/art/\"+ str(i) + \".txt\"
os.system(\"curl \" +  website)") &

        echo "$(tput setaf 5)ENSURE YOU HAVE TAKEN A SNAPSHOT OF THE SYSTEM YOU ARE ABOUT TO WORK ON$(tput sgr 0)"
        echo
        log_dir="/var/log/Chike_tools/"

        #Check if log dir exist, if not create it
        if [[ ! -d "$log_dir" ]]; then
                echo "Creating log file in /var/log/Chike_tools/extend_lv.log"
                sudo mkdir /var/log/Chike_tools/
                sudo touch /var/log/Chike_tools/{extend_lv.log,create_lv.log,extend_vg.log,create_partition.log,request_cert.log,generate_csr.log,ssl_check.log,logs,raid.log,remove_raid.log}
                sudo chown -R "$me":"$me" /var/log/Chike_tools
        fi
        sleep 1
        #clear
}




check_ssl() {
        #This function will ensure prerequisites for SSL are satisfied before probing Sectigo API to issue a certificate. Malvina will need to elevate our account privileges.
        start
        read -r -p "What subdomain should be used for the SSL (do not include the .lsbu.ac.uk extension)? " domain
        echo "$(date +'%T %D'),$domain added" | awk '{gsub(/,/,"\t")}1' | sudo tee -a /var/log/Chike_tools/ssl_check.log
        local os
        os=$(awk -F= '/^ID=/{gsub(/"/,"");print $2}' /etc/os-release)

        #Check if a certificate has already been generated for this domain, if so, exit.
        check=/etc/letsencrypt/live/"$domain".lsbu.ac.uk
        if sudo test ! -d "$check" ;then

                #Check the system in use had mod_ssl, if not, install mod_ssl
                if [[ "$os" == "rhel" ]];then
                        echo "$(date +'%T %D'),$os is in use" | awk '{gsub(/,/,"\t")}1' | sudo tee -a /var/log/Chike_tools/ssl_check.log
                        echo "Now installing mod_ssl" | sudo tee -a /var/log/Chike_tools/ssl_check.log
                        sleep 1
                        sudo yum -y install httpd &>> /var/log/Chike_tools/ssl_check.log 2>&1
                        sudo yum -y install mod_ssl &>> /var/log/Chike_tools/ssl_check.log 2>&1
                        type httpd &>> /var/log/Chike_tools/ssl_check.log 2>&1

                        #If httpd is not available, then return to the menu. We cannot continue without httpd.
                        if [[ "$?" -ne 0 ]]; then
                                sudo echo "$(date +'%T %D'),httpd is not installed. Returning to Main Menu...,ERROR" | awk '{gsub(/,/,"\t")}1' | sudo tee -a /var/log/Chike_tools/ssl_check.log
                                sleep 3
                                end
                                menu
                        fi
                        sudo systemctl enable httpd --now
                        type openssl &>> /var/log/Chike_tools/ssl_check.log 2>&1
                        #check for openssl and install if not available
                        if [[ "$?" -ne 0 ]]; then
                                echo "Now installing openssl" | sudo tee -a /var/log/Chike_tools/ssl_check.log
                                sleep 1
                                sudo yum -y install openssl &>> /var/log/Chike_tools/ssl_check.log 2>&1
                                sleep 3
                                end
                                menu
                        fi
                elif [[ "$os" == "debian" || "$os" == "elementary" || "$os" == "ubuntu" ]];then
                        echo "$(date +'%T %D'),$os is in use" | awk '{gsub(/,/,"\t")}1' | sudo tee -a /var/log/Chike_tools/ssl_check.log
                        echo "Now installing mod_ssl" | sudo tee -a /var/log/Chike_tools/ssl_check.log
                        sleep 1
                        sudo apt -y install apache2 &>> /var/log/Chike_tools/ssl_check.log 2>&1
                        sudo apt -y install mod_ssl &>> /var/log/Chike_tools/ssl_check.log 2>&1
                        type apache2 &>> /var/log/Chike_tools/ssl_check.log 2>&1

                        #If apache2 is not available, then return to the menu. We cannot continue without httpd.
                        if [[ "$?" -ne 0 ]]; then
                                echo "$(date +'%T %D') apache2 is not installed. Returning to Main Menu..." | sudo tee -a /var/log/Chike_tools/ssl_check.log
                                sleep 3
                                end
                                menu
                        fi

                        sudo systemctl enable apache2 --now
                        type openssl &>> /var/log/Chike_tools/ssl_check.log 2>&1
                        #check for openssl and install if not available
                        if [[ "$?" -ne 0 ]]; then
                                echo "Now installing openssl" | sudo tee -a /var/log/Chike_tools/ssl_check.log
                                sleep 1
                                sudo apt -y install libssl-dev &>> /var/log/Chike_tools/ssl_check.log 2>&1
                                sleep 3
                                end
                                menu
                        fi
                fi
        else
                echo "$(date +'%T %D'),A SSL for this domain has already been generated. This is an error. Now returning to the menu " | awk '{gsub(/,/,"\t")}1' | sudo tee -a  /var/log/Chike_tools/ssl_check.log
                sleep 5
                end
                menu
        fi
}


#Do you like Matrix? So do I!
#This function has zero real world value, but I enjoy looking at it.
matrix() {
        # Decoration. No real value or functionality. Do not edit the code in this function orther than changing the color.
        blue="\033[0;34m"
        brightblue="\033[1;34m"
        cyan="\033[0;36m"
        brightcyan="\033[1;36m"
        green="\033[0;32m"
        brightgreen="\033[1;32m"
        red="\033[0;31m"
        brightred="\033[1;31m"
        white="\033[1;37m"
        black="\033[0;30m"
        grey="\033[0;37m"
        darkgrey="\033[1;30m"

        # Color can be changed here. Please refrain from editing anything else within the matrix function
        colors=($green $brightgreen)


        # Do not edit below this line
        spacing=${1:-100} # the likelihood of a character being left in place
        scroll=${2:-0} # 0 for static, positive integer determines scroll speed
        screenlines=$(expr `tput lines` - 1 + $scroll)
        screencols=$(expr `tput cols` / 2 - 1)

       # chars=(a b c d e f g h i j k l m n o p q r s t u v w x y z A B C D E F G H I J K L M N O P Q R S T U V W X Y Z 0 1 2 3 4 5 6 7 8 9 ^)
       # charset via Carl:
       chars=(ｱ ｲ ｳ ｴ ｵ ｶ ｷ ｸ ｹ ｺ ｻ ｼ ｽ ｾ ｿ ﾀ ﾁ ﾂ ﾃ ﾄ ﾅ ﾆ ﾇ ﾈ ﾉ ﾊ ﾋ ﾌ ﾍ ﾎ ﾏ ﾐ ﾑ ﾒ ﾓ ﾔ ﾕ ﾖ ﾗ ﾘ ﾙ ﾚ ﾛ ﾜ ﾝ)

       count=${#chars[@]}
       colorcount=${#colors[@]}

       trap "tput sgr0; clear; exit" SIGTERM SIGINT

        if [[ $1 =~ '-h' ]]; then
                echo "Display a Matrix(ish) screen in the terminal"
                echo "Usage:            matrix [SPACING [SCROLL]]"
                echo "Example:  matrix 100 0"
                exit 0
        fi


        clear
        tput cup 0 0
        #while :
        for ((i=0; i<1000; i++)); do
                for i in $(eval echo {1..$screenlines}); do
                        for i in $(eval echo {1..$screencols}); do
                                rand=$(($RANDOM%$spacing))
                                        case $rand in
                                                0)
                                                        printf "${colors[$RANDOM%$colorcount]}${chars[$RANDOM%$count]} "
                                                        ;;
                                                1)
                                                        printf "  "
                                                        ;;
                                                *)
                                                        printf "\033[2C"
                                                        ;;
                                        esac
                                done
                                printf "\n"

                                # sleep .005
                        done
                        tput cup 0 0
                done
}


gen_csr() {
        #If a manual csr is needed, this function will dynamically generate based on input entered. Run this before requesting an auto cert
        start
        read -r -p "What subdomain should the CSR use (do not include the .lsbu.ac.uk extension)? " domain
        echo "$(date +'%T %D'),CSR for $domain is preparing to generate" | awk '{gsub(/,/,"\t")}1' | sudo tee -a /var/log/Chike_tools/generate_csr.log
        #os=$(awk -F= '/^ID=/{gsub(/"/,"");print $2}' /etc/os-release)
        openssl req -new -newkey rsa:2048 -nodes -keyout "$domain".lsbu.ac.uk.key -out "$domain".lsbu.ac.uk.csr | sudo tee -a /var/log/Chike_tools/generate_csr.log 2>&1
        sudo mv  "$domain".lsbu.ac.uk.csr /etc/pki/tls/certs/
        sudo mv  "$domain".lsbu.ac.uk.key /etc/pki/tls/private/
        if [[ "$?" -eq 0 ]];then
                echo "$(date +'%T %D'),Successfully generated CSR and Private Key.,CSR located in /etc/pki/tls/certs/$domain.lsbu.ac.uk.csr,Key located in /etc/pki/tls/private/$domain.lsbu.ac.uk.key," | awk '{gsub(/,/,"\t")}1' | tee -a /var/log/Chike_tools/generate_csr.log
                sleep 2
                end
                menu
        else
                rm -f "$domain".lsbu.ac.uk.csr "$domain".lsbu.ac.uk.key
                echo "$domain.lsbu.ac.uk.csr $domain.lsbu.ac.uk.key removed due to error" | sudo tee -a /var/log/Chike_tools/generate_csr.log
                echo "$(date +'%T %D'),An ERROR has occured,CSR has not been created,please ensure a webserver is installed and running" | awk '{gsub(/,/,"\t")}1' | sudo tee -a /var/log/Chike_tools/generate_csr.log
                sleep 2
                end
                menu
        fi
}




req_cert() {
        #This function will ensure certbot and its dependencies are available before requesting a cert.
        #All credentials can be obtained from Sectigo dashboard under ACME. Elevated privileges will need to be requested to authenticate.
        #Is certbot installed?
        start
        #local os
        #os=$(awk -F= '/^ID=/{gsub(/"/,"");print $2}' /etc/os-release)
        type certbot &>> /var/log/Chike_tools/request_cert.log 2>&1
        if [[ "$?" -eq 0 ]]; then
                echo "$(date +'%T %D'),certbot is available" | awk '{gsub(/,/,"\t")}1' | sudo tee -a /var/log/Chike_tools/request_cert.log
        else
                echo "$(date +'%T %D'),installing certbot" | awk '{gsub(/,/,"\t")}1' | sudo tee -a /var/log/Chike_tools/request_cert.log

                #Install ACME certbot to automate certificates for Sectigo. Can be run on rhel or Debian based distributions.
                if [[ "$os" == "debian" || "$os" == "ubuntu" ]];then
                        sudo apt -y install software-properties-common &>> /var/log/Chike_tools/request_cert.log 2>&1
                        sudo add-apt-repository universe &>> /var/log/Chike_tools/request_cert.log 2>&1
                        sudo add-apt-repository ppa:certbot/certbot &>> /var/log/Chike_tools/request_cert.log 2>&1
                        sudo apt -y update &>> /var/log/Chike_tools/request_cert.log 2>&1
                        sudo apt -y install certbot &>> /var/log/Chike_tools/request_cert.log 2>&1
                        sudo apt install python3-certbot-apache &>> /var/log/Chike_tools/request_cert.log 2>&1
                        if [[ "$?" -ne 0 ]]; then
                                sudo apt -y install pytest python3 augeas-libs &>> /var/log/Chike_tools/request_cert.log 2>&1
                                sudo python3 -m venv /opt/certbot/ &>> /var/log/Chike_tools/request_cert.log 2>&1
                                sudo /opt/certbot/bin/pip install --upgrade pip &>> /var/log/Chike_tools/request_cert.log 2>&1
                                sudo /opt/certbot/bin/pip install certbot certbot-apache &>> /var/log/Chike_tools/request_cert.log 2>&1
                                sudo ln -s /opt/certbot/bin/certbot /usr/bin/certbot &>> /var/log/Chike_tools/request_cert.log 2>&1
                        fi
                elif [[ "$os" == "rhel" || "$os" == "centos" ]];then
                        sudo yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm &>> /var/log/Chike_tools/request_cert.log 2>&1
                        sudo yum -y install epel-release &>> /var/log/Chike_tools/request_cert.log 2>&1
                        sudo yum -y install certbot &>> /var/log/Chike_tools/request_cert.log 2>&1
			sudo yum -y install python3-certbot-apache &>> /var/log/Chike_tools/request_cert.log 2>&1
                        if [[ "$?" -ne 0 ]]; then
                                sudo yum -y install pytest python3 augeas-libs &>> /var/log/Chike_tools/request_cert.log 2>&1
                                sudo python3 -m venv /opt/certbot/ &>> /var/log/Chike_tools/request_cert.log 2>&1
                                sudo /opt/certbot/bin/pip install --upgrade pip &>> /var/log/Chike_tools/request_cert.log 2>&1
                                sudo /opt/certbot/bin/pip install certbot certbot-apache &>> /var/log/Chike_tools/request_cert.log 2>&1
                                sudo ln -s /opt/certbot/bin/certbot /usr/bin/certbot &>> /var/log/Chike_tools/request_cert.log 2>&1
                        fi
                fi
        fi
        echo "Now beginning the installation of the SSL Certificate" | sudo tee -a /var/log/Chike_tools/request_cert.log
        s="."
        x="."
        for ((i=0; i<15; i++));do
                echo "$s" | sudo tee -a /var/log/Chike_tools/request_cert.log
                s+=$x
        done
        #Automate the entire installation with certbot and Sectigo's API. Fields are pre-filled with my API credentials
        #but can be changed if needed
        read -rp "Please enter your email: " email
        read -rp "Please enter your KEY ID: " key_id
        read -rp "Please enter your HMAC KEY: " hmac_key
        read -rp "Is this a apache or nginx webserver? " webserver
        host="https://acme.sectigo.com/v2/OV"
        sudo certbot --"$webserver" --agree-tos --email "$email" --non-interactive --preferred-challenges=dns --expand --force-renewal --server "$host" --eab-kid "$key_id" --eab-hmac-key "$hmac_key" --domain "$domain".lsbu.ac.uk &>> /var/log/Chike_tools/request_cert.log 2>&1
        sudo certbot install --cert-name "$domain".lsbu.ac.uk
        if [[ "$?" -eq 0 ]];then
                #Is sendmail available?
                type mail &>> /var/log/Chike_tools/request_cert.log 2>&1
                if [[ "$?" -eq 0 ]]; then 
cat << EOF > Certificate
Hello "$engineer_name"

The OV SSL requested for "$domain".lsbu.ac.uk has been successfully generated and issued without the need of a CSR.
Please find attached the Certificate Cert, Private Key and Full Chain issued by Sectigo for $domain.lsbu.ac.uk.

If for any reason something has gone wrong with the cert being issued or an email sent without certs, please check the logs or reach out to myself (Chike Egbuna) so I can take a look and resolve the fault.

Kind regards
Linux is MUCH better than Windozz
EOF

                        if [[ "$os" == "debian" || "$os" == "ubuntu" ]];then
                                sudo mail -r "$email" -A /etc/letsencrypt/live/"$domain".lsbu.ac.uk/cert.pem -A /etc/letsencrypt/live/"$domain".lsbu.ac.uk/privkey.pem -A /etc/letsencrypt/live/"$domain".lsbu.ac.uk/chain.pem -s "CertificateFile For $domain.lsbu.ac.uk" "$email" < Certificate
                                rm -rf Certificate
                        elif [[ "$os" == "rhel" || "$os" == "centos" ]];then
                                sudo mail -r "$email" -a /etc/letsencrypt/live/"$domain".lsbu.ac.uk/cert.pem -a /etc/letsencrypt/live/"$domain".lsbu.ac.uk/privkey.pem -a /etc/letsencrypt/live/"$domain".lsbu.ac.uk/chain.pem -s "CertificateFile For $domain.lsbu.ac.uk" "$email" < Certificate
                                rm -rf Certificate
                        fi
                else
                        echo "mailx is not available"  | tee -a /var/log/Chike_tools/request_cert.log 2>&1
                fi
                #If the SSL request was successful.
                #SSL should be functional after restarting the webserver
                # All request to root will be redirected to HTTPS

                if [[ "$os" == "debian" || "$os" == "ubuntu" ]];then
                        sudo sed '/<IfModule mod_ssl.c>/,/<\/IfModule>/d' /etc/apache2/apache2.conf > /tmp/temp
                        sudo rm -rf /etc/apache2/apache2.conf
                        sudo mv /tmp/temp /etc/apache2/apache2.conf
                elif [[ "$os" == "rhel" || "$os" == "centos" ]];then        
                        sudo sed '/<IfModule mod_ssl.c>/,/<\/IfModule>/d' /etc/httpd/conf/httpd.conf > /tmp/temp
                        sudo rm -rf /etc/httpd/conf/httpd.conf
                        sudo mv /tmp/temp /etc/httpd/conf/httpd.conf
                fi
                if [[ "$(sudo iptables -S | grep -o '80')" -ne 80 ]] && [[ "$(sudo iptables -S | grep -o '443')" -ne 443 ]]; then
                        sudo iptables -I INPUT -p tcp -m tcp --dport 443 -j ACCEPT
                        sudo iptables -I INPUT -p tcp -m tcp --dport 80 -j ACCEPT
                        sudo iptables-save &>> /var/log/Chike_tools/request_cert.log 2>&1
                        echo "iptables has been updated" | sudo tee -a /var/log/Chike_tools/request_cert.log
                        if [[ "$os" == "debian" || "$os" == "ubuntu" || "$os" == "elementary" ]];then
                                echo "RewriteRule ^/$ https://%{HTTP_HOST}/ [R,L]" | sudo tee -a /etc/apache2/apache.conf
                                echo "Automatic https redirect added to apache configuration file"  | sudo tee -a /var/log/Chike_tools/request_cert.log
                        elif [[ "$os" == "rhel" ]];then
                                echo "RewriteRule ^/$ https://%{HTTP_HOST}/ [R,L]" | sudo tee -a /etc/httpd/conf/httpd.conf
                                echo "Automatic https redirect added to apache configuration file"  | sudo tee -a /var/log/Chike_tools/request_cert.log
                        fi
                fi
                if [[ "$os" == "debian" || "$os" == "ubuntu" ]];then
                        sudo systemctl restart apache2 &>> /var/log/Chike_tools/request_cert.log 
                        if [[ "$?" -eq 0 ]];then
                                echo "Webserver has started successfully" | sudo tee -a /var/log/Chike_tools/request_cert.log
                                echo "Sectigo SSL has successfully been generated for $domain.lsbu.ac.uk. Now restarting the webserver, if any errors are encountered, please check the logs in $(tput setaf 6)/var/log/Chike_tools/$(tput sgr 0)" 
                                sleep 5
                                end
                                menu
                        else
                                echo "An error has occured while restarting the webserver. Please check the logs" | sudo tee -a /var/log/Chike_tools/request_cert.log
                                echo "The certificate has been issued and will be active once the error has been resolved and the webserver restarted with sudo systemctl restart httpd"
                                sleep 5
                                end
                                menu
                        fi
                elif [[ "$os" == "rhel" || "$os" == "centos" ]];then
                        sudo systemctl restart httpd &>> /var/log/Chike_tools/request_cert.log 
                        if [[ "$?" -eq 0 ]];then
                                echo "Webserver has started successfully" | sudo tee -a /var/log/Chike_tools/request_cert.log
                                echo "Sectigo SSL has successfully been generated for $domain.lsbu.ac.uk. Now restarting the webserver, if any errors are encountered. Be sure to check the syntax" 
                                echo "Please enter this command;"
                                echo "$(tput setaf 2)sudo certbot install --cert-name "$domain".lsbu.ac.uk $(tput sgr0)"
                                echo "to finalise the SSL installation"
                                sleep 8
                        else
                                echo "An error has occured while restarting the webserver. Please check the logs" | sudo tee -a /var/log/Chike_tools/request_cert.log
                                echo "The certificate has been issued and will be active once the error has been resolved and the webserver restarted with sudo systemctl restart httpd"
                        fi
                        sleep 8
                        end
                        menu
                fi
        else
                echo "SSL installation has failed. Please check the ACME Sectigo credentials and ensure you have the correct level of authentication to auto SSL provisioning" | sudo tee -a /var/log/Chike_tools/request_cert.log
                sleep 8
                end
                menu
        fi
}




part() {
        #Not sure how much this tool will be needed but may be useful
        #Will find unused drives and offer them for partitioning. Only ext4 and xfs fs are currently available.
        start
        local auto

        #This nifty variable will dynamically remove used drives that are offered during configuration.Took me a good 30 minutes to write this single line.
        auto=$(diff <(diff <(lsblk -io KNAME | awk '/sd[a-z][0-9]/{gsub(/[0-9]/,"");print}') <(lsblk | awk '$NF!~/\/[a-z]|[[:punct:]]/ && NR != 1 && $1 !~ /[a-z][0-9]/{print $1}') | awk -F">" '/>/{sub(/ /,"");print $2}') <(sudo pvdisplay | awk '/\/dev\/sd[a-z]/ {gsub(/\/dev\//,"");gsub(/[0-9]/,"");print $NF}') | awk -F"<" '/</{sub(/ /,"");print $2}' | sed '/[[:punct:]]/d')
        sysfs="/sys/dev/block"
        if [[ -d "$sysfs" ]];then

                #There is an embedded script at the end before the variable that gives the list format when displaying drives
                read -rp "Please enter the drive to be used from this list of unused drives on the system; $(echo; while read -r line; do echo "/dev/$line"; done <<< "$auto"; echo Selection):" drive
                local max
                max=$(lsblk | awk -v max="${drive:5:3}" '$1==max {print $4}')
                echo "There is $max available on this drive. What size would you like the partiton to be? "
                echo "1) Maximum Available size"
                echo "2) Custom size"
                read -rp ": " part_size
                if [[ "$part_size" -eq 1 ]];then
                        echo "Creating partition $drive" | sudo tee -a /var/log/Chike_tools/create_partition.log
                        sudo parted --script "$drive" \
                                mklabel gpt \
                                mkpart primary 0.00G "$max" &>> /var/log/Chike_tools/create_partition.log 2>&1
                                local temp
                                temp=$max
                elif [[ "$part_size" -eq 2 ]];then
                        read -rp "Please enter the size: " partSize
                        echo "Creating partition $drive" | sudo tee -a /var/log/Chike_tools/create_partition.log
                        sudo parted --script "$drive" \
                                mklabel gpt \
                                mkpart primary 0.00G "$partSize" &>> /var/log/Chike_tools/create_partition.log 2>&1
                fi
                if [[ "$?" -eq 0 ]];then
                        echo "$(date +'%T %D'),$drive partition has been created." | awk '{gsub(/,/,"\t")}1' | sudo tee -a /var/log/Chike_tools/create_partition.log
                        read -rp "What filesystem should $drive use (ext4, xfs)?: " fs
                        if [[ $fs == "xfs" ]];then
                                sudo mkfs.xfs "$drive"1 | tee -a /var/log/Chike_tools/create_partition.log 2>&1
                        elif [[ $fs == "ext4" ]];then
                                sudo mkfs.ext4 "$drive"1 | sudo tee -a /var/log/Chike_tools/create_partition.log 2>&1
                        fi
                        if [[ "$?" -eq 0 ]]; then
                                read -rp "Should $drive be mounted now? Y|N: " ans
                                if [[ $ans == "Y" ]] || [[ $ans == "y" ]]; then
                                        read -rp "Please provide the directory tree name you would like to mount to e.g /var/lib/mysql: " mount_dir
                                        sudo mkdir -p "$mount_dir" | sudo tee -a /var/log/Chike_tools/create_partition.log 2>&1
                                        sudo mount -o rw "$drive"1 "$mount_dir" | sudo tee -a /var/log/Chike_tools/create_partition.log 2>&1
                                        local drive_id
                                        drive_id=$(sudo blkid | grep "$drive" | sed -n "s|.*\<UUID=.\([^\"]*\).*|UUID=\1|p")
                                        echo "$drive_id  $mount_dir             $fs    defaults       0 0 " | sudo tee -a /etc/fstab
                                        echo "$drive has now been mounted to $mount_dir" | sudo tee -a /var/log/Chike_tools/create_partition.log
                                        sleep 1
                                        end
                                        menu
                                else
                                        echo "$drive has not been mounted but is now available. " | sudo tee -a /var/log/Chike_tools/create_partition.log
                                        sleep 1
                                        end
                                        menu
                                fi
                        else
                                echo "An ERROR occured, $drive has not been allocated a filesystem" | sudo tee -a /var/log/Chike_tools/create_partition.log
                                sleep 1
                                end
                                menu
                        fi
                else
                        echo "$(date +'%T %D'),An Error has occured,$drive has not been created " | awk '{gsub(/,/,"\t")}1' | sudo tee -a /var/log/Chike_tools/create_partition.log
                        sleep 1
                        end
                        menu
                fi
        else
                echo "System not compatable. Is this WSL2? There is an issue with sysfs" | sudo tee -a /var/log/Chike_tools/create_partition.log
                sleep 1
                end
                menu
        fi
}





extend_vg() {
        #This function will extend an existing Volume group. It will automatically find any VG on the system.
        start
        local auto

        #This nifty variable will dynamically remove used drives that are offered during configuration.Took me a good 30 minutes to write this single line.
        auto=$(diff <(diff <(lsblk -io KNAME | awk '/sd[a-z][0-9]/{gsub(/[0-9]/,"");print}') <(lsblk | awk '$NF!~/\/[a-z]|[[:punct:]]/ && NR != 1 && $1 !~ /[a-z][0-9]/{print $1}') | awk -F">" '/>/{sub(/ /,"");print $2}') <(sudo pvdisplay | awk '/\/dev\/sd[a-z]/ {gsub(/\/dev\//,"");gsub(/[0-9]/,"");print $NF}') | awk -F"<" '/</{sub(/ /,"");print $2}' | sed '/[[:punct:]]/d') 
        local max
        max=$(lsblk | awk -v max="${drive:5:3}" '$1==max {print $4}')
        local vg
        vg=$(sudo vgdisplay | awk '/VG Name/{print $NF}')
        local free_space
        free_space=$(sudo vgs | awk -v vg="$vg" '$1~vg{sub(/[[:punct:]]/,".");print $NF}')
        echo "There is $free_space free space available on $vg." | sudo tee -a /var/log/Chike_tools/extend_vg.log

        #There is an embedded script at the end before the variable that gives the list format hen displaying drives
        read -rp "Please enter the drive to be used to extend the volume group. Here is a list of unused drives; $(echo ; while read -r line; do echo "/dev/$line"; done <<< "$auto"; echo Selection):" drive
        sudo pvcreate "$drive" &>> /var/log/Chike_tools/extend_vg.log 2>&1
        sudo vgextend "$vg" "$drive" &>> /var/log/Chike_tools/extend_vg.log 2>&1
        if [[ "$?" -eq 0 ]];then
                echo "$(date +'%T %D'),Volume Group $vg has successfully been extended with partition $drive." | awk '{gsub(/,/,"\t")}1' | sudo tee -a /var/log/Chike_tools/extend_vg.log
                sleep 3
                end
                menu
        else
                echo "$(date +'%T %D'),ERROR, Volume Group $vg was not extended." | awk '{gsub(/,/,"\t")}1' | sudo tee -a /var/log/Chike_tools/extend_vg.log
                sleep 3
                end
                menu
        fi
}





extend_lv() {
        #This function will extend logical volumes. It will also find all LVs and give you the choice which to expand.
        start
        local auto
        auto=$(sudo lvs | awk 'NR>1{print $1, $4}' | column -t)
        local vg
        vg=$(sudo vgdisplay | awk '/VG Name/{print $NF}')
        local free_space
        #free_space=$(sudo vgs | awk -v vg="$vg" '$1~vg{gsub(/</,"");print $7}')
        free_space=$(sudo vgs | awk -v vg="$vg" '$1~vg{sub(/[[:punct:]]/,".");print $NF}')
        echo "There is $free_space free space available on $vg. Ensure there is adequate space on $vg VG before proceeding with extending" | sudo tee -a /var/log/Chike_tools/extend_lv.log

        read -rp "Please enter the Logical Volume you wish to extend $(echo; while read -r line; do echo "$line"; done <<< "$auto"; echo Selection): " drive
        read -rp "What size would you like to extend the Logical Volume $drive by i.e 100M, 100G, 1T? " size
        local extend
        extend=/dev/"$vg"/"$drive"

        if [[ ! -h "$extend" ]];then
                echo "$(date +'%T %D'),LVM cannot be found,Aborting,ERROR" | awk '{gsub(/,/,"\t")}1' | sudo tee -a /var/log/Chike_tools/extend_lv.log
                sleep 2
                end
                menu
        else
                echo "$(date +'%T %D'),$drive$vg created,SUCCESS" | sudo awk '{gsub(/,/,"\t")}1' | sudo tee -a /var/log/Chike_tools/extend_lv.log
                sudo lvextend -L "$size" /dev/"$vg"/"$drive" -r | sudo tee -a /var/log/Chike_tools/extend_lv.log 2>&1
        fi

        echo "Y) Menu"
        echo "*) Exit"
        read -rp "Logical Volume has been successfully extended. Would you like to exit or go back to the menu? " leave

        if [[ "$leave" == "Y" ]] || [[ "$leave" == "y" ]];then
                sleep 2
                end
                menu
        else
                sleep 2
                echo "Exiting..."
                end
                exit 0
        fi
}





create_lv() {
        #This function creates new logical volumes. It will request all the info it needs to successfully create an LV
        start
        local auto
        auto=$(sudo lvs | awk 'NR>1{print $1, $4}' | column -t)
        local vg
        vg=$(sudo vgdisplay | awk '/VG Name/{print $NF}')
        local free_space
        free_space=$(sudo vgs | awk -v vg="$vg" '$1~vg{gsub(/</,"");print $7}')
        echo "There is $free_space free space available on this system to create a Logical Volume with."
        read -rp "Please enter the name you wish to use for the Logical Volume: " drive
        read -rp "What size would you like the Logical Volume to be e.g 100M, 5G, 1T? " size
        read -rp "Where do you want to mount point e.g /var/log/custom? " mount_point

        #Now all data has been collected, the function will now create the LV and filesystem of choice.
        sudo lvcreate -n "$drive" -L "$size" "$vg" &>> /var/log/Chike_tools/create_lv.log 2>&1
        if [[ "$?" -eq 0 ]]; then
        read -rp "What filesystem should $drive use (ext4, xfs)?: " fs2
                if [[ "$fs2" == "xfs" ]];then
                        sudo mkfs.xfs /dev/"$vg"/"$drive" | sudo tee -a /var/log/Chike_tools/create_lv.log 2>&1
                elif [[ "$fs2" == "ext4" ]];then
                        sudo mkfs.ext4 /dev/"$vg"/"$drive" | sudo tee -a /var/log/Chike_tools/create_lv.log 2>&1
                fi

                #It will now be mounted to the location specified by the engineer.
                sudo mkdir -p "$mount_point"
                sudo mount -o rw /dev/"$vg"/"$drive" "$mount_point" &>> /var/log/Chike_tools/create_lv.log 2>&1
                if [[ "$?"  -eq 0 ]]; then
                        local drive_id
                        drive_id=$(sudo blkid | grep "$drive" | sed -n "s|.*\<UUID=.\([^\"]*\).*|UUID=\1|p")
                        echo "$drive_id  $mount_point             $fs2    defaults       0 0 " | sudo tee -a /etc/fstab
                        #echo "$drive $(pwd)/$mount_point    $fs2    defaults    0 0 " | sudo tee -a /etc/fstab
                        echo "$(date +'%T %D'),/dev/$vg/$drive Logical Volume Created,Mounted at $mount_point,/dev/$vg/$drive is $size " | awk '{gsub(/,/,"\t")}1' | sudo tee -a /var/log/Chike_tools/create_lv.log
                        echo "Y) Menu"
                        echo "*) Exit"
                        read -rp "Logical Volume created and mounted. Would you like to exit or go back to the menu? " leave
                        if [[ "$leave" == "Y" ]] || [[ "$leave" == "y" ]];then
                                end
                                menu
                        else
                                end
                                exit 0
                        fi
                else
                        echo "$(date +'%T %D') An error occured, partition /dev/$vg/$drive has not been mounted." | sudo tee -a /var/log/Chike_tools/create_lv.log
                        sleep 2
                        end
                        menu
                fi
        else
                echo "$(date +'%T %D') An error occured, Logical volume /dev/$vg/$drive has not been created." | sudo tee -a /var/log/Chike_tools/create_lv.log
                sleep 2
                end
                menu
        fi
}



menu() {
        #This function is the menu. The code for the display is ugly and fragile but works for the purpose needed.
        #There is a call to the splash screen function first to waste time before offering options. This will eventually become annoying.
        splash_screen "$@"
        #This is the main menu instead of using a case loop.
        echo
        echo

        #If customizing the script, bear in mind even the addition of a single space will break the format of the menu.
        #A case loop can easily replace this but the pretty format will be lost.
        echo "1) Create Partition From Empty Drive
2) Extending Volume Groups
3) Add/Del Logical Volumes
4) RAID
5) CA SSL
6) Gen CSR 
7) Matrix
8) User Management
*) Exit" | pr -3T -s"      " | sed -E '2,$s/([0-9]\) [^0-9]*)([0-9]\)[^[:punct:]0-9]*)(.*)/\1          \2    \3/'
        read -rp "Please enter a number [1-8]: " tool
        if [[ "$tool" -eq 1 ]];then
                part
        elif [[ "$tool" -eq 2 ]];then
                extend_vg
        elif [[ "$tool" -eq 3 ]];then
                lv
        elif [[ "$tool" -eq 4 ]];then
                raided
        elif [[ "$tool" -eq 5 ]];then
                check_ssl
                req_cert
        elif [[ "$tool" -eq 6 ]];then
                gen_csr
        elif [[ "$tool" -eq 7 ]];then
                matrix
        elif [[ "$tool" -eq 8 ]];then
                users
        else
                echo "exiting......"
                sleep 1
                clear
                end
                exit 0
        fi
}

lv() {
        
        echo "1) Create Logical Volume
2) Extend Logical Volume
3) Return To Menu
*) Exit" | pr -3T -s"      " 
        read -rp "Please enter a number [1-3]: " tool

        if [[ "$tool" -eq 1 ]];then
                create_lv
        elif [[ "$tool" -eq 2 ]];then
                extend_lv
        elif [[ "$tool" -eq 3 ]];then
                menu
        else
                echo "exiting......"
                sleep 1
                clear
                end
                exit 0
        fi
}

raided() {
       
        echo
        echo

        #If customizing the script, bear in mind even the addition of a single space will break the format of the menu.
        #A case loop can easily replace this but the pretty format will be lost.
        echo "1) Create RAID Array
2) Delete RAID array
3) Return to Menu
*) Exit" | pr -3T -s"      " 
        read -rp "Please enter a number [1-3]: " tool

        if [[ "$tool" -eq 1 ]];then
                raid
        elif [[ "$tool" -eq 2 ]];then
                remove_raid
        elif [[ "$tool" -eq 3 ]];then
                menu
        else
                echo "exiting......"
                sleep 1
                clear
                end
                exit 0
        fi
}

users() {
       
        echo
        echo

        #If customizing the script, bear in mind even the addition of a single space will break the format of the menu.
        #A case loop can easily replace this but the pretty format will be lost.
        echo "1) Add Users
2) Delete Users
3) Return to Menu
*) Exit" | pr -3T -s"      " 
        read -rp "Please enter a number [1-3]: " tool

        if [[ "$tool" -eq 1 ]];then
                add_users
        elif [[ "$tool" -eq 2 ]];then
                del_users
        elif [[ "$tool" -eq 3 ]];then
                menu
        else
                echo "exiting......"
                sleep 1
                clear
                end
                exit 0
        fi
}

start() {
        #If SELINUX is in enforcing mode, this will cause strange behaviour in some functions, to avoid that, it is temporaily put into permissive mode while a function executes. All functions will finish with `end` function to reinstate the enforcing state.
        if [[ "$state" == "Enforcing" ]]; then
                sudo sed 's/\([^=]*=\)enforcing/\1permissive/' /etc/sysconfig/selinux > /tmp/temp
                sudo rm -rf /etc/sysconfig/selinux
                sudo mv /tmp/temp /etc/sysconfig/selinux
        fi
}

end() {
        #If SELINUX was in enforcing mode, this will revert it back to its original state when a function has executed.
        if [[ "$state" == "Enforcing" ]]; then
                sudo sed 's/\([^=]*=\)permissive/\1enforcing/' /etc/sysconfig/selinux > /tmp/temp
                sudo rm -rf /etc/sysconfig/selinux
                sudo mv /tmp/temp /etc/sysconfig/selinux
        fi
}

raid() {
        start
        lsblk -o KNAME,SIZE > raid



        diff <(diff <(lsblk -io KNAME | awk '/sd[a-z][0-9]/{gsub(/[0-9]/,"");print}') <(lsblk | awk '$NF!~/\/[a-z]|[[:punct:]]/ && NR != 1 && $1 !~ /[a-z][0-9]/{print $1}') | awk -F">" '/>/{sub(/ /,"");print $2}') <(sudo pvdisplay | awk '/\/dev\/sd[a-z]/ {gsub(/\/dev\//,"");gsub(/[0-9]/,"");print $NF}') | awk -F"<" '/</{sub(/ /,"");print $2}' | sed '/[[:punct:]]/d' > orig

        raid_drives=$(awk 'FNR==NR{a[$1]=$2;next}{print $1, a[$1]}' raid orig)

        echo "RAID is best set up with drives of similar sizes. If drives are not the same size, you can partition them first and then create the RAID device"
        read -rp "What level of RAID would you like to add (0, 1, 5 or 6)? " raid_level
        if [[ "$raid_level" -eq 0 ]];then
                echo "Checking at least 2 empty drives exist to create the array"
                echo "NOTE: There is no redundancy offered with RAID 0 except performance gain. Consider RAID 1"
                emp_drives=$(printf '%s %s\n' "$raid_drives" | wc -l)
                if [[ "$emp_drives" -ge 2 ]]; then
                        echo "There are at least 2 empty drives available."
                        echo "Here is a list of the available drives"
                        printf '%s %s\n' "$raid_drives"
                        read -rp "Please select the first drive from the first column list e.g sdb: " drive1
                        read -rp "Please select the second drive from the first column list e.g sdc: " drive2
                        read -rp "What should the name of the RAID array be e.g md0? " raid_name
                        read -rp "What filesystem should be used? xfs or ext4: " fs
                        read -rp "Please provide the directory tree name you would like to mount to e.g /var/lib/mysql: " mnt_dir
                        #Is mdadm available?
                        type mdadm &>> logs
                        if [[ "$?" -eq 0 ]]; then
                                sudo mdadm --create --verbose /dev/md/"$raid_name" --level="$raid_level" --raid-devices=2 /dev/"$drive1" /dev/"$drive2"
                                sudo cat /proc/mdstat
                                sleep 3
                        else
                                sudo yum -y install mdadm &>> logs
                                sudo mdadm --create --verbose /dev/md/"$raid_name" --level="$raid_level" --raid-devices=2 /dev/"$drive1" /dev/"$drive2"
                                sudo cat /proc/mdstat
                                sleep 3
                        fi
                        sudo mkfs."$fs" /dev/md/"$raid_name"
                        sudo mkdir -p $mnt_dir
                        sudo mount /dev/md/"$raid_name" "$mnt_dir"

                        #Ensure array is reassembled during boot
                        sudo mdadm --detail --scan | sudo tee -a /etc/mdadm/mdadm.conf
                        sudo update-initramfs -u
                        echo "/dev/md/$raid_name $mnt_dir ext4 defaults,nofail,discard 0 0" | sudo tee -a /etc/fstab
                        sleep 2
                        end
                        menu
                else
                        echo "There are not enough available drives to create this array."
                        echo "This is a FATAL error. Returning to menu"
                        sleep 2
                        end
                        menu
                fi
        elif [[ "$raid_level" -eq 1 ]];then
                echo "Checking at least 2 empty drives exist to create the array"
                echo "NOTE: You will lose half of your available storage but will gain redundancy if a drive should fail"
                emp_drives=$(printf '%s %s\n' "$raid_drives" | wc -l)
                if [[ "$emp_drives" -ge 2 ]]; then
                        echo "There are at least 2 empty drives available."
                        echo "Here is a list of the available drives"
                        printf '%s %s\n' "$raid_drives"
                        read -rp "Please select the first drive from the first column list e.g sdb: " drive1
                        read -rp "Please select the second drive from the first column list e.g sdc: " drive2
                        read -rp "What should the name of the RAID array be e.g md0? " raid_name
                        read -rp "What filesystem should be used? xfs or ext4: " fs
                        read -rp "Please provide the directory tree name you would like to mount to e.g /var/lib/mysql: " mnt_dir
                        #Is mdadm available?
                        type mdadm &>> logs
                        if [[ "$?" -eq 0 ]]; then
                                sudo mdadm --create --verbose /dev/md/"$raid_name" --level="$raid_level" --raid-devices=2 /dev/"$drive1" /dev/"$drive2"
                                sudo cat /proc/mdstat
                                sleep 3
                        else
                                sudo yum -y install mdadm &>> logs
                                sudo mdadm --create --verbose /dev/md/"$raid_name" --level="$raid_level" --raid-devices=2 /dev/"$drive1" /dev/"$drive2"
                                sudo cat /proc/mdstat
                                sleep 3
                        fi
                        sudo mkfs."$fs" /dev/md/"$raid_name"
                        sudo mkdir -p $mnt_dir
                        sudo mount /dev/md/"$raid_name" "$mnt_dir"

                        #Ensure array is reassembled during boot
                        sudo mdadm --detail --scan | sudo tee -a /etc/mdadm/mdadm.conf
                        sudo update-initramfs -u
                        echo "/dev/md/$raid_name $mnt_dir ext4 defaults,nofail,discard 0 0" | sudo tee -a /etc/fstab
                        sleep 2
                        end
                        menu
                else
                        echo "There are not enough available drives to create this array."
                        echo "This is a FATAL error. Returning to menu"
                        sleep 2
                        end
                        menu
                fi
        elif [[ "$raid_level" -eq 5 ]];then
                echo "Checking at least 3 empty drives exist to create the array"
                echo "NOTE: There is no redundancy offered with RAID 0 except performance gain. Consider RAID 1"
                emp_drives=$(printf '%s %s\n' "$raid_drives" | wc -l)
                if [[ "$emp_drives" -ge 3 ]]; then
                        echo "There are at least 3 empty drives available."
                        echo "Here is a list of the available drives"
                        printf '%s %s\n' "$raid_drives"
                        read -rp "Please select the first drive from the first column list e.g sdb: " drive1
                        read -rp "Please select the second drive from the first column list e.g sdc: " drive2
                        read -rp "Please select the third drive from the first column list e.g sdd: " drive3
                        read -rp "What should the name of the RAID array be e.g md0? " raid_name
                        read -rp "What filesystem should be used? xfs or ext4: " fs
                        read -rp "Please provide the directory tree name you would like to mount to e.g /var/lib/mysql: " mnt_dir
                        #Is mdadm available?
                        type mdadm &>> logs
                        if [[ "$?" -eq 0 ]]; then
                                sudo mdadm --create --verbose /dev/md/"$raid_name" --level="$raid_level" --raid-devices=3 /dev/"$drive1" /dev/"$drive2" /dev/"$drive3"
                                sudo cat /proc/mdstat
                                sleep 3
                        else
                                sudo yum -y install mdadm &>> logs
                                sudo mdadm --create --verbose /dev/md/"$raid_name" --level="$raid_level" --raid-devices=3 /dev/"$drive1" /dev/"$drive2"
                                sudo cat /proc/mdstat
                                sleep 3
                        fi
                        sudo mkfs."$fs" /dev/md/"$raid_name"
                        sudo mkdir -p $mnt_dir
                        sudo mount /dev/md/"$raid_name" "$mnt_dir"

                        #Ensure array is reassembled during boot
                        sudo mdadm --detail --scan | sudo tee -a /etc/mdadm/mdadm.conf
                        sudo update-initramfs -u
                        echo "/dev/md/$raid_name $mnt_dir ext4 defaults,nofail,discard 0 0" | sudo tee -a /etc/fstab
                        sleep 2
                        end
                        menu
                else
                        echo "There are not enough available drives to create this array."
                        echo "This is a FATAL error. Returning to menu"
                        sleep 2
                        end
                        menu
                fi
        elif [[ "$raid_level" -eq 6 ]];then
                echo "Checking at least 4 empty drives exist to create the array"
                echo "NOTE: There is no redundancy offered with RAID 0 except performance gain. Consider RAID 1"
                emp_drives=$(printf '%s %s\n' "$raid_drives" | wc -l)
                if [[ "$emp_drives" -ge 4 ]]; then
                        echo "There is at least 4 empty drives available."
                        echo "Here is a list of the available drives"
                        printf '%s %s\n' "$raid_drives"
                        read -rp "Please select the first drive from the first column list e.g sdb: " drive1
                        read -rp "Please select the second drive from the first column list e.g sdc: " drive2
                        read -rp "Please select the third drive from the first column list e.g sdc: " drive3
                        read -rp "Please select the fourth drive from the first column list e.g sdc: " drive4
                        read -rp "What should the name of the RAID array be e.g md0? " raid_name
                        read -rp "What filesystem should be used? xfs or ext4: " fs
                        read -rp "Please provide the directory tree name you would like to mount to e.g /var/lib/mysql: " mnt_dir
                        #Is mdadm available?
                        type mdadm &>> logs
                        if [[ "$?" -eq 0 ]]; then
                                sudo mdadm --create --verbose /dev/md/"$raid_name" --level="$raid_level" --raid-devices=4 /dev/"$drive1" /dev/"$drive2" /dev/"$drive3" /dev/"$drive4"
                                sudo cat /proc/mdstat
                                sleep 3
                        else
                                sudo yum -y install mdadm &>> logs
                                sudo mdadm --create --verbose /dev/md/"$raid_name" --level="$raid_level" --raid-devices=4 /dev/"$drive1" /dev/"$drive2"
                                sudo cat /proc/mdstat
                                sleep 3
                        fi
                        sudo mkfs."$fs" /dev/md/"$raid_name"
                        sudo mkdir -p $mnt_dir
                        sudo mount /dev/md/"$raid_name" "$mnt_dir"

                        #Ensure array is reassembled during boot
                        sudo mdadm --detail --scan | sudo tee -a /etc/mdadm/mdadm.conf
                        sudo update-initramfs -u
                        echo "/dev/md/$raid_name $mnt_dir ext4 defaults,nofail,discard 0 0" | sudo tee -a /etc/fstab
                        sleep 2
                        end
                        menu
                else
                        echo "There are not enough available drives to create this array."
                        echo "This is a FATAL error. Returning to menu"
                        sleep 2
                        end
                        menu
                fi
        fi
        rm -f raid orig
}

remove_raid() {
        echo "Please select the RAID array you will like to remove" | sudo tee -a /var/log/Chike_tools/remove_raid.log 2>&1
        echo "NOTE: This process will completely destroy the array and any data written to it. Make sure that you are operating on the correct array and that you have copied off any data you need to retain prior to destroying the array." | sudo tee -a /var/log/Chike_tools/remove_raid.log 2>&1
        echo "Would you like to continue? " 
        echo "Y"
        echo "N"
        read -rp "Selection: " destroy 
        if [[ $destroy == "Y" ]] || [[ $destroy == "y" ]]; then
                sudo cat /proc/mdstat &>>  /var/log/Chike_tools/remove_raid.log 2>&1

                #Unmount the array from filesystem
                read -rp "Please select the array to remove e.g md0, md89, md126: " rem_array
                sudo umount /dev/"$rem_array" &>>  /var/log/Chike_tools/remove_raid.log 2>&1

                #Now stop and remove the array
                sudo mdadm --stop /dev/"$rem_array" &>>  /var/log/Chike_tools/remove_raid.log 2>&1
                sudo mdadm --remove /dev/"$rem_array" &>>  /var/log/Chike_tools/remove_raid.log 2>&1

                #Find arrays drives
                remove=$(lsblk -o KNAME,FSTYPE | grep -B1 "rem_array" | awk '$1~/sd/{print $1}')

                #Run through list of found drives to zero their superblocks and reset to normal
                for line in "$remove"; do
                sudo mdadm --zero-superblock /dev/"$line" &>>  /var/log/Chike_tools/remove_raid.log 2>&1
                done

                #Edit fstab and cleanup
                sudo sed '/,nofail,discard/{s/^/#/}' /etc/fstab > /tmp/tempfile
                sudo rm -rf /etc/fstab
                sudo mv /tmp/tempfile /etc/fstab
        else
                echo "Operation has been aborted. Returning to the menu"
                sleep 2
                end
                menu
        fi
}

add_users() {
        start
        #local os
        #os=$(awk -F= '/^ID=/{gsub(/"/,"");print $2}' /etc/os-release)
        if [[ "$os" == "debian" || "$os" == "ubuntu" ]];then
                read -rp "Please enter a list of users seperated by a comma that you would like to add: " user_list
                read -rp "What shell would you like the users to use .e.g bash, sh, zsh? " shell
                read -rp "What password would you like to set for the user? " password
                sudo sed 's/\([^,]*\),/\1\n/g' <<< $user_list > list.chiketool
                while read -r user; do 
	                sudo useradd -m -p $(openssl passwd -1 "$password") --shell /bin/"$shell" "$user" 
	                #sudo echo "$user:$password" | chpasswd
	                echo "$user has been added to the system with a $shell shell"
                done < list.chiketool
                read -rp "Should the user have sudo/root access? " access
                if [[ "$access" == "Y" || "$access" == "y" || "$access" == "yes" || "%access" == "Yes" ]];then
	                while read -r user1; do
		                sudo usermod -aG sudo "$user1"
		                echo "$user1 has successfully been added to the sudo group"
	                done < list.chiketool
	                rm -rf list.chiketool
                        sleep 3
                        clear
                        end
                        menu
                else
	                rm -rf list.chiketool
                        sleep 3
                        clear
                        end
                        menu
                fi
        elif [[ "$os" == "rhel" || "$os" == "centos" ]]; then
                read -rp "Please enter a list of users seperated by a comma that you would like to add: " user_list
                read -rp "What shell would you like the users to use .e.g bash, sh, zsh? " shell
                read -rp "What password would you like to set for the user? " password
                sudo sed 's/\([^,]*\),/\1\n/g' <<< $user_list > list.chiketool
                while read -r user; do 
	                sudo adduser -m --shell /bin/"$shell" "$user" 
	                sudo echo "$user:$password" | chpasswd
	                echo "$user has been added to the system with a $shell shell"
                done < list.chiketool
                read -rp "Should the user have sudo/root access? " access
                if [[ "$access" == "Y" || "$access" == "y" || "$access" == "yes" || "%access" == "Yes" ]];then
	                while read -r user1; do
		                sudo usermod -aG wheel "$user1"
		                echo "$user1 has successfully been added to the wheel group"
	                done < list.chiketool
	                rm -rf list.chiketool
                        sleep 3
                        clear
                        end
                        menu
                else
	                rm -rf list.chiketool
                        sleep 3
                        clear
                        end
                        menu
                fi
        fi
}

del_users() {
        getent passwd | awk -F: '$3 >= 1000{print $1,cnt++}' | column -t
        read -rp "Please enter the a list seperated by a comma of the number corresponding to the user you wish to remove: " user_del_list
	sudo sed 's/\([^,]*\),/\1\n/g' <<< "$user_del_list" > del_list.chiketool
	while read -r user; do
		if [[ "$user" -eq 0 ]]; then
			echo "Cannot remove this user, please select another"
			del_users
		elif [[ "$user" -gt 0 ]]; then
        		getent passwd | awk -F: '$3 >= 1000{print $1,cnt++}' | column -t | sudo sed -n "$((user_del_list+1))s/\([^ ]*\).*/userdel -r \1/pe" #&> /dev/null
		else
			echo "Cannot remove this user, please select another"
			del_users
		fi
	done < del_list.chiketool
	rm -f del_list.checklist
        sleep 3
        clear
        end
        menu
}





#Additonal functionality and features can easily be added. Feel free to ask me if there is a feature you feel may be needed in this script.

"$@"
if [[ $engineer_name =~ [a-z] ]]; then
        menu
else
        clear
        echo "Hello Engineer."
        read -rp "What is your name? " engineer_name
        menu 
fi
