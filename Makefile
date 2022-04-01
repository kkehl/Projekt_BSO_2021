.PHONY: install
install:
	sudo mkdir /usr/local/share/antivirus2021
	sudo cp -R include /usr/local/include/antivirus2021
	sudo cp -R src /usr/local/src/antivirus2021
	sudo cp -R tests /usr/local/share/antivirus2021
	sudo cp -R viruses /usr/local/share/antivirus2021
	sudo cp statsChild.txt /usr/local/share/antivirus2021/statsChild.txt
	sudo cp statsParent.txt /usr/local/share/antivirus2021/statsParent.txt
	sudo chown root:root /usr/local/share/antivirus2021/statsChild.txt
	sudo chmod 600 /usr/local/share/antivirus2021/statsChild.txt
	sudo chown root:root /usr/local/share/antivirus2021/statsParent.txt
	sudo chmod 600 /usr/local/share/antivirus2021/statsParent.txt
	sudo cp pid.txt /usr/local/share/antivirus2021/pid.txt
	sudo chown root:root /usr/local/share/antivirus2021/pid.txt
	sudo chmod 600 /usr/local/share/antivirus2021/pid.txt
	sudo cp database.txt /usr/local/share/antivirus2021/database.txt
	sudo chown root:root /usr/local/share/antivirus2021/database.txt
	sudo chmod 600 /usr/local/share/antivirus2021/database.txt
	mkdir /usr/local/src/antivirus2021/obj || true
	cd /usr/local/src/antivirus2021 && make
	sudo chown root:root /usr/local/bin/av
	sudo chmod 700 /usr/local/bin/av
  
.PHONY: uninstall
uninstall:  
	cd src && sudo make clean  
	sudo rm -r /usr/local/share/antivirus2021
	sudo rm -r /usr/local/include/antivirus2021
	sudo rm -r /usr/local/src/antivirus2021
