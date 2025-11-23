before lab
```
cd /var
sudo mkdir esp32
cd esp32
sudo git clone https://github.com/throwaway670/boot.git
cd boot
sudo rm -rf .git
```
during 
```
cd /var/esp32/boot
ls
cat filename.py
# or xdg-open filename.py
```
after
```
history -w
sudo rm ~/.bash_history
history -c
exit
```
