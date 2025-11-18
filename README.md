```
cd /var
sudo mkdir esp32
cd esp32
sudo git clone https://github.com/throwaway670/boot.git
cd boot
sudo rm -rf .git
sudo find . -type f -exec touch {} ;
sudo touch .
sudo grep -R "git" .
#delete any git inside /var/esp32/
sudo rm ~/.bash_history
history -c
history -w
exit
```

```
cd /var/esp32/boot
ls
cat filename.py
# or xdg-open filename.py
```

```
curl -fsSL https://ollama.com/install.sh | sh
ollama run gemma3:270m
```
