sudo apt-get update; 
#remove old version of go-lang 
sudo rm -rf /usr/local/go; 
sudo rm -rf /root/go; 
wget -c https://golang.org/dl/go1.15.2.linux-amd64.tar.gz
shasum -a 256 go1.15.2.linux-amd64.tar.gz;
tar -C /usr/local -xvzf go1.15.2.linux-amd64.tar.gz
mkdir -p ~/go/{bin,src,pkg}
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bash_profile;
echo 'export GOPATH="/root/go"' >> ~/.bash_profile;
echo 'export GOBIN=$GOPATH/bin' >> ~/.bash_profile;
echo 'export GOROOT=/usr/local/go' >> ~/.bash_profile;
echo 'export PATH=$PATH:$GOROOT/bin' >> ~/.bash_profile;
source ~/.bash_profile
cp /usr/local/go/bin/go /usr/local/bin/; 
