sudo apt-get update
sudo apt install curl
curl -O https://dl.google.com/go/go1.14.9.linux-amd64.tar.gz
tar xvf go1.14.9.linux-amd64.tar.gz
sudo chown -R root:root ./go
sudo mv go /usr/local
sudo rm -r go1.14.9.linux-amd64.tar.gz
echo "
export GOPATH=$HOME/go
export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin
" >> ~/.profile
source ~/.profile;
