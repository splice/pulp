source ./env_vars


yum install -y vim-enhanced
cp ./dotfiles/dot.vimrc /root/.vimrc
cp ./dotfiles/dot.vimrc /home/vagrant/.vimrc
chown vagrant /home/vagrant/.vimrc

echo "Run: 'vagrant ssh' to ssh into the Pulp devel env VM"
echo " or ssh vagrant@pulp.example.com   (Password is 'vagrant')"
echo "Enjoy."


