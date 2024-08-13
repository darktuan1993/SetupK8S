unset KUBECONFIG
sudo kubeadm reset
sudo rm -rf /etc/cni/net.d
sudo rm -rf /var/lib/cni/
sudo rm -rf /var/run/kubernetes/
sudo docker system prune -af
sudo systemctl stop docker
sudo apt-get remove --purge docker-ce docker-ce-cli containerd.io
sudo systemctl stop containerd
sudo apt-get remove --purge containerd
sudo apt-get remove --purge kubeadm kubectl kubelet kubernetes-cni kube*
sudo rm -rf ~/.kube
sudo rm -rf /etc/kubernetes/
sudo rm -rf /var/lib/etcd/
sudo rm -rf /var/lib/kubelet/
sudo rm -rf /var/lib/dockershim
sudo rm -rf /etc/systemd/system/kubelet.service.d
sudo rm -rf /etc/systemd/system/kubelet.service
sudo rm -rf /usr/bin/kube*
sudo rm -rf /usr/local/bin/kube*
sudo reboot
