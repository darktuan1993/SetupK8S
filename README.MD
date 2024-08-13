#### Kiểm tra version có thể cài đặt 
apt-cache madison kubelet kubeadm kubectl

#### Upload cert
kubeadm init --config=kubeadm-config.yaml --upload-certs