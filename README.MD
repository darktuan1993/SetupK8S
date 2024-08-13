#### Kiểm tra version có thể cài đặt 
apt-cache madison kubelet kubeadm kubectl

#### Upload cert
kubeadm init --config=kubeadm-config.yaml --upload-certs

#### Tìm lại lệnh join
kubeadm token create --print-join-command

#### Tạo lại token create join

kubeadm init phase upload-certs --upload-certs


