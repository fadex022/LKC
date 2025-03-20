#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import time
import json
import argparse

class KubernetesSetup:
    def __init__(self):
        self.config = {
            "cluster_name": "mon-cluster",
            "nodes": 3,
            "cpu_per_node": 2,
            "memory_per_node": "2G",
            "disk_per_node": "20G",
            "kubernetes_version": "1.31.5",
            "pod_network_cidr": "10.244.0.0/16",
            "service_cidr": "10.96.0.0/12",
            "rancher_enabled": True,
            "rancher_version": "2.10.3",
            "rancher_port": 8080
        }
        
    def check_prerequisites(self) -> bool:
        """Vérifie si tous les prérequis sont installés."""
        print("Vérification des prérequis...")
        prerequisites = ["multipass", "kubectl"]
        missing = []
        
        for tool in prerequisites:
            try:
                subprocess.run(["which", tool], check=True, stdout=subprocess.DEVNULL)
                print(f"✅ {tool} installé")
            except subprocess.CalledProcessError:
                missing.append(tool)
                print(f"❌ {tool} non trouvé")
        
        if missing:
            print("\nVeuillez installer les outils manquants:")
            if "multipass" in missing:
                print("  - Multipass: brew install --cask multipass")
            if "kubectl" in missing:
                print("  - kubectl: brew install kubectl")
            return False
        
        return True
        
    def prompt_for_config(self) -> None:
        """Demande à l'utilisateur les paramètres de configuration."""
        print("\n=== Configuration du cluster Kubernetes ===")
        
        self.config["cluster_name"] = input(f"Nom du cluster [{self.config['cluster_name']}]: ") or self.config["cluster_name"]
        
        try:
            nodes = int(input(f"Nombre de nœuds (1 master + N workers) [{self.config['nodes']}]: ") or self.config["nodes"])
            self.config["nodes"] = nodes if nodes > 0 else self.config["nodes"]
        except ValueError:
            print("Valeur invalide, utilisation de la valeur par défaut.")
            
        self.config["cpu_per_node"] = input(f"CPUs par nœud [{self.config['cpu_per_node']}]: ") or self.config["cpu_per_node"]
        self.config["memory_per_node"] = input(f"Mémoire par nœud [{self.config['memory_per_node']}]: ") or self.config["memory_per_node"]
        self.config["disk_per_node"] = input(f"Disque par nœud [{self.config['disk_per_node']}]: ") or self.config["disk_per_node"]
        
        self.config["kubernetes_version"] = input(f"Version de Kubernetes [{self.config['kubernetes_version']}]: ") or self.config["kubernetes_version"]
        self.config["pod_network_cidr"] = input(f"CIDR du réseau Pod [{self.config['pod_network_cidr']}]: ") or self.config["pod_network_cidr"]
        self.config["service_cidr"] = input(f"CIDR du réseau Service [{self.config['service_cidr']}]: ") or self.config["service_cidr"]
        
        rancher_enabled = input(f"Installer Rancher (oui/non) [{'oui' if self.config['rancher_enabled'] else 'non'}]: ").lower() or ("oui" if self.config["rancher_enabled"] else "non")
        self.config["rancher_enabled"] = rancher_enabled in ["oui", "o", "yes", "y", "true"]
        
        if self.config["rancher_enabled"]:
            self.config["rancher_version"] = input(f"Version de Rancher [{self.config['rancher_version']}]: ") or self.config["rancher_version"]
            try:
                rancher_port = int(input(f"Port pour Rancher [{self.config['rancher_port']}]: ") or self.config["rancher_port"])
                self.config["rancher_port"] = rancher_port
            except ValueError:
                print("Valeur invalide, utilisation de la valeur par défaut.")
        
        print("\nConfiguration du cluster:")
        for key, value in self.config.items():
            print(f"  - {key}: {value}")
        
        confirm = input("\nConfirmer cette configuration? (oui/non) [oui]: ").lower() or "oui"
        if confirm not in ["oui", "o", "yes", "y", "true"]:
            print("Configuration annulée.")
            sys.exit(0)
    
    def create_multipass_instances(self) -> bool:
        """Crée les instances Multipass pour le cluster."""
        print(f"\nCréation de {self.config['nodes']} instances Multipass...")
        
        # Création du nœud master
        master_name = f"{self.config['cluster_name']}-master"
        try:
            print(f"Création du nœud master: {master_name}")
            subprocess.run([
                "multipass", "launch", "-n", master_name,
                "-c", str(self.config["cpu_per_node"]), 
                "-m", self.config["memory_per_node"], 
                "-d", self.config["disk_per_node"]
            ], check=True)
            print(f"✅ Nœud master {master_name} créé")
        except subprocess.CalledProcessError as e:
            print(f"❌ Erreur lors de la création du nœud master: {e}")
            return False
        
        # Création des nœuds worker
        for i in range(1, self.config["nodes"]):
            worker_name = f"{self.config['cluster_name']}-worker{i}"
            try:
                print(f"Création du nœud worker: {worker_name}")
                subprocess.run([
                    "multipass", "launch", "-n", worker_name,
                    "-c", str(self.config["cpu_per_node"]), 
                    "-m", self.config["memory_per_node"], 
                    "-d", self.config["disk_per_node"]
                ], check=True)
                print(f"✅ Nœud worker {worker_name} créé")
            except subprocess.CalledProcessError as e:
                print(f"❌ Erreur lors de la création du nœud worker {worker_name}: {e}")
                return False
        
        return True
    
    def run_command_with_retry(self, node, command, description, max_retries=3):
        """Exécute une commande avec plusieurs tentatives en cas d'échec."""
        for attempt in range(max_retries):
            try:
                print(f"  - Tentative {attempt+1}/{max_retries}: {description}...")
                result = subprocess.run(
                    ["multipass", "exec", node, "--", "bash", "-c", command],
                    check=True, capture_output=True, text=True
                )
                print(f"    ✅ Réussi: {description}")
                return True, result.stdout
            except subprocess.CalledProcessError as e:
                print(f"    ⚠️ Échec tentative {attempt+1}: {e}")
                if attempt == max_retries - 1:
                    print(f"    ❌ Échec après {max_retries} tentatives: {description}")
                    print(f"    Détails de l'erreur: {e.stderr}")
                    return False, ""
                time.sleep(5)  # Attendre avant de réessayer
        return False, ""

    def prepare_nodes(self) -> bool:
        """Prépare tous les nœuds pour l'installation de Kubernetes."""
        print("\nPréparation des nœuds pour Kubernetes...")

        containerd_install_cmd = """
# Installation de Containerd
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo   "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
$(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install containerd.io -y

# Configuration de Containerd
sudo mkdir -p /etc/containerd
sudo containerd config default | sudo tee /etc/containerd/config.toml
sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/g' /etc/containerd/config.toml
sudo systemctl restart containerd
""
# Configurer crictl pour utiliser Containerd (il utilise Docker par défaut)
cat <<EOF | sudo tee /etc/crictl.yaml
runtime-endpoint: unix:///run/containerd/containerd.sock
EOF
"""
        
        # Commandes pour installer les prérequis et Docker
        docker_install_cmd = """
# Mettre à jour les paquets
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common

# Désactiver le swap
sudo swapoff -a
sudo sed -i '/swap/d' /etc/fstab

# Installer Docker
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io

# Configurer Docker pour Kubernetes
sudo mkdir -p /etc/docker
cat <<EOF | sudo tee /etc/docker/daemon.json
{
    "exec-opts": ["native.cgroupdriver=systemd"],
    "log-driver": "json-file",
    "log-opts": {
    "max-size": "100m"
    },
    "storage-driver": "overlay2"
}
EOF

sudo mkdir -p /etc/systemd/system/docker.service.d
sudo systemctl daemon-reload
sudo systemctl restart docker
sudo systemctl enable docker

# Ajouter l'utilisateur ubuntu au groupe docker
sudo usermod -aG docker ubuntu

# Charger les modules nécessaires
cat <<EOF | sudo tee /etc/modules-load.d/k8s.conf
overlay
br_netfilter
EOF

sudo modprobe overlay
sudo modprobe br_netfilter

# Configurer sysctl
cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF

sudo sysctl --system
"""
        
        # Commandes pour installer kubeadm, kubelet et kubectl
        k8s_install_cmd = """
# alias
echo 'alias k="kubectl"' >> $HOME/.bashrc

# Configuration des paramètres réseau pour Kubernetes
cat <<EOF | sudo tee /etc/sysctl.d/kubernetes.conf
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.ipv4.ip_forward = 1
EOF

sudo sysctl --system

sudo modprobe overlay
sudo modprobe br_netfilter

# Désactiver la fonction « apt daily stuff » car elle peut créer des erreurs
(
sudo systemctl stop apt-daily.timer
sudo systemctl disable apt-daily.timer
sudo systemctl mask apt-daily.service
sudo systemctl stop apt-daily-upgrade.timer
sudo systemctl disable apt-daily-upgrade.timer
sudo systemctl mask apt-daily-upgrade.service
sudo systemctl daemon-reload
) 1>/dev/null 2>&1 || true

# Nettoyage
rm -rf $HOME/.kube
sudo kubeadm reset -f || true
sudo apt-mark unhold kubelet kubeadm kubectl || true
sudo apt-get remove -y containerd kubelet kubeadm kubectl kubernetes-cni || true
sudo apt-get autoremove -y
sudo systemctl daemon-reload
sudo apt-get update

# Ajouter le dépôt Kubernetes
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v{k8s_ver}/deb/ /" | sudo tee /etc/apt/sources.list.d/kubernetes.list
curl -fsSL https://pkgs.k8s.io/core:/stable:/v{k8s_ver}/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg

sudo apt-get update
sudo apt-get install -y kubelet kubeadm kubectl
sudo apt-mark hold kubelet kubeadm kubectl

# Vérifier l'installation
kubeadm version
kubectl version --client
"""
        
        # Remplacer la version de Kubernetes
        k8s_version = self.config["kubernetes_version"].split('.')
        k8s_minor_version = f"{k8s_version[0]}.{k8s_version[1]}"
        k8s_install_cmd = k8s_install_cmd.format(k8s_ver=k8s_minor_version)
        
        # Exécuter les commandes sur tous les nœuds
        nodes = [f"{self.config['cluster_name']}-master"]
        for i in range(1, self.config["nodes"]):
            nodes.append(f"{self.config['cluster_name']}-worker{i}")
        
        for node in nodes:
            print(f"Préparation du nœud: {node}...")
            
            # Installer Containerd
            success, _ = self.run_command_with_retry(
                node, containerd_install_cmd, "Installation de Containerd"
            )
            if not success:
                return False
                
            # Installer kubeadm et les outils Kubernetes
            success, output = self.run_command_with_retry(
                node, k8s_install_cmd, "Installation de kubeadm, kubelet et kubectl"
            )
            if not success:
                return False
            
            print(f"✅ Nœud {node} préparé avec succès")
        
        return True
        
    def initialize_master(self) -> dict:
        """Initialise le nœud master avec kubeadm."""
        print("\nInitialisation du nœud master avec kubeadm...")
        master_name = f"{self.config['cluster_name']}-master"
        
        # Récupération de l'adresse IP du master
        try:
            result = subprocess.run(
                ["multipass", "info", master_name, "--format", "json"],
                check=True, capture_output=True, text=True
            )
            info = json.loads(result.stdout)
            master_ip = info["info"][master_name]["ipv4"][0]
            print(f"✅ Adresse IP du master: {master_ip}")
        except (subprocess.CalledProcessError, json.JSONDecodeError, KeyError) as e:
            print(f"❌ Erreur lors de la récupération de l'IP du master: {e}")
            return {}
        
        # Créer le fichier de configuration pour kubeadm
        kubeadm_config = f"""
cat <<EOF | sudo tee /tmp/kubeadm-config.yaml
apiVersion: kubeadm.k8s.io/v1beta3
kind: InitConfiguration
nodeRegistration:
  name: {master_name}
localAPIEndpoint:
  advertiseAddress: {master_ip}
  bindPort: 6443
---
apiVersion: kubeadm.k8s.io/v1beta3
kind: ClusterConfiguration
kubernetesVersion: v{self.config["kubernetes_version"]}
networking:
  serviceSubnet: {self.config["service_cidr"]}
  podSubnet: {self.config["pod_network_cidr"]}
  dnsDomain: "cluster.local"
controlPlaneEndpoint: "{master_ip}:6443"
EOF
"""
        
        success, _ = self.run_command_with_retry(
            master_name, kubeadm_config, "Création du fichier de configuration kubeadm"
        )
        if not success:
            return {}
        
        # Initialisation du cluster avec kubeadm
        kubeadm_pull_image = "sudo kubeadm config images pull"
        kubeadm_init_cmd = "sudo kubeadm init --config=/tmp/kubeadm-config.yaml"
        # kubeadm_init_cmd = "sudo kubeadm init --config=/tmp/kubeadm-config.yaml --upload-certs"

        success, pull_output = self.run_command_with_retry(
            master_name, kubeadm_pull_image, "Pull des images Kubernetes", max_retries=2
        )
        if not success:
            return {}

        success, init_output = self.run_command_with_retry(
            master_name, kubeadm_init_cmd, "Initialisation du cluster avec kubeadm", max_retries=2
        )
        if not success:
            return {}
        
        # Configurer kubectl sur le master
        kubectl_config_cmd = """
mkdir -p $HOME/.kube
sudo cp -f /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
"""
        success, _ = self.run_command_with_retry(
            master_name, kubectl_config_cmd, "Configuration de kubectl sur le master"
        )
        if not success:
            return {}
        
        # Déploiement du réseau Calico
        calico_cmd = """
kubectl apply -f https://docs.projectcalico.org/manifests/calico.yaml
"""
        success, _ = self.run_command_with_retry(
            master_name, calico_cmd, "Déploiement du réseau Calico"
        )
        if not success:
            return {}
        
        # Attendre que le nœud master soit prêt
        wait_cmd = """
for i in {{1..10}}; do
  kubectl get nodes
  if [ $? -eq 0 ]; then
    kubectl wait --for=condition=Ready node/{master_name} --timeout=60s
    exit $?
  fi
  sleep 10
done
exit 1
"""
        wait_cmd = wait_cmd.format(master_name=master_name)
        success, _ = self.run_command_with_retry(
            master_name, wait_cmd, "Attente de la disponibilité du nœud master"
        )
        if not success:
            print("⚠️ Le nœud master n'est pas encore prêt, mais nous continuons...")
        
        # Récupérer la commande de jointure pour les nœuds worker
        join_cmd = """
kubeadm token create --print-join-command
"""
        success, join_output = self.run_command_with_retry(
            master_name, join_cmd, "Récupération de la commande de jointure"
        )
        if not success:
            return {}
        
        print("✅ Master initialisé avec succès")
        
        return {
            "master_ip": master_ip,
            "join_command": join_output.strip()
        }
    
    def join_workers(self, join_info: dict) -> bool:
        """Rejoint les nœuds worker au cluster."""
        if not join_info or "join_command" not in join_info:
            print("❌ Informations de jointure manquantes")
            return False
            
        print("\nConnexion des nœuds worker au cluster...")
        
        for i in range(1, self.config["nodes"]):
            worker_name = f"{self.config['cluster_name']}-worker{i}"
            print(f"Connexion du nœud {worker_name} au cluster...")
            
            join_cmd = f"sudo {join_info['join_command']} --v=5"
            
            success, _ = self.run_command_with_retry(
                worker_name, join_cmd, f"Connexion du nœud {worker_name} au cluster", max_retries=2
            )
            if not success:
                print(f"⚠️ Échec de la connexion du nœud {worker_name}, mais nous continuons...")
                continue
                
            print(f"✅ Nœud {worker_name} connecté au cluster")
        
        # Vérifier les nœuds sur le master
        master_name = f"{self.config['cluster_name']}-master"
        check_nodes_cmd = "kubectl get nodes"
        
        success, nodes_output = self.run_command_with_retry(
            master_name, check_nodes_cmd, "Vérification des nœuds", max_retries=3
        )
        if success:
            print("\nNœuds dans le cluster:")
            for line in nodes_output.splitlines():
                print(f"  {line}")
        
        return True
    
    def setup_local_kubectl(self) -> bool:
        """Configure kubectl en local pour se connecter au cluster."""
        print("\nConfiguration de kubectl en local...")
        master_name = f"{self.config['cluster_name']}-master"
        
        # Récupération du fichier kubeconfig
        os.makedirs(os.path.expanduser("~/.kube"), exist_ok=True)
        kubeconfig_path = os.path.expanduser(f"~/.kube/config-{self.config['cluster_name']}")
        
        # Vérifier que admin.conf existe sur le master
        check_admin_conf_cmd = "ls -la /etc/kubernetes/admin.conf"
        success, _ = self.run_command_with_retry(
            master_name, check_admin_conf_cmd, "Vérification du fichier admin.conf"
        )
        
        if not success:
            print("❌ Le fichier admin.conf n'existe pas sur le master")
            return False
        
        try:
            # Récupérer le fichier admin.conf
            subprocess.run([
                "multipass", "exec", master_name, "--", 
                "sudo", "cat", "/etc/kubernetes/admin.conf"
            ], check=True, text=True, 
            stdout=open(kubeconfig_path, "w"))
            
            # Récupérer l'IP du master
            result = subprocess.run(
                ["multipass", "info", master_name, "--format", "json"],
                check=True, capture_output=True, text=True
            )
            info = json.loads(result.stdout)
            master_ip = info["info"][master_name]["ipv4"][0]
            
            # Remplacer l'adresse localhost par l'IP du master dans le kubeconfig
            with open(kubeconfig_path, "r") as f:
                content = f.read()
            content = content.replace("127.0.0.1", master_ip)
            with open(kubeconfig_path, "w") as f:
                f.write(content)
                
            print(f"✅ Fichier kubeconfig créé: {kubeconfig_path}")
            print(f"Pour utiliser ce cluster: export KUBECONFIG={kubeconfig_path}")
            
            # Définir KUBECONFIG pour l'environnement actuel
            os.environ["KUBECONFIG"] = kubeconfig_path
            
            # Vérifier si kubectl peut se connecter au cluster
            try:
                subprocess.run(["kubectl", "get", "nodes"], check=True, stdout=subprocess.DEVNULL)
                print("✅ Connexion locale au cluster établie avec succès")
            except subprocess.CalledProcessError:
                print("⚠️ Impossible de se connecter localement au cluster")
                print("   Veuillez vérifier la connexion manuellement avec:")
                print(f"   export KUBECONFIG={kubeconfig_path}")
                print("   kubectl get nodes")
            
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Erreur lors de la récupération du fichier kubeconfig: {e}")
            return False
    
    def install_rancher(self) -> bool:
        """Installe Rancher sur le cluster Kubernetes."""
        if not self.config["rancher_enabled"]:
            return True
            
        print(f"\nInstallation de Rancher {self.config['rancher_version']}...")
        master_name = f"{self.config['cluster_name']}-master"
        
        # Installation de Helm sur le nœud master
        helm_install_cmd = """
curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
chmod 700 get_helm.sh
./get_helm.sh
"""
        success, _ = self.run_command_with_retry(
            master_name, helm_install_cmd, "Installation de Helm"
        )
        if not success:
            return False
        
        # Installation du certificat manager
        cert_manager_cmd = """
kubectl create namespace cert-manager
helm repo add jetstack https://charts.jetstack.io
helm repo update
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --version v1.17.0 \
  --set installCRDs=true
"""
        success, _ = self.run_command_with_retry(
            master_name, cert_manager_cmd, "Installation du gestionnaire de certificats"
        )
        if not success:
            return False
        
        # Attendre que cert-manager soit prêt
        wait_cert_manager_cmd = """
kubectl -n cert-manager wait --for=condition=available --timeout=180s deployment/cert-manager
"""
        success, _ = self.run_command_with_retry(
            master_name, wait_cert_manager_cmd, "Attente du démarrage de cert-manager"
        )
        if not success:
            print("⚠️ Cert-manager n'est pas prêt, mais nous continuons...")
        
        # Installation de Rancher avec Helm
        rancher_install_cmd = f"""
helm repo add rancher-stable https://releases.rancher.com/server-charts/stable
helm repo update
kubectl get namespace cattle-system || kubectl create namespace cattle-system
helm install rancher rancher-stable/rancher \
  --namespace cattle-system \
  --set hostname={master_name}.sslip.io \
  --set bootstrapPassword=admin \
  --version {self.config['rancher_version']}
"""
        success, _ = self.run_command_with_retry(
            master_name, rancher_install_cmd, "Installation de Rancher via Helm", max_retries=2
        )
        if not success:
            return False
        
        # Attendre que Rancher soit prêt
        wait_rancher_cmd = """
kubectl -n cattle-system wait --for=condition=available --timeout=300s deployment/rancher
"""
        success, _ = self.run_command_with_retry(
            master_name, wait_rancher_cmd, "Attente du démarrage de Rancher"
        )
        if not success:
            print("⚠️ Rancher n'est pas prêt, mais nous continuons...")
        
        # Récupération de l'adresse IP du master
        try:
            result = subprocess.run(
                ["multipass", "info", master_name, "--format", "json"],
                check=True, capture_output=True, text=True
            )
            info = json.loads(result.stdout)
            master_ip = info["info"][master_name]["ipv4"][0]
            
            print(f"\n✅ Rancher est installé!")
            print(f"  Adresse: https://{master_name}.sslip.io")
            print(f"  Pour y accéder localement, ajoutez cette entrée dans votre fichier /etc/hosts:")
            print(f"  {master_ip} {master_name}.sslip.io")
            print("  Nom d'utilisateur: admin")
            print("  Mot de passe: admin")
        except (subprocess.CalledProcessError, json.JSONDecodeError, KeyError) as e:
            print(f"❌ Erreur lors de la récupération de l'IP du master: {e}")
            return False
        
        return True
    
    def run(self) -> None:
        """Exécute le processus complet de configuration."""
        if not self.check_prerequisites():
            sys.exit(1)
            
        self.prompt_for_config()
        
        if not self.create_multipass_instances():
            print("❌ Échec de la création des instances Multipass.")
            sys.exit(1)
            
        if not self.prepare_nodes():
            print("❌ Échec de la préparation des nœuds.")
            sys.exit(1)
            
        join_info = self.initialize_master()
        if not join_info:
            print("❌ Échec de l'initialisation du nœud master.")
            sys.exit(1)
            
        if not self.join_workers(join_info):
            print("❌ Échec de la connexion des nœuds worker.")
            sys.exit(1)
            
        if not self.setup_local_kubectl():
            print("❌ Échec de la configuration de kubectl en local.")
            sys.exit(1)
            
        if self.config["rancher_enabled"] and not self.install_rancher():
            print("❌ Échec de l'installation de Rancher.")
            sys.exit(1)
            
        print("\n✅ Installation terminée avec succès!")
        print(f"Cluster Kubernetes '{self.config['cluster_name']}' créé avec {self.config['nodes']} nœuds.")
        print(f"Pour utiliser ce cluster: export KUBECONFIG=~/.kube/config-{self.config['cluster_name']}")
        
        if self.config["rancher_enabled"]:
            master_name = f"{self.config['cluster_name']}-master"
            print(f"Rancher est accessible à l'adresse: https://{master_name}.sslip.io")
            print("Nom d'utilisateur: admin")
            print("Mot de passe: admin")

def main():
    parser = argparse.ArgumentParser(description="Configuration de cluster Kubernetes avec Multipass et Rancher")
    parser.add_argument("--non-interactive", action="store_true", help="Mode non interactif (utilise les valeurs par défaut)")
    args = parser.parse_args()
    
    setup = KubernetesSetup()
    
    if args.non_interactive:
        print("Mode non interactif: utilisation des valeurs par défaut.")
    else:
        setup.run()

if __name__ == "__main__":
    main()