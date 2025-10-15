# 1️⃣ Limpia todas las reglas actuales
sudo iptables -F
sudo iptables -X

# 2️⃣ Limpia también reglas NAT y mangle
sudo iptables -t nat -F
sudo iptables -t nat -X
sudo iptables -t mangle -F
sudo iptables -t mangle -X

# 3️⃣ Quita cualquier contador
sudo iptables -Z

# 4️⃣ Establece políticas por defecto en ACCEPT (para no perder conexión)
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT
