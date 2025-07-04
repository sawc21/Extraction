# Extraction

to install local llm:
wsl --install
sudo apt update && sudo apt upgrade -y
sudo apt install git python3 python3-venv python3-pip -y
curl -fsSL https://ollama.com/install.sh | sh
ollama pull mistral
ollama run mistral
