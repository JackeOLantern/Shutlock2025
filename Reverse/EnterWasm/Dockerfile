# Utiliser Python 3.9, version compatible Wasmer
FROM python:3.9-slim

WORKDIR /app

# Copier les fichiers nécessaires
COPY solve_wasm.py encode.wasm .

# Installer wasmer avec Cranelift
RUN pip install wasmer==1.1.0 wasmer_compiler_cranelift==1.1.0

# Commande par défaut pour exécuter le script
CMD ["python", "solve_wasm.py"]
