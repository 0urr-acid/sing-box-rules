#!/bin/sh

GITHUB_USER="0urr-acid"
GITHUB_REPO="sing-box-rules"
DEST_DIR="/etc/sing-box-rules/"
# Optional interface name, e.g. INTERFACE=tun0 ./update_rules.sh
INTERFACE="${INTERFACE:-}"

if command -v curl >/dev/null 2>&1; then
    DOWNLOADER="curl"
elif command -v wget >/dev/null 2>&1; then
    DOWNLOADER="wget"
else
    echo "[ERROR] Install curl or wget to download rules."
    exit 1
fi

DOWNLOAD_INTERFACE=""
if [ -n "$INTERFACE" ]; then
    if [ ! -d "/sys/class/net/$INTERFACE" ]; then
        echo "[WARN] Interface $INTERFACE does not exist; using default routing."
    elif [ "$DOWNLOADER" = "curl" ]; then
        DOWNLOAD_INTERFACE="$INTERFACE"
    else
        echo "[WARN] Interface binding requires curl; using wget with default routing."
    fi
fi

download() {
    if [ "$DOWNLOADER" = "curl" ]; then
        if [ -n "$DOWNLOAD_INTERFACE" ]; then
            curl -fLsS --interface "if!$DOWNLOAD_INTERFACE" \
                --user-agent "Script" --output "$1" "$2"
        else
            curl -fLsS --user-agent "Script" --output "$1" "$2"
        fi
    else
        wget -O "$1" --header="User-Agent: Script" "$2"
    fi
}

if ! mkdir -p "$DEST_DIR"; then
    echo "[ERROR] Failed to create $DEST_DIR."
    exit 1
fi

FAILED_UPDATES=0

API_URL="https://api.github.com/repos/$GITHUB_USER/$GITHUB_REPO/releases/latest"
TMP_DIR=$(mktemp -d) || exit 1
trap 'rm -rf "$TMP_DIR"' EXIT
trap 'exit 1' HUP INT TERM
API_JSON="$TMP_DIR/release.json"

echo "[$(date)] Fetching release metadata..."

if ! download "$API_JSON" "$API_URL"; then
    echo "[ERROR] Failed to fetch release metadata from GitHub API."
    exit 1
fi

PARSER=""
if command -v jsonfilter >/dev/null 2>&1; then
    PARSER="jsonfilter"
elif command -v jq >/dev/null 2>&1; then
    PARSER="jq"
else
    echo "[ERROR] Install jsonfilter or jq to read the release asset list."
    exit 1
fi

if [ "$PARSER" = "jsonfilter" ]; then
    jsonfilter -i "$API_JSON" -e '$.assets[*].name' > "$TMP_DIR/assets" || exit 1
else
    jq -r '.assets[].name' "$API_JSON" > "$TMP_DIR/assets" || exit 1
fi

if ! grep '\.srs$' "$TMP_DIR/assets" > "$TMP_DIR/srs-assets"; then
    echo "[ERROR] No .srs assets found in the latest release."
    exit 1
fi

while IFS= read -r FILE_NAME; do
    case "$FILE_NAME" in
        */*|*\\*|*\"*|*\'*)
            echo "  [ERROR] Unsupported asset name: $FILE_NAME"
            FAILED_UPDATES=$((FAILED_UPDATES + 1))
            continue
            ;;
    esac

    TMP_FILE="$TMP_DIR/$FILE_NAME.tmp"
    DEST_FILE="$DEST_DIR/$FILE_NAME"

    SRC_URL=""
    EXPECTED_HASH=""

    if [ "$PARSER" = "jsonfilter" ]; then
        SRC_URL=$(jsonfilter -i "$API_JSON" -e "$.assets[@.name='$FILE_NAME'].browser_download_url")
        EXPECTED_HASH=$(jsonfilter -i "$API_JSON" -e "$.assets[@.name='$FILE_NAME'].digest" | sed 's/sha256://')
    elif [ "$PARSER" = "jq" ]; then
        SRC_URL=$(jq -r --arg name "$FILE_NAME" '.assets[] | select(.name == $name) | .browser_download_url' "$API_JSON")
        EXPECTED_HASH=$(jq -r --arg name "$FILE_NAME" '.assets[] | select(.name == $name) | .digest' "$API_JSON" | sed 's/sha256://')
    fi

    if [ -z "$SRC_URL" ] || [ "$SRC_URL" = "null" ]; then
        echo "  [ERROR] Asset $FILE_NAME not found in release JSON."
        FAILED_UPDATES=$((FAILED_UPDATES + 1))
        continue
    fi

    echo "Downloading: $FILE_NAME ..."

    if ! download "$TMP_FILE" "$SRC_URL"; then
        echo "  [ERROR] Failed to download $FILE_NAME."
        FAILED_UPDATES=$((FAILED_UPDATES + 1))
        rm -f "$TMP_FILE"
        continue
    fi

    if [ ! -s "$TMP_FILE" ] || grep -q "<html" "$TMP_FILE"; then
        echo "  [ERROR] File $FILE_NAME is empty or corrupted (HTML response)."
        FAILED_UPDATES=$((FAILED_UPDATES + 1))
        rm -f "$TMP_FILE"
        continue
    fi

    if [ -n "$EXPECTED_HASH" ] && [ "$EXPECTED_HASH" != "null" ]; then
        ACTUAL_HASH=$(sha256sum "$TMP_FILE" | awk '{print $1}')
        if [ "$ACTUAL_HASH" = "$EXPECTED_HASH" ]; then
            echo "  [OK] Checksum verified for $FILE_NAME."
        else
            echo "  [ERROR] Checksum mismatch for $FILE_NAME!"
            echo "    Expected: $EXPECTED_HASH"
            echo "    Got:      $ACTUAL_HASH"
            FAILED_UPDATES=$((FAILED_UPDATES + 1))
            rm -f "$TMP_FILE"
            continue
        fi
    fi

    if ! mv -f "$TMP_FILE" "$DEST_FILE" || ! chmod 644 "$DEST_FILE"; then
        echo "  [ERROR] Failed to install $FILE_NAME."
        FAILED_UPDATES=$((FAILED_UPDATES + 1))
        continue
    fi
    echo "  [SUCCESS] $FILE_NAME updated."
done < "$TMP_DIR/srs-assets"

echo "[$(date)] Update finished. Errors: $FAILED_UPDATES"
[ "$FAILED_UPDATES" -eq 0 ]
