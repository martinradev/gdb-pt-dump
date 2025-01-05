
download_latest() {
    if [[ -d test_images ]]; then
        echo "Test images already downloaded. Skipping..."
        return 0
    fi
    source_url="https://github.com/martinradev/gdb-pt-dump/releases/download/test_binary_images_v1/test_images.tar.zst"
    wget "${source_url}"
    tar -xf test_images.tar.zst
    rm test_images.tar.zst
    return 0
}
