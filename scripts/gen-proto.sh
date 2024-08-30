#!/bin/bash

CURRENT_DIR="$1"

echo "Current directory: ${CURRENT_DIR}"

rm -rf "${CURRENT_DIR}/genproto"
echo "Removed existing genproto directory."

mkdir -p "${CURRENT_DIR}/genproto"
echo "Created new genproto directory."

for proto_dir in $(find "${CURRENT_DIR}/protos" -type d); do
  echo "Processing directory: ${proto_dir}"
  for proto_file in "${proto_dir}"/*.proto; do
    if [ -f "${proto_file}" ]; then
      echo "Compiling ${proto_file}"
      protoc -I="${CURRENT_DIR}/protos" -I="${proto_dir}" -I="/usr/local/go" \
        --go_out="${CURRENT_DIR}/genproto" --go-grpc_out="${CURRENT_DIR}/genproto" "${proto_file}"
    fi
  done
done

echo "Protobuf files have been generated."