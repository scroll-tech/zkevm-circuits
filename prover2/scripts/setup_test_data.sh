set -x
set -e

dir="${1:-"./test_data/.configs"}"
mkdir -p "$dir"

for ((i = 1; i < 7; ++i)); do
	template="./configs/layer${i}.config"
	file="$dir/layer${i}.config"
	jq ".degree = ${i}" ${template} > ${file}
done
