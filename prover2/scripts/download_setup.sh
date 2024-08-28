set -x
set -e

# Set degree to env SCROLL_PROVER_MAX_DEGREE, first input or default value 26.
degree="${SCROLL_PROVER_MAX_DEGREE:-${1:-26}}"

# Set the output dir to second input or default as `./integration/params`.
dir="${2:-"./test_data/.params"}"
mkdir -p "$dir"

file="$dir"/params"${degree}"
rm -f "$file"

# degree 1 - 26
axel -ac https://circuit-release.s3.us-west-2.amazonaws.com/setup/params"$degree" -o "$file"
