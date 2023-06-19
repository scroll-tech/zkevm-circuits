module main

go 1.16

require (
	github.com/ethereum/go-ethereum v1.11.5
	github.com/holiman/uint256 v1.2.0
	github.com/imdario/mergo v0.3.15 // indirect
)

// Replace for scroll go-ethereum
replace github.com/ethereum/go-ethereum => github.com/scroll-tech/go-ethereum v1.10.24-0.20230614193733-b7e7c4dc3be8
