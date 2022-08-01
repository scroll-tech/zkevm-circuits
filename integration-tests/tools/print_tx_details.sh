TXID=0x01c2da2a4fb287b3d819454f1f3e3fb1384a72026bedb4424fb5bec70eb8a627
function p() {
	echo ""
	echo ""
	TXID=$1
	curl http://0.0.0.0:8545/ \
		-X POST \
		-H "Content-Type: application/json" \
		--data '{"method":"eth_getTransactionByHash","params":["'$TXID'"],"id":1,"jsonrpc":"2.0"}'
	echo ""
	curl http://0.0.0.0:8545 \
		-X POST \
		-H "Content-Type: application/json" \
		--data '{"method":"eth_getTransactionReceipt","params":["'$TXID'"],"id":1,"jsonrpc":"2.0"}'
}

for txid in 0x34e469f2711203fc786f0a9b96dcbc7e022cb7182ceab4f7317b724d52fef7af 0x01c2da2a4fb287b3d819454f1f3e3fb1384a72026bedb4424fb5bec70eb8a627 0x80a3e55293009984f68b93eaa81923fb75f36fa05620a0d8080c15a0c383c3a7; do
	p $txid
done
