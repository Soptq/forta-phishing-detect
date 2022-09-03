import { createAddress } from "forta-agent-tools";
import genesisAddressJson from "evm-labels/lib/esm/mainnet/genesis/addresses.json"
import exchangeAddressJson from "evm-labels/lib/esm/mainnet/exchange/addresses.json"
import { exchange } from "evm-labels"

const getIdentifiedAddresses = () => {
	const identifiedAddresses = [];
	for (const address of genesisAddressJson.addresses) {
		// @ts-ignore
		identifiedAddresses.push(createAddress(address));
	}
	for (const address of exchangeAddressJson.addresses) {
		// @ts-ignore
		identifiedAddresses.push(createAddress(address));
	}
	return [
		createAddress("0x000000000000000000000000000000000000dead"),
		...identifiedAddresses,
	]
}

export default {
	getIdentifiedAddresses,
	exchange
};