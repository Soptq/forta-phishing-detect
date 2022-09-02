import { createAddress } from "forta-agent-tools";
import genesisAddressJson from "evm-labels/lib/esm/mainnet/genesis/addresses.json"
import exchangeAddressJson from "evm-labels/lib/esm/mainnet/exchange/addresses.json"

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
	return identifiedAddresses
}

export default {
	getIdentifiedAddresses,
};