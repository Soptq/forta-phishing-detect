import {
  Finding,
  HandleTransaction,
  TransactionEvent,
  FindingSeverity,
  FindingType,
  getEthersProvider,
  ethers,
  getAlerts,
} from "forta-agent";
import { handlers, createAddress } from "forta-agent-tools";
import labels from "./labels";
const LRU = require('lru-cache')

let findingsCount = 0;

const approvalThreshold = 5 // used to filter alerts from bot `0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14`.
const phishingWindow = 12 * 60 * 60 // 12 hours.
const drainThreshold = 0.8 // if 80% of the balance is transferred, it is likely to be a drain attack.
const numTransferThreshold = 5 // if there are more than 5 transfers in `phishingWindow` from different addresses, the drain rate can be calculated.
const numTransferToEOAThreshold = 10 // if there are more than 10 transfers to EOA in `phishingWindow` from different addresses, it is likely to be a phishing attack.
const drainRateThreshold = 0.8 // if 80% of the transactions of an address is defined as a drain attack, it is likely to be a phishing attack.
const numLegitTransactions = 2000 // if the number of transactions of an account is greater than this value, it is considered to be legit.
const approvalCheck = false;
// This is a common assumption. However, you can turn it off and this bot would still work, but the false positive would be probably higher considering many contracts have very similar activities with phishing attackers,e.g. NFT Mint, Bootstrap, FOMO.
const assertAttackersAlwaysUseEOA = true;
const skipAddresses = labels.getIdentifiedAddresses();

const approvalsCache = new LRU({
  max: 100000,
  updateAgeOnGet: false,
  updateAgeOnHas: false,
})

const tokenTransferInCache = new LRU({
  max: 100000,
  updateAgeOnGet: false,
  updateAgeOnHas: false,
})

const erc721TransferCache = new LRU({
  max: 100000,
  updateAgeOnGet: false,
  updateAgeOnHas: false,
})

const monitorAddressesCache = new LRU({
  max: 100000,
  updateAgeOnGet: true,
  updateAgeOnHas: true,
});

const transactionCountCache = new LRU({
  max: 100000,
  updateAgeOnGet: true,
  updateAgeOnHas: true,
});

const isContractCache = new LRU({
  max: 100000,
  updateAgeOnGet: true,
  updateAgeOnHas: true,
});

const erc20TransfersHandler = new handlers.Erc20Transfers({
  onFinding(metadata) {
    return Finding.from({
      name: "ERC20 transfer",
      description: "A ERC20 transfer was detected",
      alertId: "FORTA-1",
      severity: FindingSeverity.Info,
      type: FindingType.Info,
      metadata: {
        token: metadata.emitter,
        from: metadata.from,
        to: metadata.to,
        amount: metadata.amount.toString(),
      },
    });
  },
});

const erc721TransfersHandler = new handlers.Erc721Transfers({
  onFinding(metadata) {
    return Finding.from({
      name: "ERC721 transfer",
      description: "A ERC721 transfer was detected",
      alertId: "FORTA-1",
      severity: FindingSeverity.Info,
      type: FindingType.Info,
      metadata: {
        token: metadata.emitter,
        from: metadata.from,
        to: metadata.to,
        tokenId: metadata.tokenId.toString(),
      },
    });
  },
});

const ethTransfersHandler = new handlers.EthTransfers({
  onFinding(metadata) {
    return Finding.from({
      name: "Ether transfer",
      description: "A ether transfer was detected",
      alertId: "FORTA-1",
      severity: FindingSeverity.Info,
      type: FindingType.Info,
      metadata: {
        from: metadata.from,
        to: metadata.to,
        value: metadata.value.toString(),
      },
    });
  },
});

const getTokenBalance = async (tokenAddress: string, accountAddress: string, blockNumber: number) => {
  const contract =  new ethers.Contract(
    tokenAddress,
    ['function balanceOf(address) view returns (uint)'],
    getEthersProvider(),
  );
  return await contract.balanceOf(accountAddress, { blockTag: blockNumber });
}

const addRecord = async (fromAddress: string, tokenAddress: string, targetAddress: string, amount: ethers.BigNumber,
                               currentTimestamp: number, blockNumber: number) => {
  if (!(erc721TransferCache.has(targetAddress))) {
    erc721TransferCache.set(targetAddress, {});
  }

  const targetReceivedFrom = erc721TransferCache.get(targetAddress);
  if (!(fromAddress in targetReceivedFrom)) {
    targetReceivedFrom[fromAddress] = {};
  }
  if (!(tokenAddress in targetReceivedFrom[fromAddress])) {
    let balance;
    if (tokenAddress === createAddress("0x0")) {
      balance = await getEthersProvider().getBalance(fromAddress, blockNumber - 1);
    } else {
      balance = await getTokenBalance(tokenAddress, fromAddress, blockNumber - 1);
    }
    targetReceivedFrom[fromAddress][tokenAddress] = {
      amount: amount,
      originalAmount: balance,
    }
  } else {
    targetReceivedFrom[fromAddress][tokenAddress].amount = targetReceivedFrom[fromAddress][tokenAddress].amount.add(amount);
  }
  erc721TransferCache.set(targetAddress, targetReceivedFrom);

  const fromBalance = targetReceivedFrom[fromAddress][tokenAddress].originalAmount;
  if (fromBalance.eq(0)) {
    return;
  }

  const drained = targetReceivedFrom[fromAddress][tokenAddress].amount
    .mul(100)
    .div(fromBalance)
    .gte(Number(drainThreshold.toFixed(2)) * 100);

  const record = {
    fromAddress: fromAddress,
    tokenAddress: tokenAddress,
    drained: drained,
    timestamp: currentTimestamp,
  };
  if (tokenTransferInCache.has(targetAddress)) {
    let transfers = tokenTransferInCache.get(targetAddress);
    // remove previous erc721 record, if any
    transfers = transfers.filter((t: any) => t.fromAddress !== fromAddress ||  t.tokenAddress !== tokenAddress);
    // filter expired transfers
    transfers = transfers.filter((t: any) => t.timestamp > currentTimestamp - phishingWindow);
    transfers.push(record);
    tokenTransferInCache.set(targetAddress, transfers);
  } else {
    tokenTransferInCache.set(targetAddress, [record])
  }
}

const isContract = async (address: string) => {
  if (isContractCache.has(address)) {
    return isContractCache.get(address);
  }
  const code = await getEthersProvider().getCode(address);
  const isContract = code !== "0x"
  isContractCache.set(address, isContract);

  return isContract;
}

const cachedGetTransactionCount = async (address: string, blockNumber: number) => {
  if (transactionCountCache.has(address)) {
    return transactionCountCache.get(address);
  }
  const count = await getEthersProvider().getTransactionCount(address, blockNumber);
  transactionCountCache.set(address, count);
  return count;
}

const skipChecking = async (address: string, blockNumber: number) => {
  if (skipAddresses.indexOf(address) !== -1) {
    return true;
  }

  if (assertAttackersAlwaysUseEOA) {
    const isContractAddress = await isContract(address);
    if (isContractAddress) {
      return true;
    } else {
      return await cachedGetTransactionCount(address, blockNumber) > numLegitTransactions;
    }
  } else {
    return false;
  }
}

// When phishing, many unrelated accounts will transfer funds to the target account.
// Observed feature:
// 1. Large number of transfers in a small period of time.
// 2. Transferred value is likely to be large as the intention if to drain the wallet. (> 80% of sender's balance)
const handleTokenTransfer: HandleTransaction = async (
  txEvent: TransactionEvent
) => {
  const findings: Finding[] = [];
  const timestamp = txEvent.block.timestamp;
  const blockNumber = txEvent.block.number;
  const possiblePhishingAddress = new Set();

  // check ETH trans transfer
  if (ethers.BigNumber.from(txEvent.transaction.value).gt(0) && !!txEvent.transaction.to) {
    const fromAddress = createAddress(txEvent.transaction.from);
    const targetAddress = createAddress(txEvent.transaction.to);
    const amount = txEvent.transaction.value;
    if (labels.exchange.isExchangeAddress(targetAddress)) {
      if (skipAddresses.indexOf(fromAddress) === -1) {
        skipAddresses.push(fromAddress);
      }
      if (monitorAddressesCache.has(fromAddress)) {
        monitorAddressesCache.delete(fromAddress);
      }
    }

    if (!(await skipChecking(targetAddress, blockNumber))
      && txEvent.transaction.nonce > 0
      && skipAddresses.indexOf(fromAddress) === -1
      && !(await isContract(fromAddress))
    ) {
      possiblePhishingAddress.add(targetAddress)

      await addRecord(fromAddress, createAddress("0x0"), targetAddress, ethers.BigNumber.from(amount), timestamp, blockNumber);
    }
  }

  // check ETH trace transfer
  const eth_transfer_findings = await ethTransfersHandler.handle(txEvent);
  for (const finding of eth_transfer_findings) {
    const fromAddress = createAddress(finding.metadata.from);
    const targetAddress = createAddress(finding.metadata.to);
    const amount = finding.metadata.amount;

    if (labels.exchange.isExchangeAddress(targetAddress)) {
      if (skipAddresses.indexOf(fromAddress) === -1) {
        skipAddresses.push(fromAddress);
      }
      if (monitorAddressesCache.has(fromAddress)) {
        monitorAddressesCache.delete(fromAddress);
      }
    }

    const _transactionCount = fromAddress === txEvent.transaction.from ? txEvent.transaction.nonce : await cachedGetTransactionCount(fromAddress, blockNumber);
    if (await skipChecking(targetAddress, blockNumber)
      || skipAddresses.indexOf(fromAddress) !== -1
      || _transactionCount === 0
      || await isContract(fromAddress)
    ) {
      continue
    }
    possiblePhishingAddress.add(targetAddress)

    await addRecord(fromAddress, createAddress("0x0"), targetAddress, ethers.BigNumber.from(amount), timestamp, blockNumber);
  }

  // check erc20 transfer
  const erc20_transfer_findings = await erc20TransfersHandler.handle(txEvent);
  const varietyTokenAddresses: any = {};
  for (const finding of erc20_transfer_findings) {
    const tokenAddress = createAddress(finding.metadata.token);
    const targetAddress = createAddress(finding.metadata.to);
    if (!(targetAddress in varietyTokenAddresses)) {
      varietyTokenAddresses[targetAddress] = new Set();
    }
    varietyTokenAddresses[targetAddress].add(tokenAddress)
  }

  for (const finding of erc20_transfer_findings) {
    const tokenAddress = createAddress(finding.metadata.token);
    const fromAddress = createAddress(finding.metadata.from);
    const targetAddress = createAddress(finding.metadata.to);
    const amount = finding.metadata.amount;

    if (labels.exchange.isExchangeAddress(targetAddress)) {
      if (skipAddresses.indexOf(fromAddress) === -1) {
        skipAddresses.push(fromAddress);
      }
      if (monitorAddressesCache.has(fromAddress)) {
        monitorAddressesCache.delete(fromAddress);
      }
    }

    // usually attackers won't spend native tokens to buy many ERC20 since it will increase the variety of his tokens,
    // and thus making laundering harder.
    if (createAddress(txEvent.transaction.from) === targetAddress
      && ethers.BigNumber.from(txEvent.transaction.value).gt(0)
      // @ts-ignore
      && varietyTokenAddresses[targetAddress].size > 1
    ) {
      continue
    }
    const _transactionCount = fromAddress === txEvent.transaction.from ? txEvent.transaction.nonce : await cachedGetTransactionCount(fromAddress, blockNumber) + 1;
    if (await skipChecking(targetAddress, blockNumber)
      || skipAddresses.indexOf(fromAddress) !== -1
      || _transactionCount === 0
      || await isContract(fromAddress))
    {
      continue
    }
    possiblePhishingAddress.add(targetAddress)

    await addRecord(fromAddress, tokenAddress, targetAddress, ethers.BigNumber.from(amount), timestamp, blockNumber);
  }

  // check erc721 transfer
  const erc721_transfer_findings = await erc721TransfersHandler.handle(txEvent);
  for (const finding of erc721_transfer_findings) {
    const tokenAddress = createAddress(finding.metadata.token);
    const fromAddress = createAddress(finding.metadata.from);
    const targetAddress = createAddress(finding.metadata.to);

    if (labels.exchange.isExchangeAddress(targetAddress)) {
      if (skipAddresses.indexOf(fromAddress) === -1) {
        skipAddresses.push(fromAddress);
      }
      if (monitorAddressesCache.has(fromAddress)) {
        monitorAddressesCache.delete(fromAddress);
      }
    }

    // usually attackers won't spend native tokens to buy ERC721 due to liquidity shortage.
    // however, many traders will.
    if (createAddress(txEvent.transaction.from) === targetAddress && ethers.BigNumber.from(txEvent.transaction.value).gt(0)) {
      continue
    }
    const _transactionCount = fromAddress === txEvent.transaction.from ? txEvent.transaction.nonce : await cachedGetTransactionCount(fromAddress, blockNumber);
    if (await skipChecking(targetAddress, blockNumber)
      || skipAddresses.indexOf(fromAddress) !== -1
      || _transactionCount === 0
      || await isContract(fromAddress)
    ) {
      continue
    }
    possiblePhishingAddress.add(targetAddress)

    await addRecord(fromAddress, tokenAddress, targetAddress, ethers.BigNumber.from(1), timestamp, blockNumber);
  }

  // Analyze the results
  const possiblePhishingAddressList = Array.from(possiblePhishingAddress);
  for (const address of possiblePhishingAddressList) {
    // @ts-ignore
    if (skipAddresses.indexOf(address) !== -1) {
      continue;
    }
    const transfers = tokenTransferInCache.get(address);
    if (!transfers) {
      continue;
    }
    const distinctFromAddress = new Set(transfers.map((t: any) => t.fromAddress));
    const drainRate = transfers.filter((t: any) => t.drained).length / transfers.length;
    // @ts-ignore
    if ((!(await isContract(address))) && distinctFromAddress.size > numTransferToEOAThreshold) {
      findings.push(
        Finding.fromObject({
          name: "Possible phishing EOA",
          description: "A possible phishing address was detected",
          alertId: "PHISHING-DETECTED",
          severity: FindingSeverity.Low,
          type: FindingType.Suspicious,
          metadata: {
            // @ts-ignore
            possiblePhishingAddress: address,
            totalPossibleVictims: distinctFromAddress.size.toString(),
          },
        })
      );
    }

    if (distinctFromAddress.size > numTransferThreshold && drainRate > drainRateThreshold) {
      findings.push(
        Finding.fromObject({
          name: "Possible phishing S1",
          description: `Tokens are drained and transferred to another account in a short time`,
          alertId: "PHISHING-DETECTED",
          severity: FindingSeverity.Medium,
          type: FindingType.Suspicious,
          metadata: {
            // @ts-ignore
            possiblePhishingAddress: address,
            totalPossibleVictims: distinctFromAddress.size.toString(),
            drainRate: drainRate.toString(),
          },
        })
      );
    }
  }

  return findings;
}

// If monitored suspicious address perform transactions to reduce its token variety,
// it becomes more suspicious (unlike LP).
const handleTokenVarietyReduction: HandleTransaction = async (
    txEvent: TransactionEvent,
) => {
  const blacklistedAddressesHandler = new handlers.BlacklistedAddresses({
    addresses: Array.from(monitorAddressesCache.keys()),
    onFinding(metadata) {
      return Finding.from({
        name: "Monitored Address",
        description: "A transaction involving a monitored address was found",
        alertId: "MONITORED ADDRESSES FOUND",
        severity: FindingSeverity.Info,
        type: FindingType.Info,
        metadata: {},
        addresses: metadata.addresses,
      });
    },
  });

  const findings: Finding[] = [];

  const blacklisted_findings = await blacklistedAddressesHandler.handle(txEvent);
  if (blacklisted_findings.length === 0) {
    return findings;
  }

  // check if the balance of the related token becomes 0
  // eth native
  if (ethers.BigNumber.from(txEvent.transaction.value).gt(0) && !!txEvent.transaction.to) {
    const fromAddress = createAddress(txEvent.transaction.from);
    const targetAddress = createAddress(txEvent.transaction.to);
    // hackers will not link their phishing address to their real identity
    if (labels.exchange.isExchangeAddress(targetAddress)) {
      if (skipAddresses.indexOf(fromAddress) === -1) {
        skipAddresses.push(fromAddress);
      }
      skipAddresses.push(fromAddress);
      if (monitorAddressesCache.has(fromAddress)) {
        monitorAddressesCache.delete(fromAddress);
      }
    } else {
      if (monitorAddressesCache.has(fromAddress)) {
        const currentBalance = await getEthersProvider().getBalance(fromAddress, txEvent.block.number);
        if (currentBalance.eq(0)) {
          findings.push(
            Finding.fromObject({
              name: "Possible phishing S2",
              description: `ETH in a monitored address is drained`,
              alertId: "VARIETY-REDUCTION",
              severity: FindingSeverity.Medium,
              type: FindingType.Suspicious,
              metadata: {
                // @ts-ignore
                possiblePhishingAddress: fromAddress,
              },
            })
          );
        }
      }
    }
  }

  const eth_transfer_findings = await ethTransfersHandler.handle(txEvent);
  for (const finding of eth_transfer_findings) {
    const fromAddress = createAddress(finding.metadata.from);
    const targetAddress = createAddress(finding.metadata.to);

    if (labels.exchange.isExchangeAddress(targetAddress)) {
      if (skipAddresses.indexOf(fromAddress) === -1) {
        skipAddresses.push(fromAddress);
      }
      skipAddresses.push(fromAddress);
      if (monitorAddressesCache.has(fromAddress)) {
        monitorAddressesCache.delete(fromAddress);
      }
      continue;
    }

    if (monitorAddressesCache.has(fromAddress)) {
      const currentBalance = await getEthersProvider().getBalance(fromAddress, txEvent.block.number);
      if (currentBalance.eq(0)) {
        findings.push(
          Finding.fromObject({
            name: "Possible phishing S2",
            description: `ETH in a monitored address is drained`,
            alertId: "VARIETY-REDUCTION",
            severity: FindingSeverity.Medium,
            type: FindingType.Suspicious,
            metadata: {
              // @ts-ignore
              possiblePhishingAddress: fromAddress,
            },
          })
        );
      }
    }
  }

  // erc20
  const erc20_transfer_findings = await erc20TransfersHandler.handle(txEvent);
  for (const finding of erc20_transfer_findings) {
    const tokenAddress = createAddress(finding.metadata.token);
    const fromAddress = createAddress(finding.metadata.from);
    const targetAddress = createAddress(finding.metadata.to);

    if (labels.exchange.isExchangeAddress(targetAddress)) {
      if (skipAddresses.indexOf(fromAddress) === -1) {
        skipAddresses.push(fromAddress);
      }
      skipAddresses.push(fromAddress);
      if (monitorAddressesCache.has(fromAddress)) {
        monitorAddressesCache.delete(fromAddress);
      }
      continue;
    }

    if (monitorAddressesCache.has(fromAddress)) {
      const currentBalance = await getTokenBalance(tokenAddress, fromAddress, txEvent.block.number);
      if (currentBalance.eq(0)) {
        findings.push(
          Finding.fromObject({
            name: "Possible phishing S2",
            description: `ERC20 Tokens in a monitored address are drained`,
            alertId: "VARIETY-REDUCTION",
            severity: FindingSeverity.Medium,
            type: FindingType.Suspicious,
            metadata: {
              // @ts-ignore
              possiblePhishingAddress: fromAddress,
              tokenAddress: tokenAddress,
            },
          })
        );
      }
    }
  }

  // erc721
  const erc721_transfer_findings = await erc721TransfersHandler.handle(txEvent);
  for (const finding of erc721_transfer_findings) {
    const tokenAddress = createAddress(finding.metadata.token);
    const fromAddress = createAddress(finding.metadata.from);
    const targetAddress = createAddress(finding.metadata.to);

    if (labels.exchange.isExchangeAddress(targetAddress)) {
      if (skipAddresses.indexOf(fromAddress) === -1) {
        skipAddresses.push(fromAddress);
      }
      skipAddresses.push(fromAddress);
      if (monitorAddressesCache.has(fromAddress)) {
        monitorAddressesCache.delete(fromAddress);
      }
      continue;
    }

    if (monitorAddressesCache.has(fromAddress)) {
      const currentBalance = await getTokenBalance(tokenAddress, fromAddress, txEvent.block.number);
      if (currentBalance.eq(0)) {
        findings.push(
          Finding.fromObject({
            name: "Possible phishing S2",
            description: `ERC721 Tokens in a monitored address are drained`,
            alertId: "VARIETY-REDUCTION",
            severity: FindingSeverity.Medium,
            type: FindingType.Suspicious,
            metadata: {
              // @ts-ignore
              possiblePhishingAddress: fromAddress,
              tokenAddress: tokenAddress,
            },
          })
        );
      }
    }
  }

  return findings;
}

// If monitored suspicious address starts to send funds to money laundering protocols or simply send out.
// It becomes more suspicious as it may want to transfer the funds.
const handleTransferOutOrLaundering: HandleTransaction = async (
  txEvent: TransactionEvent
) => {
  const blacklistedAddressesHandler = new handlers.BlacklistedAddresses({
    addresses: Array.from(monitorAddressesCache.keys()),
    onFinding(metadata) {
      return Finding.from({
        name: "Monitored Address",
        description: "A transaction involving a monitored address was found",
        alertId: "MONITORED ADDRESSES FOUND",
        severity: FindingSeverity.Info,
        type: FindingType.Info,
        metadata: {},
        addresses: metadata.addresses,
      });
    },
  });

  const findings: Finding[] = [];

  const blacklisted_findings = await blacklistedAddressesHandler.handle(txEvent);
  if (blacklisted_findings.length === 0) {
    return findings;
  }

  // check TC
  const results: any = await getAlerts({
    botIds: ["0x4adff9a0ed29396d51ef3b16297070347aab25575f04a4e2bd62ec43ca4508d2"],
    transactionHash: txEvent.transaction.hash,
    severities: ['HIGH'],
    chainId: txEvent.network,
  });

  if (results.alerts.length > 0) {
    const relatedAddress = results.alerts[0].addresses;
    const relatedAddressLowerCase = relatedAddress.map((address: string) => address.toLowerCase());
    for (const address of Array.from(monitorAddressesCache.keys())) {
      // @ts-ignore
      if (relatedAddressLowerCase.indexOf(address.toLowerCase()) !== -1) {
        findings.push(Finding.fromObject({
          name: "Possible phishing S3",
          description: `A money laundering activity involving a monitored address is found`,
          alertId: "TC-WITH-MONITORED-ADDRESS",
          severity: FindingSeverity.Medium,
          type: FindingType.Suspicious,
          metadata: {
            // @ts-ignore
            possiblePhishingAddress: address,
          },
        }));
      }
    }
  }

  return findings
}

const handleTransaction: HandleTransaction = async (
  txEvent: TransactionEvent
) => {
  // update transaction count
  if (transactionCountCache.has(txEvent.transaction.from)) {
    const count = transactionCountCache.get(txEvent.transaction.from);
    transactionCountCache.set(txEvent.transaction.from, count + 1);
  }

  const findings: Finding[] = [];

  // limiting this agent to emit only 5 findings so that the alert feed is not spammed
  if (findingsCount >= 5) return findings;

  // get some suspicious approval EOAs.
  if (approvalCheck) {
    let hasNext = true;
    let startingCursor = undefined;

    while(hasNext) {
      const results: any = await getAlerts({
        botIds: ["0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14"],
        chainId: txEvent.network,
        alertId: "ICE-PHISHING-HIGH-NUM-APPROVALS",
        transactionHash: txEvent.transaction.hash,
      })

      hasNext = results.pageInfo.hasNextPage;
      startingCursor = results.pageInfo.endCursor;

      for (const alert of results.alerts) {
        const regex = /(0x[a-fA-F0-9]{40}).*(\d) assets.*(\d) accounts.*(\d) days/;
        const desc = alert.description;
        let m, container: any[] = [];

        if ((m = regex.exec(desc)) !== null) {
          m.forEach((match: any, groupIndex: any) => {
            container.push(match);
          });
        }

        const targetAddress = createAddress(container[1]);
        if (await skipChecking(targetAddress, txEvent.block.number)) {
          continue;
        }
        const averageApprovalPerDay = container[2] * container[3] / container[4];
        if (averageApprovalPerDay > approvalThreshold) {
          approvalsCache.set(targetAddress, true);
        }
      }
    }
  }

  // analyze transfer event and try to get some insights.
  const tokenTransferFindings = await handleTokenTransfer(txEvent);
  for (const tokenTransferFinding of tokenTransferFindings) {
    const phishingAddress = tokenTransferFinding.metadata.possiblePhishingAddress;
    if (monitorAddressesCache.has(phishingAddress)) {
      continue;
    }
    const transfers = tokenTransferInCache.get(phishingAddress);
    if (!transfers) {
      continue;
    }
    const distinctFromAddress = new Set(transfers.map((t: any) => t.fromAddress));
    const drainRate = transfers.filter((t: any) => t.drained).length / transfers.length;
    monitorAddressesCache.set(phishingAddress, true);
    if (approvalsCache.has(phishingAddress)) {
      if (tokenTransferFinding.name === "Possible phishing EOA") {
        findings.push(
          Finding.fromObject({
            name: "Possible phishing activities with many transfers and approvals",
            description: `The reported EOA address had received funds from ${distinctFromAddress.size} distinct addresses. Will start monitor this address for more evidence. The reported address had gained approvals previously.`,
            alertId: "POSSIBLE-PHISHING-ACTIVITIES-EOA",
            severity: FindingSeverity.Medium,
            type: FindingType.Suspicious,
            metadata: {
              phishingAddress: phishingAddress,
              transactionHash: txEvent.transaction.hash,
            },
          })
        );
      }
      if (tokenTransferFinding.name === "Possible phishing S1") {
        findings.push(
          Finding.fromObject({
            name: "Possible phishing activities with high approvals",
            description: `The reported address had received funds from ${distinctFromAddress.size} distinct addresses, having a drain rate of ${drainRate}. Will start monitor this address for more evidence. The reported address had gained approvals previously.`,
            alertId: "POSSIBLE-PHISHING-ACTIVITIES",
            severity: FindingSeverity.Medium,
            type: FindingType.Suspicious,
            metadata: {
              phishingAddress: phishingAddress,
              transactionHash: txEvent.transaction.hash,
            },
          })
        );
      }
    } else {
      if (tokenTransferFinding.name === "Possible phishing EOA") {
        findings.push(
          Finding.fromObject({
            name: "Possible phishing activities with many transfers",
            description: `The reported EOA address had received funds from ${distinctFromAddress.size} distinct addresses. Will start monitor this address for more evidence.`,
            alertId: "POSSIBLE-PHISHING-ACTIVITIES-EOA",
            severity: FindingSeverity.Medium,
            type: FindingType.Suspicious,
            metadata: {
              phishingAddress: phishingAddress,
              transactionHash: txEvent.transaction.hash,
            },
          })
        );
      }
      if (tokenTransferFinding.name === "Possible phishing S1") {
        findings.push(
          Finding.fromObject({
            name: "Possible phishing activities",
            description: `The reported address had received funds from ${distinctFromAddress.size} distinct addresses, having a drain rate of ${drainRate}. Will start monitor this address for more evidence.`,
            alertId: "POSSIBLE-PHISHING-ACTIVITIES",
            severity: FindingSeverity.Medium,
            type: FindingType.Suspicious,
            metadata: {
              phishingAddress: phishingAddress,
              transactionHash: txEvent.transaction.hash,
            },
          })
        );
      }
    }
  }

  const tokenVarietyReductionFindings = await handleTokenVarietyReduction(txEvent);
  for (const tokenVarietyReductionFinding of tokenVarietyReductionFindings) {
    const phishingAddress = tokenVarietyReductionFinding.metadata.possiblePhishingAddress;
    const transfers = tokenTransferInCache.get(phishingAddress);
    if (!transfers) {
      continue;
    }
    const distinctFromAddress = new Set(transfers.map((t: any) => t.fromAddress));
    const drainRate = transfers.filter((t: any) => t.drained).length / transfers.length;
    findings.push(
      Finding.fromObject({
        name: "Confirmed phishing activities",
        description: `The reported address had received funds from ${distinctFromAddress.size} distinct addresses, having a drain rate of ${drainRate}. It just made a transfer or swap to reduce its token variety.`,
        alertId: "CONFIRMED-PHISHING-ACTIVITIES",
        severity: FindingSeverity.High,
        type: FindingType.Suspicious,
        metadata: {
          phishingAddress: phishingAddress,
          transactionHash: txEvent.transaction.hash,
        },
      })
    );
  }

  const transferOutOrLaunderingFindings = await handleTransferOutOrLaundering(txEvent);
  for (const transferOutOrLaunderingFinding of transferOutOrLaunderingFindings) {
    const phishingAddress = transferOutOrLaunderingFinding.metadata.possiblePhishingAddress;
    const transfers = tokenTransferInCache.get(phishingAddress);
    if (!transfers) {
      continue;
    }
    const distinctFromAddress = new Set(transfers.map((t: any) => t.fromAddress));
    const drainRate = transfers.filter((t: any) => t.drained).length / transfers.length;
    findings.push(
      Finding.fromObject({
        name: "Confirmed phishing activities",
        description: `The reported address had received funds from ${distinctFromAddress.size} distinct addresses, having a drain rate of ${drainRate}. It just made a interaction with TC.`,
        alertId: "CONFIRMED-PHISHING-ACTIVITIES",
        severity: FindingSeverity.High,
        type: FindingType.Suspicious,
        metadata: {
          phishingAddress: phishingAddress,
          transactionHash: txEvent.transaction.hash,
        },
      })
    );
  }

  return findings;
};

const tryCatchHandleTransaction: HandleTransaction = async (
  txEvent: TransactionEvent
) => {
  try {
    return await handleTransaction(txEvent);
  } catch (error) {
    console.error(error);
    return [];
  }
}

export default {
  handleTransaction: tryCatchHandleTransaction,
};
