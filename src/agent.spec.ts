import {
  FindingType,
  FindingSeverity,
  Finding,
  HandleTransaction,
  createTransactionEvent,
  ethers,
} from "forta-agent";
import agent from "./agent";

jest.setTimeout(60 * 60 * 1000);

describe("Should report phishing with real data from an phishing incident", () => {
  let handleTransaction: HandleTransaction;

  beforeAll(() => {
    handleTransaction = agent.handleTransaction;
  });

  describe("SUI Network Discord Hack @ 2022", () => {
    it("returns findings", async () => {
	    const tx1 = createTransactionEvent({
				type: 0,
		    addresses: {
			    '0x53857d9718d0133642248d40e9fe7f38d105d584': true,
			    '0x8bce2ecae08d11a591b4196151212f0dfa63319f': true
		    },
		    block: {
			    hash: '0x3b85b09f9177852034904458c62adc117ca87f2ee85994d9668a7c4c5cd2bafb',
			    number: 15422056,
			    timestamp: 1661610091
		    },
		    contractAddress: null,
		    logs: [],
		    network: 1,
		    traces: [],
		    transaction: {
			    hash: '0x1027cadc27425cae0be87fd1df8731cf5071556d294515488cf524d5d13cda05',
			    from: '0x53857d9718d0133642248d40e9fe7f38d105d584',
			    to: '0x8bce2ecae08d11a591b4196151212f0dfa63319f',
			    nonce: 3,
			    gas: '0x5208',
			    gasPrice: '0x4aea90fc5',
			    value: '0x3b548fbfbfc000',
			    data: '0x',
			    r: '0xe803aa5bae33010ea36584c644d1fc10a96096c0eb09394813844228a76e44ae',
			    s: '0x41a5afe260c3efeef4593ff89c6a77a6730103b16e93faaba62f864d024721c8',
			    v: '0x1'
		    },
	    });
	    const tx2 = createTransactionEvent({
		    type: 0,
		    addresses: {
			    '0x4757125cd974a8aae70fc78e286e803e5ad5a119': true,
			    '0x8bce2ecae08d11a591b4196151212f0dfa63319f': true
		    },
		    block: {
			    hash: '0xba596db89b1aa473205bff474417e5357ff38f988b9fe31b3883e3610c992755',
			    number: 15422144,
			    timestamp: 1661611255
		    },
		    contractAddress: null,
		    logs: [],
		    network: 1,
		    traces: [],
		    transaction: {
			    hash: '0x367c25a023476d65ec3e1ba8391a79336184549cfbb3eff11097734293373331',
			    from: '0x4757125cd974a8aae70fc78e286e803e5ad5a119',
			    to: '0x8bce2ecae08d11a591b4196151212f0dfa63319f',
			    nonce: 17,
			    gas: '0x55f0',
			    gasPrice: '0x338589934',
			    value: '0x3d41d0acd47c90',
			    data: '0x',
			    r: '0xe6ff261e3c06dc8f3a8c35f57299afb35cabe9a0a1b8a67aecc9c44ae5cb23cc',
			    s: '0x7a45dd35d50497970f22954b0b5a5746e55600ed9411173b9464e4908a27440e',
			    v: '0x26'
		    },
	    });
	    const tx3 = createTransactionEvent({
		    type: 0,
		    addresses: {
			    '0x73a746036f7813079881b41aae45b03abb547093': true,
			    '0x8bce2ecae08d11a591b4196151212f0dfa63319f': true
		    },
		    block: {
			    hash: '0x00baed5c4c7fe502c6555c09ca4e3c00d774597ea1459ffe0703e7f8c88347b5',
			    number: 15422152,
			    timestamp: 1661611357
		    },
		    contractAddress: null,
		    logs: [],
		    network: 1,
		    traces: [],
		    transaction: {
			    hash: '0x7026918c913721b8839b2fcbcf4b40c2c533b7f2522db71a794f18eb0df5262b',
			    from: '0x73a746036f7813079881b41aae45b03abb547093',
			    to: '0x8bce2ecae08d11a591b4196151212f0dfa63319f',
			    nonce: 9,
			    gas: '0x55f0',
			    gasPrice: '0x381590bd9',
			    value: '0x30ded1dcb7f3f4',
			    data: '0x',
			    r: '0x3ac566180796d9c89a364edb59c6d904347463d0ce53e23862f14715ee0ab8fa',
			    s: '0x6fe99d31c6b70fc32ba806fdc3fac0b220888eeef38e8eef98a755962cabf249',
			    v: '0x25'
		    },
	    });
	    const tx4 = createTransactionEvent({
		    type: 0,
		    addresses: {
			    '0xc096a30d0983f68a92e2014229c035bf9a29a792': true,
			    '0x8bce2ecae08d11a591b4196151212f0dfa63319f': true
		    },
		    block: {
			    hash: '0x4373052824f327ab7aa300a164bc4b3677bf82dfe289f7c42d7b8cd50999920f',
			    number: 15422166,
			    timestamp: 1661611461
		    },
		    contractAddress: null,
		    logs: [],
		    network: 1,
		    traces: [],
		    transaction: {
			    hash: '0xa062c03d89a4ac77e56b3c6124dc3342cf147bece934075c5d2f41ee60ad3c39',
			    from: '0xc096a30d0983f68a92e2014229c035bf9a29a792',
			    to: '0x8bce2ecae08d11a591b4196151212f0dfa63319f',
			    nonce: 59,
			    gas: '0x55f0',
			    gasPrice: '0x257289f10',
			    value: '0x2838f813bc7640',
			    data: '0x',
			    r: '0xb65692bfdbfa935d7405858278f7bad959846d3030a64972e0f281408ad4bbf6',
			    s: '0x1a2e3c5a58abdcd778109ce1c3fbe20f855ead6d49b7ba6892b8ec165162dade',
			    v: '0x26'
		    },
	    });
	    const tx5 = createTransactionEvent({
		    type: 0,
		    addresses: {
			    '0x8bce2ecae08d11a591b4196151212f0dfa63319f': true,
			    '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48': true
		    },
		    block: {
			    hash: '0x7b58c0fa50a0b26dfd564c99e212e34cbb0cbc98b241bb10dd5f5d826b1cac84',
			    number: 15422168,
			    timestamp: 1661611528
		    },
		    contractAddress: null,
		    logs: [
			    {
				    address: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
				    topics: [
					    '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
					    '0x000000000000000000000000f1b75e876ed49eeb522e4ad1b5f8c88a0361a727',
					    '0x0000000000000000000000008bce2ecae08d11a591b4196151212f0dfa63319f'
				    ],
				    data: '0x00000000000000000000000000000000000000000000000000000000317105bd',
				    logIndex: 271,
				    blockNumber: 15422168,
				    blockHash: '0x7b58c0fa50a0b26dfd564c99e212e34cbb0cbc98b241bb10dd5f5d826b1cac84',
				    transactionIndex: 140,
				    transactionHash: '0xad75ae5a8a9795c1d584209a37f4cf5c39868863adb9a3ec402254315ff855bb',
				    removed: false
			    }
		    ],
		    network: 1,
		    traces: [],
		    transaction: {
			    hash: '0xad75ae5a8a9795c1d584209a37f4cf5c39868863adb9a3ec402254315ff855bb',
			    from: '0x8bce2ecae08d11a591b4196151212f0dfa63319f',
			    to: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
			    nonce: 1,
			    gas: '0x1a965',
			    gasPrice: '0x1f404405c',
			    value: '0x0',
			    data: '0x23b872dd000000000000000000000000f1b75e876ed49eeb522e4ad1b5f8c88a0361a7270000000000000000000000008bce2ecae08d11a591b4196151212f0dfa63319f00000000000000000000000000000000000000000000000000000000317105bd',
			    r: '0xc5bbf8aaf6d19f2594940569de7c4f2930cf9fed0ab0ce3c260f073c9a6feba2',
			    s: '0x573e6815f31dd0935f4422cc752f40357fa18605dba9f8a55c1a89b600f34e76',
			    v: '0x1'
		    },
	    });
	    const tx6 = createTransactionEvent({
		    type: 0,
		    addresses: {
			    '0x77f33f91a21289db8cf79f97d935f177157d0b37': true,
			    '0x8bce2ecae08d11a591b4196151212f0dfa63319f': true
		    },
		    block: {
			    hash: '0x60ea7fb852f19dd4db5041abf2152d26601faffbbb43662e316dfac770c91fe9',
			    number: 15422317,
			    timestamp: 1661613234
		    },
		    contractAddress: null,
		    logs: [],
		    network: 1,
		    traces: [],
		    transaction:  {
			    hash: '0xd760b4444bedf7a4e8367b74ee5a951d1c62e0ffa6f3ae160c2f29084c540434',
			    from: '0x77f33f91a21289db8cf79f97d935f177157d0b37',
			    to: '0x8bce2ecae08d11a591b4196151212f0dfa63319f',
			    nonce: 9,
			    gas: '0x55f0',
			    gasPrice: '0x29de33c97',
			    value: '0x1bfbe6555d19680',
			    data: '0x',
			    r: '0x711ef6b7121f1bb444ece732d7932f96bac69e34c04bb2440ad7005f86e53960',
			    s: '0x5d45615584481e46d79b790b3c728bd7a84e3975af3175b03b55bb4d53a1500e',
			    v: '0x25'
		    },
	    });
	    const tx7 = createTransactionEvent({
		    type: 0,
		    addresses: {
			    '0x8bce2ecae08d11a591b4196151212f0dfa63319f': true,
			    '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45': true,
			    '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48': true,
			    '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2': true,
			    '0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640': true
		    },
		    block: {
			    hash: '0xb3471705b3903ea755dcc5fd24056e3248310754985a8f4d11024cfdd04ac3ad',
			    number: 15422415,
			    timestamp: 1661614401
		    },
		    contractAddress: null,
		    logs: [
			    {
				    address: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
				    topics: [
					    '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925',
					    '0x0000000000000000000000008bce2ecae08d11a591b4196151212f0dfa63319f',
					    '0x00000000000000000000000068b3465833fb72a70ecdf485e0e4c7bd8665fc45'
				    ],
				    data: '0x00000000000000000000000000000000000000000000000000000000317105bd',
				    logIndex: 343,
				    blockNumber: 15422415,
				    blockHash: '0xb3471705b3903ea755dcc5fd24056e3248310754985a8f4d11024cfdd04ac3ad',
				    transactionIndex: 126,
				    transactionHash: '0x4ee475c53f0a0d32b698459f4a7141fddf7fa3c5207d9010a3d4550241293fcd',
				    removed: false
			    },
			    {
				    address: '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2',
				    topics: [
					    '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
					    '0x00000000000000000000000088e6a0c2ddd26feeb64f039a2c41296fcb3f5640',
					    '0x00000000000000000000000068b3465833fb72a70ecdf485e0e4c7bd8665fc45'
				    ],
				    data: '0x00000000000000000000000000000000000000000000000007c7a6d555d04332',
				    logIndex: 344,
				    blockNumber: 15422415,
				    blockHash: '0xb3471705b3903ea755dcc5fd24056e3248310754985a8f4d11024cfdd04ac3ad',
				    transactionIndex: 126,
				    transactionHash: '0x4ee475c53f0a0d32b698459f4a7141fddf7fa3c5207d9010a3d4550241293fcd',
				    removed: false
			    },
			    {
				    address: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
				    topics: [
					    '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
					    '0x0000000000000000000000008bce2ecae08d11a591b4196151212f0dfa63319f',
					    '0x00000000000000000000000088e6a0c2ddd26feeb64f039a2c41296fcb3f5640'
				    ],
				    data: '0x00000000000000000000000000000000000000000000000000000000317105bd',
				    logIndex: 345,
				    blockNumber: 15422415,
				    blockHash: '0xb3471705b3903ea755dcc5fd24056e3248310754985a8f4d11024cfdd04ac3ad',
				    transactionIndex: 126,
				    transactionHash: '0x4ee475c53f0a0d32b698459f4a7141fddf7fa3c5207d9010a3d4550241293fcd',
				    removed: false
			    },
			    {
				    address: '0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640',
				    topics: [
					    '0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67',
					    '0x00000000000000000000000068b3465833fb72a70ecdf485e0e4c7bd8665fc45',
					    '0x00000000000000000000000068b3465833fb72a70ecdf485e0e4c7bd8665fc45'
				    ],
				    data: '0x00000000000000000000000000000000000000000000000000000000317105bdfffffffffffffffffffffffffffffffffffffffffffffffff838592aaa2fbcce000000000000000000000000000000000000659358bac7b5e3164d6c99204a9d00000000000000000000000000000000000000000000000139bc573ffb3a922d0000000000000000000000000000000000000000000000000000000000031a41',
				    logIndex: 346,
				    blockNumber: 15422415,
				    blockHash: '0xb3471705b3903ea755dcc5fd24056e3248310754985a8f4d11024cfdd04ac3ad',
				    transactionIndex: 126,
				    transactionHash: '0x4ee475c53f0a0d32b698459f4a7141fddf7fa3c5207d9010a3d4550241293fcd',
				    removed: false
			    },
			    {
				    address: '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2',
				    topics: [
					    '0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65',
					    '0x00000000000000000000000068b3465833fb72a70ecdf485e0e4c7bd8665fc45'
				    ],
				    data: '0x00000000000000000000000000000000000000000000000007c7a6d555d04332',
				    logIndex: 347,
				    blockNumber: 15422415,
				    blockHash: '0xb3471705b3903ea755dcc5fd24056e3248310754985a8f4d11024cfdd04ac3ad',
				    transactionIndex: 126,
				    transactionHash: '0x4ee475c53f0a0d32b698459f4a7141fddf7fa3c5207d9010a3d4550241293fcd',
				    removed: false
			    }
		    ],
		    network: 1,
		    traces: [],
		    transaction: {
			    hash: '0x4ee475c53f0a0d32b698459f4a7141fddf7fa3c5207d9010a3d4550241293fcd',
			    from: '0x8bce2ecae08d11a591b4196151212f0dfa63319f',
			    to: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45',
			    nonce: 8,
			    gas: '0x3fd8d',
			    gasPrice: '0x1dc2cb252',
			    value: '0x0',
			    data: '0x5ae401dc00000000000000000000000000000000000000000000000000000000630a402e0000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000160000000000000000000000000000000000000000000000000000000000000028000000000000000000000000000000000000000000000000000000000000000c4f3995c67000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000000000000000000000000000000000000317105bd00000000000000000000000000000000000000000000000000000000630a44bb000000000000000000000000000000000000000000000000000000000000001b0856196b2914523efc1b6fbdbc361102bfca1225911c04fc1cdc5ac54e587e844979e30a8d15a6baa313d420c5df4965a755f71c1c79e0f52780df5bc9f9bc830000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e404e45aaf000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc200000000000000000000000000000000000000000000000000000000000001f4000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000317105bd00000000000000000000000000000000000000000000000007bf4eeb8623859e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004449404b7c00000000000000000000000000000000000000000000000007bf4eeb8623859e0000000000000000000000008bce2ecae08d11a591b4196151212f0dfa63319f00000000000000000000000000000000000000000000000000000000',
			    r: '0xf69bbb67b75ea5f15d6b4d367e73eb47ac08cf15dca49603ece388452e9eb6d2',
			    s: '0x2e83b4c46b5dc4af8d6d28577cf09166da4dc1efae99ffd8b43fe1b84e93427a',
			    v: '0x0'
		    },
	    });

	    await handleTransaction(tx1);
	    await handleTransaction(tx2);
	    await handleTransaction(tx3);
	    await handleTransaction(tx4);
	    await handleTransaction(tx5);

	    let findings = await handleTransaction(tx6);
	    expect(findings).toStrictEqual([
		    Finding.fromObject({
			    name: "Possible phishing activities",
			    description: 'The reported address had received funds from 6 distinct addresses, having a drain rate of 1. Will start monitor this address for more evidence.',
			    alertId: "POSSIBLE-PHISHING-ACTIVITIES",
			    protocol: 'ethereum',
			    severity: FindingSeverity.Medium,
			    type: FindingType.Suspicious,
			    metadata: {
				    phishingAddress: '0x8bce2ecae08d11a591b4196151212f0dfa63319f',
				    transactionHash: '0xd760b4444bedf7a4e8367b74ee5a951d1c62e0ffa6f3ae160c2f29084c540434'
			    },
			    addresses: [],
		    }),
	    ]);

	    findings = await handleTransaction(tx7);
	    expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Confirmed phishing activities",
          description: 'The reported address had received funds from 6 distinct addresses, having a drain rate of 1. It just made a transfer or swap to reduce its token variety.',
          alertId: "CONFIRMED-PHISHING-ACTIVITIES",
	        protocol: 'ethereum',
	        severity: FindingSeverity.High,
          type: FindingType.Suspicious,
          metadata: {
	          phishingAddress: '0x8bce2ecae08d11a591b4196151212f0dfa63319f',
	          transactionHash: '0x4ee475c53f0a0d32b698459f4a7141fddf7fa3c5207d9010a3d4550241293fcd'
          },
	        addresses: [],
        }),
      ]);
    });
  });

	describe("Project Galaxy Discord Hack @ 2022", () => {
		it("returns findings", async () => {
			const tx1 = createTransactionEvent({
				type: 0,
				addresses: {
					'0x7cdd33ec534fd8f270c002ef9db3b34f7e4ccaf3': true,
					'0x8a8fa36b68df2eb9762b053303380992fdbdf7ed': true
				},
				block: {
					hash: '0xd96b7b92597906ef3cf2a9373e428ec797ae4eb56913a1cdc3e32bc34443fc40',
					number: 14619599,
					timestamp: 1650426438
				},
				contractAddress: null,
				logs: [],
				network: 1,
				traces: [],
				transaction: {
					hash: '0xdd7c5c1943b16cd86a9bfca955f67caea43260a3f915888ac5fe4a685da4b0ea',
					from: '0x7cdd33ec534fd8f270c002ef9db3b34f7e4ccaf3',
					to: '0x8a8fa36b68df2eb9762b053303380992fdbdf7ed',
					nonce: 248,
					gas: '0x5208',
					gasPrice: '0xb9c06635e',
					value: '0x16345785d8a0000',
					data: '0x',
					r: '0xab1b19361d244755ef24a0060a6b9d258e1a4a740ccd191410184584092d5a5c',
					s: '0x64ed0d04b83c3d20ed328729d7bcdf0074fdf18f5bac01d01712c6fd11e25f85',
					v: '0x0'
				},
			});
			const tx2 = createTransactionEvent({
				type: 0,
				addresses: {
					'0x2424ae241ef3d6b7568982ab5c83d7ca28eec803': true,
					'0x8a8fa36b68df2eb9762b053303380992fdbdf7ed': true
				},
				block: {
					hash: '0x9660e5ea6a1d5e473b09c6851f7fb74ee638fb639b0a75c5e512b9b543d42b0f',
					number: 14619606,
					timestamp: 1650426555
				},
				contractAddress: null,
				logs: [],
				network: 1,
				traces: [],
				transaction: {
					hash: '0x4013b4acd87ddb27d4d9b53e10ffa450d3feed05a8926f0615674b2b32fca930',
					from: '0x2424ae241ef3d6b7568982ab5c83d7ca28eec803',
					to: '0x8a8fa36b68df2eb9762b053303380992fdbdf7ed',
					nonce: 16,
					gas: '0x5208',
					gasPrice: '0xb8a712411',
					value: '0x16345785d8a0000',
					data: '0x',
					r: '0xdb4a44b8d0256baf86949c2a39b9ca9044f08c5b3569d3912838c4fd8ff71100',
					s: '0x15ece8e2dd95e652968ff60063d72b19b4ef8e6c7fbe294b3ec29e7d17339635',
					v: '0x1'
				},
			});
			const tx3 = createTransactionEvent({
				type: 0,
				addresses: {
					'0xdcd1000cb62fae013aed379d9f1287d828bceaa3': true,
					'0x8a8fa36b68df2eb9762b053303380992fdbdf7ed': true
				},
				block: {
					hash: '0x3710eccf8c9acf1be1ab5e5108307453dabd5d90d1ed49001e52d0472e44cf85',
					number: 14619608,
					timestamp: 1650426622
				},
				contractAddress: null,
				logs: [],
				network: 1,
				traces: [],
				transaction: {
					hash: '0x7ff07472e522836c6711433b5d5245e4726f501e49f9a1a1b07cf88c14965075',
					from: '0xdcd1000cb62fae013aed379d9f1287d828bceaa3',
					to: '0x8a8fa36b68df2eb9762b053303380992fdbdf7ed',
					nonce: 147,
					gas: '0x5208',
					gasPrice: '0xe5028aff0',
					value: '0x16345785d8a0000',
					data: '0x',
					r: '0xd3f3b9d812540c10c45c79f8ba2688b921a7727a6f9db4959c8b1ee28090b6e2',
					s: '0xf304205750b2d2986558d6b556bd2fd1c145f5e390af14b4ef2a602f6cd6f3c',
					v: '0x1'
				},
			});
			const tx4 = createTransactionEvent({
				type: 0,
				addresses: {
					'0x176ab9b99b21e032bd9a9c261a6bf5dcc46fddd9': true,
					'0x8a8fa36b68df2eb9762b053303380992fdbdf7ed': true
				},
				block: {
					hash: '0x53ce5cadcf432f0e736c732ba09778d2e9e8e7957b9500c63d0c0fccf2405dc8',
					number: 14619552,
					timestamp: 1650425838
				},
				contractAddress: null,
				logs: [],
				network: 1,
				traces: [],
				transaction: {
					hash: '0x2533ed4febe5fcbaa0d7349aadab26a7b5ffcd9efd030e7fda9c3960782d6150',
					from: '0x176ab9b99b21e032bd9a9c261a6bf5dcc46fddd9',
					to: '0x8a8fa36b68df2eb9762b053303380992fdbdf7ed',
					nonce: 156,
					gas: '0x5208',
					gasPrice: '0xa46714cb9',
					value: '0x16345785d8a0000',
					data: '0x',
					r: '0x1ec63b304df71551020c6341806214a521c97ff576a995a63181ecb0aa043894',
					s: '0x6c6e04dd5f556a6300cb8b7c0c635c70c8e6bc949733a23c0961de4fdc6433ed',
					v: '0x0'
				},
			});
			const tx5 = createTransactionEvent({
				type: 0,
				addresses: {
					'0x2dd9c09a1b2fa93f2e1c47a9275a63e8733d8753': true,
					'0x8a8fa36b68df2eb9762b053303380992fdbdf7ed': true
				},
				block: {
					hash: '0xd8dd6f056ca1b64d938108cdd0c8b439d88a1d0b7c1d04e594d7a13641db3ae5',
					number: 14619616,
					timestamp: 1650426735
				},
				contractAddress: null,
				logs: [],
				network: 1,
				traces: [],
				transaction: {
					hash: '0x07ca6109cd1fe262ade5ef4f6406b11ff887ff4cb295126e0d6d4d9bb1ee0e66',
					from: '0x2dd9c09a1b2fa93f2e1c47a9275a63e8733d8753',
					to: '0x8a8fa36b68df2eb9762b053303380992fdbdf7ed',
					nonce: 24,
					gas: '0x5208',
					gasPrice: '0xb5ee204d0',
					value: '0x2c68af0bb140000',
					data: '0x',
					r: '0xce6e5560d151101d318c8d5b227ae0459f0a80728c89f57fa26b5b34e9de4754',
					s: '0x48603dc44c9483165dcce2c6241f8de57e42c578314cbde124f86d8b087fbaaa',
					v: '0x0'
				},
			});
			const tx6 = createTransactionEvent({
				type: 0,
				addresses: {
					'0x3d3b69457ce7e7998f19e85e018b5a296aed781e': true,
					'0x8a8fa36b68df2eb9762b053303380992fdbdf7ed': true
				},
				block: {
					hash: '0x1243ecd4f4cd7ba951443481dadc318ab9ff94dc463ea1ba3e3bb39698072d91',
					number: 14619575,
					timestamp: 1650426074
				},
				contractAddress: null,
				logs: [],
				network: 1,
				traces: [],
				transaction: {
					hash: '0x681a87fd12b705df8637a9d6a57c58ad24232f341a94bd2409b250f9345759fa',
					from: '0x3d3b69457ce7e7998f19e85e018b5a296aed781e',
					to: '0x8a8fa36b68df2eb9762b053303380992fdbdf7ed',
					nonce: 1053,
					gas: '0x5208',
					gasPrice: '0xb005a5501',
					value: '0x16345785d8a0000',
					data: '0x',
					r: '0x1aef5708ded1bc43058744d68b9bf192d4e76e5672b6ef1f65c9504ae5aac8c1',
					s: '0x3a029a181712a8f225a6f3ba0684c8c5272861a09b86afc2ca2b462ebe020163',
					v: '0x1'
				},
			});
			const tx7 = createTransactionEvent({
				type: 0,
				addresses: {
					'0xf1fe0a34e66d684f182a0886f795e5f22d0e64b6': true,
					'0x8a8fa36b68df2eb9762b053303380992fdbdf7ed': true
				},
				block: {
					hash: '0x7fed8df458da30bc26b87bc5e0c907a57a1be7aee0843686b7da278fede0c76e',
					number: 14619595,
					timestamp: 1650426378
				},
				contractAddress: null,
				logs: [],
				network: 1,
				traces: [],
				transaction: {
					hash: '0xe80f9233f4eaed072cf711c0f734b8720b2b3e1f0eb6ed3bd0085d871ac80c85',
					from: '0xf1fe0a34e66d684f182a0886f795e5f22d0e64b6',
					to: '0x8a8fa36b68df2eb9762b053303380992fdbdf7ed',
					nonce: 1150,
					gas: '0x5208',
					gasPrice: '0xcd0305fe6',
					value: '0x6f05b59d3b20000',
					data: '0x',
					r: '0xdd3412cc326ccb5b9bbca630c1aafb7e771dfd989c62e3f2f19dc1866387aba7',
					s: '0x2dc4b2043d2b6a8512a8971ee27246ce67482561b856fb774bc83d6d28a82252',
					v: '0x1'
				},
			});
			const tx8 = createTransactionEvent({
				type: 0,
				addresses: {
					'0x6f585909d5a03061ed74df7eadb9f75b7ab9fcf7': true,
					'0x8a8fa36b68df2eb9762b053303380992fdbdf7ed': true
				},
				block: {
					hash: '0x4ebac007927e0a7a7f77a553479fd5de1a141e35a796a377e02599b9c5045dd9',
					number: 14619583,
					timestamp: 1650426188
				},
				contractAddress: null,
				logs: [],
				network: 1,
				traces: [],
				transaction: {
					hash: '0x11a72fab7d54c9cf7cb62291d17882ce72d59943ff2a44f053273a1bbbd63c9f',
					from: '0x6f585909d5a03061ed74df7eadb9f75b7ab9fcf7',
					to: '0x8a8fa36b68df2eb9762b053303380992fdbdf7ed',
					nonce: 0,
					gas: '0x5208',
					gasPrice: '0xa8893bf6c',
					value: '0x16345785d8a0000',
					data: '0x',
					r: '0x6e2feddf6073a9267b2286aa2420c6e0ec157de8da27234eea81bc28dffa1998',
					s: '0x19571c7c05ad07a883cfc7add41857ab9a9b3002ed74b75e70d3dffdcfd3a7cc',
					v: '0x1'
				},
			});
			const tx9 = createTransactionEvent({
				type: 0,
				addresses: {
					'0x6e1c24586d0dfeb608e0442a8a1ce772afec03a6': true,
					'0x8a8fa36b68df2eb9762b053303380992fdbdf7ed': true
				},
				block: {
					hash: '0xfa6d1d9ca19cf9a87f82a48ca94b541a461bd1cf63c1b83d851d1e60a053c514',
					number: 14619630,
					timestamp: 1650426958
				},
				contractAddress: null,
				logs: [],
				network: 1,
				traces: [],
				transaction: {
					hash: '0x592560fa745e517f20c51b034c2e4d5b56f6e753dfed01a7907252f5e9c061d7',
					from: '0x6e1c24586d0dfeb608e0442a8a1ce772afec03a6',
					to: '0x8a8fa36b68df2eb9762b053303380992fdbdf7ed',
					nonce: 1189,
					gas: '0x5208',
					gasPrice: '0xaccb35ea6',
					value: '0x2c68af0bb140000',
					data: '0x',
					r: '0x823b759bd7fa2e9b557eadb75f55a4481fd8949b299f491845d79f3d5bd35cb6',
					s: '0x82f8417cf42a83a94fffd9a7ad93a4a345c7f3f9ba4f08104d374e5778b779c',
					v: '0x1'
				},
			});
			const tx10 = createTransactionEvent({
				type: 0,
				addresses: {
					'0xe9e20bd38bfc5df4bdb1846e16c36e23afd0c347': true,
					'0x8a8fa36b68df2eb9762b053303380992fdbdf7ed': true
				},
				block: {
					hash: '0x7cc0ddd8af0a39957924bff89b46b5509d932c7c4bb766dced72c1a8e090f75c',
					number: 14619631,
					timestamp: 1650426974
				},
				contractAddress: null,
				logs: [],
				network: 1,
				traces: [],
				transaction: {
					hash: '0x2ed8f81dc6b40def9933e8b0cc8be78421d7414eaa8074f5d9fe84f535f523ff',
					from: '0xe9e20bd38bfc5df4bdb1846e16c36e23afd0c347',
					to: '0x8a8fa36b68df2eb9762b053303380992fdbdf7ed',
					nonce: 15,
					gas: '0x5208',
					gasPrice: '0xb5a76dc34',
					value: '0x2c68af0bb140000',
					data: '0x',
					r: '0x43c2b132db0cabcfecf7ee6f6bffb23b897d0bb6e4776387f678b68288a9fe94',
					s: '0x36c57f8b6287bb03e8f430774af84f30a7fae23c7aa0e428fa74524c9cca5fe4',
					v: '0x0'
				},
			});
			const tx11 = createTransactionEvent({
				type: 0,
				addresses: {
					'0xd3dfb639ae0004208f16817f1fed570cafd61d68': true,
					'0x8a8fa36b68df2eb9762b053303380992fdbdf7ed': true
				},
				block: {
					hash: '0x72ba42a5bd3efd9100408ba981c46c8c3ba8938e80c07a324fa7d8397ae0f09d',
					number: 14619650,
					timestamp: 1650427272
				},
				contractAddress: null,
				logs: [],
				network: 1,
				traces: [],
				transaction: {
					hash: '0x14c48ddd833b078ef03bb96f517fa2180616ba5a3efa1615e4bf00f55d281f6d',
					from: '0xd3dfb639ae0004208f16817f1fed570cafd61d68',
					to: '0x8a8fa36b68df2eb9762b053303380992fdbdf7ed',
					nonce: 28,
					gas: '0x5208',
					gasPrice: '0xb1f155af6',
					value: '0x16345785d8a0000',
					data: '0x',
					r: '0x114edcb3270d7d325448c88ae64ed6262902049844f14a63681623013eadecb',
					s: '0x4386bd5612b2a335bacebdc3602564c50d7e9e5addfc0d71556040c26c93ac95',
					v: '0x0'
				},
			});

			await handleTransaction(tx1);
			await handleTransaction(tx2);
			await handleTransaction(tx3);
			await handleTransaction(tx4);
			await handleTransaction(tx5);
			await handleTransaction(tx6);
			await handleTransaction(tx7);
			await handleTransaction(tx8);
			await handleTransaction(tx9);
			await handleTransaction(tx10);

			let findings = await handleTransaction(tx11);
			expect(findings).toStrictEqual([
				Finding.fromObject({
					name: "Possible phishing activities with many transfers",
					description: 'The reported EOA address had received funds from 11 distinct addresses. Will start monitor this address for more evidence.',
					alertId: "POSSIBLE-PHISHING-ACTIVITIES-EOA",
					protocol: 'ethereum',
					severity: FindingSeverity.Medium,
					type: FindingType.Suspicious,
					metadata: {
						phishingAddress: '0x8a8fa36b68df2eb9762b053303380992fdbdf7ed',
						transactionHash: '0x14c48ddd833b078ef03bb96f517fa2180616ba5a3efa1615e4bf00f55d281f6d'
					},
					addresses: [],
				}),
			]);
		});
	});

	describe("Badger DAO Hack @ 2022", () => {
		it("returns findings", async () => {
			const tx1 = createTransactionEvent({
				type: 0,
				addresses: {
					'0x1fcdb04d0c5364fbd92c73ca8af9baa72c269107': true,
					'0xae96ff08771a109dc6650a1bdca62f2d558e40af': true
				},
				block: {
					hash: '0x42aec8e2aff3bb73d6e9b6fd3a3d3d89564c374c2d5902a2ee1060bb2b74e858',
					number: 13724676,
					timestamp: 1638411013
				},
				contractAddress: null,
				logs: [
					{
						address: '0xae96ff08771a109dc6650a1bdca62f2d558e40af',
						topics: [
							'0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
							'0x0000000000000000000000007759d0dbeab2270bea6f35679344d4d67b10cce9',
							'0x0000000000000000000000001b1b391d1026a4e3fb7f082ede068b25358a61f2'
						],
						data: '0x0000000000000000000000000000000000000000000000000fb0f6a8982846ea',
						logIndex: 60,
						blockNumber: 13724676,
						blockHash: '0x42aec8e2aff3bb73d6e9b6fd3a3d3d89564c374c2d5902a2ee1060bb2b74e858',
						transactionIndex: 21,
						transactionHash: '0x8c64ab8d24f9339d5e28863d096865dfa2f7b6b409a74aa51b8ea151ad6677fc',
						removed: false
					},
					{
						address: '0xae96ff08771a109dc6650a1bdca62f2d558e40af',
						topics: [
							'0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925',
							'0x0000000000000000000000007759d0dbeab2270bea6f35679344d4d67b10cce9',
							'0x0000000000000000000000001fcdb04d0c5364fbd92c73ca8af9baa72c269107'
						],
						data: '0xfffffffffffffffffffffffffffffffffffffffffffffffff04f095767d7b915',
						logIndex: 61,
						blockNumber: 13724676,
						blockHash: '0x42aec8e2aff3bb73d6e9b6fd3a3d3d89564c374c2d5902a2ee1060bb2b74e858',
						transactionIndex: 21,
						transactionHash: '0x8c64ab8d24f9339d5e28863d096865dfa2f7b6b409a74aa51b8ea151ad6677fc',
						removed: false
					}
				],
				network: 1,
				traces: [],
				transaction: {
					hash: '0x8c64ab8d24f9339d5e28863d096865dfa2f7b6b409a74aa51b8ea151ad6677fc',
					from: '0x1fcdb04d0c5364fbd92c73ca8af9baa72c269107',
					to: '0xae96ff08771a109dc6650a1bdca62f2d558e40af',
					nonce: 118,
					gas: '0x186a0',
					gasPrice: '0x696c25e26a',
					value: '0x0',
					data: '0x23b872dd0000000000000000000000007759d0dbeab2270bea6f35679344d4d67b10cce90000000000000000000000001b1b391d1026a4e3fb7f082ede068b25358a61f20000000000000000000000000000000000000000000000000fb0f6a8982846ea',
					r: '0xba56a6e4ab0f85a8295bb7d4a62b536d8f021dffae8d5003d527684fb51b4780',
					s: '0x51cc6fa5b2a16a6d2469e97667662c5469a8389fc63a06ac35dd2c62d4755f8',
					v: '0x1'
				},
			});
			const tx2 = createTransactionEvent({
				type: 0,
				addresses: {
					'0x1fcdb04d0c5364fbd92c73ca8af9baa72c269107': true,
					'0xae96ff08771a109dc6650a1bdca62f2d558e40af': true
				},
				block: {
					hash: '0xe8fcce6a5c9e6428a1abe5c2e087b79642079ffd97cc2e99d062518af555cce3',
					number: 13724678,
					timestamp: 1638411050
				},
				contractAddress: null,
				logs: [
					{
						address: '0xae96ff08771a109dc6650a1bdca62f2d558e40af',
						topics: [
							'0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
							'0x000000000000000000000000a856e0ca37d3b64a137ad5d3e20c31843fa9fb36',
							'0x0000000000000000000000001b1b391d1026a4e3fb7f082ede068b25358a61f2'
						],
						data: '0x0000000000000000000000000000000000000000000000000de9d01b859ee23d',
						logIndex: 45,
						blockNumber: 13724678,
						blockHash: '0xe8fcce6a5c9e6428a1abe5c2e087b79642079ffd97cc2e99d062518af555cce3',
						transactionIndex: 9,
						transactionHash: '0xf648dc1842c322408444803499568d2d5e38e72e5d6b3bd456af4ace4b367124',
						removed: false
					},
					{
						address: '0xae96ff08771a109dc6650a1bdca62f2d558e40af',
						topics: [
							'0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925',
							'0x000000000000000000000000a856e0ca37d3b64a137ad5d3e20c31843fa9fb36',
							'0x0000000000000000000000001fcdb04d0c5364fbd92c73ca8af9baa72c269107'
						],
						data: '0xfffffffffffffffffffffffffffffffffffffffffffffffff2162fe47a611dc2',
						logIndex: 46,
						blockNumber: 13724678,
						blockHash: '0xe8fcce6a5c9e6428a1abe5c2e087b79642079ffd97cc2e99d062518af555cce3',
						transactionIndex: 9,
						transactionHash: '0xf648dc1842c322408444803499568d2d5e38e72e5d6b3bd456af4ace4b367124',
						removed: false
					}
				],
				network: 1,
				traces: [],
				transaction: {
					hash: '0xf648dc1842c322408444803499568d2d5e38e72e5d6b3bd456af4ace4b367124',
					from: '0x1fcdb04d0c5364fbd92c73ca8af9baa72c269107',
					to: '0xae96ff08771a109dc6650a1bdca62f2d558e40af',
					nonce: 119,
					gas: '0x186a0',
					gasPrice: '0x696c25e26a',
					value: '0x0',
					data: '0x23b872dd000000000000000000000000a856e0ca37d3b64a137ad5d3e20c31843fa9fb360000000000000000000000001b1b391d1026a4e3fb7f082ede068b25358a61f20000000000000000000000000000000000000000000000000de9d01b859ee23d',
					r: '0xecd047111b92d9cf3e5725bd5fb9443f980c2229dc04cf5502447e08b82ea3e8',
					s: '0xc08f75b31a38d95602ca807f6d7f4b3d8bebd7124de9f5ac4809e6e2c8dcf54',
					v: '0x1'
				},
			});
			const tx3 = createTransactionEvent({
				type: 0,
				addresses: {
					'0x1fcdb04d0c5364fbd92c73ca8af9baa72c269107': true,
					'0xae96ff08771a109dc6650a1bdca62f2d558e40af': true
				},
				block: {
					hash: '0x8d8608d07ccd51983a5f18576dafba5da570b6f1611f4116b950cdbd4918572d',
					number: 13724679,
					timestamp: 1638411082
				},
				contractAddress: null,
				logs: [
					{
						address: '0xae96ff08771a109dc6650a1bdca62f2d558e40af',
						topics: [
							'0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
							'0x0000000000000000000000004523b791292da89a9194b61ba4cd9d98f2af68e0',
							'0x0000000000000000000000001b1b391d1026a4e3fb7f082ede068b25358a61f2'
						],
						data: '0x0000000000000000000000000000000000000000000000000d9c5fa86a9e1c15',
						logIndex: 10,
						blockNumber: 13724679,
						blockHash: '0x8d8608d07ccd51983a5f18576dafba5da570b6f1611f4116b950cdbd4918572d',
						transactionIndex: 5,
						transactionHash: '0xb6b99a9e39ef9c392b9c2cbcef80d4aaca1b7963435f53257ef64f6da45d52c1',
						removed: false
					},
					{
						address: '0xae96ff08771a109dc6650a1bdca62f2d558e40af',
						topics: [
							'0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925',
							'0x0000000000000000000000004523b791292da89a9194b61ba4cd9d98f2af68e0',
							'0x0000000000000000000000001fcdb04d0c5364fbd92c73ca8af9baa72c269107'
						],
						data: '0xfffffffffffffffffffffffffffffffffffffffffffffffff263a0579561e3ea',
						logIndex: 11,
						blockNumber: 13724679,
						blockHash: '0x8d8608d07ccd51983a5f18576dafba5da570b6f1611f4116b950cdbd4918572d',
						transactionIndex: 5,
						transactionHash: '0xb6b99a9e39ef9c392b9c2cbcef80d4aaca1b7963435f53257ef64f6da45d52c1',
						removed: false
					}
				],
				network: 1,
				traces: [],
				transaction: {
					hash: '0xb6b99a9e39ef9c392b9c2cbcef80d4aaca1b7963435f53257ef64f6da45d52c1',
					from: '0x1fcdb04d0c5364fbd92c73ca8af9baa72c269107',
					to: '0xae96ff08771a109dc6650a1bdca62f2d558e40af',
					nonce: 120,
					gas: '0x186a0',
					gasPrice: '0x696c25e26a',
					value: '0x0',
					data: '0x23b872dd0000000000000000000000004523b791292da89a9194b61ba4cd9d98f2af68e00000000000000000000000001b1b391d1026a4e3fb7f082ede068b25358a61f20000000000000000000000000000000000000000000000000d9c5fa86a9e1c15',
					r: '0x67306c8bcab3ffd9f74802169028fae63cb5918b4af736ad3305a4d64f8a272f',
					s: '0x142c2aed469a2098cd3414875d3ccde94a86829c15d42219363c557131a0d9c6',
					v: '0x0'
				},
			});
			const tx4 = createTransactionEvent({
				type: 0,
				addresses: {
					'0x1fcdb04d0c5364fbd92c73ca8af9baa72c269107': true,
					'0xae96ff08771a109dc6650a1bdca62f2d558e40af': true
				},
				block: {
					hash: '0x822876de732278d7312ba658fce9126e5ad9f2152a78c4d21559e43f9f03648b',
					number: 13724680,
					timestamp: 1638411096
				},
				contractAddress: null,
				logs: [
					{
						address: '0xae96ff08771a109dc6650a1bdca62f2d558e40af',
						topics: [
							'0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
							'0x0000000000000000000000006b68b7652a32aff234c17796afcea800d54e3428',
							'0x0000000000000000000000001b1b391d1026a4e3fb7f082ede068b25358a61f2'
						],
						data: '0x0000000000000000000000000000000000000000000000001bcef6b085548458',
						logIndex: 6,
						blockNumber: 13724680,
						blockHash: '0x822876de732278d7312ba658fce9126e5ad9f2152a78c4d21559e43f9f03648b',
						transactionIndex: 6,
						transactionHash: '0x7ac09239ba1991092cf1de3687b24c6613d8248ae93be3195c2e94650eec3427',
						removed: false
					},
					{
						address: '0xae96ff08771a109dc6650a1bdca62f2d558e40af',
						topics: [
							'0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925',
							'0x0000000000000000000000006b68b7652a32aff234c17796afcea800d54e3428',
							'0x0000000000000000000000001fcdb04d0c5364fbd92c73ca8af9baa72c269107'
						],
						data: '0xffffffffffffffffffffffffffffffffffffffffffffffffe431094f7aab7ba7',
						logIndex: 7,
						blockNumber: 13724680,
						blockHash: '0x822876de732278d7312ba658fce9126e5ad9f2152a78c4d21559e43f9f03648b',
						transactionIndex: 6,
						transactionHash: '0x7ac09239ba1991092cf1de3687b24c6613d8248ae93be3195c2e94650eec3427',
						removed: false
					},
				],
				network: 1,
				traces: [],
				transaction: {
					hash: '0x7ac09239ba1991092cf1de3687b24c6613d8248ae93be3195c2e94650eec3427',
					from: '0x1fcdb04d0c5364fbd92c73ca8af9baa72c269107',
					to: '0xae96ff08771a109dc6650a1bdca62f2d558e40af',
					nonce: 121,
					gas: '0x186a0',
					gasPrice: '0x696c25e26a',
					value: '0x0',
					data: '0x23b872dd0000000000000000000000006b68b7652a32aff234c17796afcea800d54e34280000000000000000000000001b1b391d1026a4e3fb7f082ede068b25358a61f20000000000000000000000000000000000000000000000001bcef6b085548458',
					r: '0xa2d66db1f341dfac81cdae4eef53dc13773032029d180a301570c3e590f250c9',
					s: '0x67fa0bdbd0e621c77ea33aacaec330344c970621ece7e194b1512b32d1ac6698',
					v: '0x0'
				},
			});
			const tx5 = createTransactionEvent({
				type: 0,
				addresses: {
					'0x1fcdb04d0c5364fbd92c73ca8af9baa72c269107': true,
					'0xae96ff08771a109dc6650a1bdca62f2d558e40af': true
				},
				block: {
					hash: '0x2cabd9927e3f40b9eacfa0e86ee08b3ef64017dd878e987b4b1d2b885262de2e',
					number: 13724681,
					timestamp: 1638411117
				},
				contractAddress: null,
				logs: [
					{
						address: '0xae96ff08771a109dc6650a1bdca62f2d558e40af',
						topics: [
							'0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
							'0x00000000000000000000000024d734a75166e66000c8d7f12a173e41358e3cc1',
							'0x0000000000000000000000001b1b391d1026a4e3fb7f082ede068b25358a61f2'
						],
						data: '0x0000000000000000000000000000000000000000000000000dd5038d3f51742f',
						logIndex: 32,
						blockNumber: 13724681,
						blockHash: '0x2cabd9927e3f40b9eacfa0e86ee08b3ef64017dd878e987b4b1d2b885262de2e',
						transactionIndex: 11,
						transactionHash: '0x143b3e873c1582cdc7fc98330b910e894e61b6ab2c89b05906e27fbc3e6c2843',
						removed: false
					},
					{
						address: '0xae96ff08771a109dc6650a1bdca62f2d558e40af',
						topics: [
							'0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925',
							'0x00000000000000000000000024d734a75166e66000c8d7f12a173e41358e3cc1',
							'0x0000000000000000000000001fcdb04d0c5364fbd92c73ca8af9baa72c269107'
						],
						data: '0xfffffffffffffffffffffffffffffffffffffffffffffffff22afc72c0ae8bd0',
						logIndex: 33,
						blockNumber: 13724681,
						blockHash: '0x2cabd9927e3f40b9eacfa0e86ee08b3ef64017dd878e987b4b1d2b885262de2e',
						transactionIndex: 11,
						transactionHash: '0x143b3e873c1582cdc7fc98330b910e894e61b6ab2c89b05906e27fbc3e6c2843',
						removed: false
					}
				],
				network: 1,
				traces: [],
				transaction: {
					hash: '0x143b3e873c1582cdc7fc98330b910e894e61b6ab2c89b05906e27fbc3e6c2843',
					from: '0x1fcdb04d0c5364fbd92c73ca8af9baa72c269107',
					to: '0xae96ff08771a109dc6650a1bdca62f2d558e40af',
					nonce: 122,
					gas: '0x186a0',
					gasPrice: '0x696c25e26a',
					value: '0x0',
					data: '0x23b872dd00000000000000000000000024d734a75166e66000c8d7f12a173e41358e3cc10000000000000000000000001b1b391d1026a4e3fb7f082ede068b25358a61f20000000000000000000000000000000000000000000000000dd5038d3f51742f',
					r: '0xa6cbb5e39931dc954c42cd25bf4ebe021ef96596d14f1bebf236e0bdade3e912',
					s: '0x5e6350253587261b666328ff03b7c2245a4375390858b563de2219d6a84af1b1',
					v: '0x1'
				},
			});
			const tx6 = createTransactionEvent({
				type: 0,
				addresses: {
					'0x1fcdb04d0c5364fbd92c73ca8af9baa72c269107': true,
					'0xae96ff08771a109dc6650a1bdca62f2d558e40af': true
				},
				block: {
					hash: '0x1430579ea05ef50a0f0e11863310766d939bec92e648148e3e76f9e62c2fcb66',
					number: 13724682,
					timestamp: 1638411132
				},
				contractAddress: null,
				logs: [
					{
						address: '0xae96ff08771a109dc6650a1bdca62f2d558e40af',
						topics: [
							'0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
							'0x0000000000000000000000008b34f5931fd52f70661174486d66a973d50a2d83',
							'0x0000000000000000000000001b1b391d1026a4e3fb7f082ede068b25358a61f2'
						],
						data: '0x0000000000000000000000000000000000000000000000000dcfa033990cc5c7',
						logIndex: 41,
						blockNumber: 13724682,
						blockHash: '0x1430579ea05ef50a0f0e11863310766d939bec92e648148e3e76f9e62c2fcb66',
						transactionIndex: 17,
						transactionHash: '0x6661c0cf44452b56c2092e30512c3a7d2addf2fef699c3d7b284fb0cc9bbd066',
						removed: false
					},
					{
						address: '0xae96ff08771a109dc6650a1bdca62f2d558e40af',
						topics: [
							'0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925',
							'0x0000000000000000000000008b34f5931fd52f70661174486d66a973d50a2d83',
							'0x0000000000000000000000001fcdb04d0c5364fbd92c73ca8af9baa72c269107'
						],
						data: '0xfffffffffffffffffffffffffffffffffffffffffffffffff2305fcc66f33a38',
						logIndex: 42,
						blockNumber: 13724682,
						blockHash: '0x1430579ea05ef50a0f0e11863310766d939bec92e648148e3e76f9e62c2fcb66',
						transactionIndex: 17,
						transactionHash: '0x6661c0cf44452b56c2092e30512c3a7d2addf2fef699c3d7b284fb0cc9bbd066',
						removed: false
					}
				],
				network: 1,
				traces: [],
				transaction: {
					hash: '0x6661c0cf44452b56c2092e30512c3a7d2addf2fef699c3d7b284fb0cc9bbd066',
					from: '0x1fcdb04d0c5364fbd92c73ca8af9baa72c269107',
					to: '0xae96ff08771a109dc6650a1bdca62f2d558e40af',
					nonce: 123,
					gas: '0x186a0',
					gasPrice: '0x696c25e26a',
					value: '0x0',
					data: '0x23b872dd0000000000000000000000008b34f5931fd52f70661174486d66a973d50a2d830000000000000000000000001b1b391d1026a4e3fb7f082ede068b25358a61f20000000000000000000000000000000000000000000000000dcfa033990cc5c7',
					r: '0x8b7cb76046f6eff0c9bd48774731a9fe9e8b76bbd72bb0777d686b553b8a6721',
					s: '0x713c2e8618e84b5166823c6eaf40c56ed4d81a37857acb58f7045c90af08138e',
					v: '0x1'
				},
			});

			await handleTransaction(tx1);
			await handleTransaction(tx2);
			await handleTransaction(tx3);
			await handleTransaction(tx4);
			await handleTransaction(tx5);

			let findings = await handleTransaction(tx6);
			expect(findings).toStrictEqual([
				Finding.fromObject({
					name: "Possible phishing activities",
					description: 'The reported address had received funds from 6 distinct addresses, having a drain rate of 1. Will start monitor this address for more evidence.',
					alertId: "POSSIBLE-PHISHING-ACTIVITIES",
					protocol: 'ethereum',
					severity: FindingSeverity.Medium,
					type: FindingType.Suspicious,
					metadata: {
						phishingAddress: '0x1b1b391d1026a4e3fb7f082ede068b25358a61f2',
						transactionHash: '0x6661c0cf44452b56c2092e30512c3a7d2addf2fef699c3d7b284fb0cc9bbd066'
					},
					addresses: [],
				}),
			]);
		});
	});
});
